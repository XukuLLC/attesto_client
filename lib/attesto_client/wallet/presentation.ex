defmodule AttestoClient.Wallet.Presentation do
  @moduledoc """
  OID4VP Presentation (holder/wallet) flow (`draft-ietf-oauth-openid4vp`).

  Given a verified `AttestoClient.Wallet.PresentationRequest` and the
  wallet's held credentials (as returned by
  `AttestoClient.Wallet.request_credential/3`), `present/4` selects which
  held credential satisfies each DCQL credential query, builds the
  `vp_token`, and POSTs it to the verifier's `response_uri` (`direct_post`).
  A presentation this module builds is the mirror image of `Attesto.VpToken.verify/2`
  - it verifies there against the same nonce/`client_id`/`response_uri`.

  Two credential formats are supported, matching `AttestoClient.Wallet`:

    * SD-JWT VC (`vc+sd-jwt` / `dc+sd-jwt`) - the issuer-signed JWT plus the
      selected Disclosures, plus a holder Key Binding JWT (`typ: kb+jwt`)
      signed over `nonce`/`aud`/`sd_hash` (`Attesto.SdJwt.verify_key_binding/3`
      is the verifier-side mirror).
    * `mso_mdoc` - a full ISO 18013-5 `DeviceResponse`, delegated to
      `AttestoClient.Wallet.Presentation.Mdoc`.

  Only `response_mode: "direct_post"` is built; `"direct_post.jwt"`
  (encrypted responses) is a follow-up and fails closed with
  `:unsupported_response_mode`.

  ## Selection

  Selection is deliberately simple - format, `meta.vct_values` /
  `meta.doctype_value`, and top-level requested-claim presence - and does
  not consider `credential_sets` (OR/AND grouping of alternative credential
  queries). It is also fully host-overridable: pass an explicit `:selection`
  (a `%{query_id => held_credential}` map) to `present/4`/`build_vp_token/3`
  to skip DCQL matching outright, e.g. when the host runs its own consent UI
  and lets the user pick.

  ## Claim minimisation (SD-JWT VC only)

  When a DCQL credential query's `claims` are all simple top-level paths
  (`["given_name"]`, not `["address", "street"]` or an array wildcard), only
  the matching Disclosures are included in the presentation; the issuer JWT
  itself (and any claim visible outside `_sd`) is unaffected. A query with no
  `claims`, or with any non-simple path, discloses every Disclosure the held
  credential carries. `mso_mdoc` presentations always include every
  `IssuerSigned` item (see `AttestoClient.Wallet.Presentation.Mdoc`).

  All HTTP goes through `AttestoClient.OAuthHTTP`, so it is mockable the same
  way as the rest of this library (`req_options: [plug: ...]`).
  """

  alias Attesto.JWS
  alias Attesto.Thumbprint
  alias AttestoClient.Builder
  alias AttestoClient.OAuthHTTP
  alias AttestoClient.Wallet.Presentation.Mdoc
  alias AttestoClient.Wallet.PresentationRequest

  @sd_jwt_vc_formats ~w(vc+sd-jwt dc+sd-jwt)
  @mdoc_format "mso_mdoc"
  @kb_typ "kb+jwt"

  @type opt ::
          {:selection, %{optional(String.t()) => map()}}
          | {:holder_keys, %{optional(String.t()) => JOSE.JWK.t() | map() | String.t()}}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, integer()}
          | {:req_options, keyword()}
          | {:timeout, pos_integer()}

  @doc """
  Select which held credential satisfies each DCQL credential query.

  `dcql_query` is `request.dcql_query`; `held_credentials` is the wallet's
  list of held credentials (see the moduledoc for the matching rule).
  Returns `{:error, {:no_match, query_id}}` for the first query no held
  credential satisfies.
  """
  @spec select(map(), [map()]) :: {:ok, %{String.t() => map()}} | {:error, term()}
  def select(%{"credentials" => queries}, held_credentials)
      when is_list(queries) and is_list(held_credentials) do
    Enum.reduce_while(queries, {:ok, %{}}, fn query, {:ok, acc} ->
      case find_match(query, held_credentials) do
        {:ok, held} -> {:cont, {:ok, Map.put(acc, Map.fetch!(query, "id"), held)}}
        :error -> {:halt, {:error, {:no_match, Map.get(query, "id")}}}
      end
    end)
  end

  def select(_dcql_query, _held_credentials), do: {:error, :invalid_dcql_query}

  @doc """
  Build the `vp_token` and POST it to `request.response_uri`.

  Requires `:holder_keys` (a `%{query_id => holder_key}` map covering every
  selected query id - see the moduledoc). Selects via `select/2` unless
  `:selection` is supplied.
  """
  @spec present(PresentationRequest.t(), [map()], [opt()]) :: {:ok, map()} | {:error, term()}
  def present(%PresentationRequest{} = request, held_credentials, opts \\ [])
      when is_list(held_credentials) and is_list(opts) do
    with {:ok, selection} <- resolve_selection(request, held_credentials, opts),
         {:ok, vp_token} <- build_vp_token(selection, request, opts) do
      submit(request, vp_token, opts)
    end
  end

  defp resolve_selection(request, held_credentials, opts) do
    case Keyword.get(opts, :selection) do
      nil -> select(request.dcql_query, held_credentials)
      %{} = selection -> {:ok, selection}
      _invalid -> {:error, :invalid_selection}
    end
  end

  @doc """
  Build the `vp_token` map (`%{query_id => presentation}`) for an explicit
  `selection`, without submitting it.

  Exposed separately so a host can build and inspect (or let the user
  confirm) a presentation before it is sent, and so tests can assert on the
  built `vp_token` directly.
  """
  @spec build_vp_token(%{String.t() => map()}, PresentationRequest.t(), [opt()]) ::
          {:ok, %{String.t() => String.t()}} | {:error, term()}
  def build_vp_token(selection, %PresentationRequest{} = request, opts \\ [])
      when is_map(selection) and is_list(opts) do
    with :ok <- check_direct_post(request) do
      build_each(selection, request, opts)
    end
  end

  defp build_each(selection, request, opts) do
    Enum.reduce_while(selection, {:ok, %{}}, fn {id, held}, {:ok, acc} ->
      accumulate_presentation(id, held, request, opts, acc)
    end)
  end

  defp accumulate_presentation(id, held, request, opts, acc) do
    case build_one(id, held, request, opts) do
      {:ok, presentation} -> {:cont, {:ok, Map.put(acc, id, presentation)}}
      {:error, reason} -> {:halt, {:error, {id, reason}}}
    end
  end

  @doc """
  POST an already-built `vp_token` to `request.response_uri` as
  `application/x-www-form-urlencoded` `direct_post` (`vp_token` JSON-encoded,
  plus `state` when the request carried one). Unauthenticated, per OID4VP -
  see `AttestoClient.OAuthHTTP.post_form_open/3`.
  """
  @spec submit(PresentationRequest.t(), map(), [opt()]) :: {:ok, map()} | {:error, term()}
  def submit(%PresentationRequest{} = request, vp_token, opts \\ [])
      when is_map(vp_token) and is_list(opts) do
    # Fail closed on `direct_post.jwt` here too, not only in `build_vp_token/3`:
    # this is a public entry point, and an unencrypted `direct_post` submission
    # of a response the request asked to be encrypted would leak it in plaintext.
    with :ok <- check_direct_post(request) do
      form =
        %{"vp_token" => JSON.encode!(vp_token)}
        |> put_optional("state", request.state)

      OAuthHTTP.post_form_open(request.response_uri, form, opts)
    end
  end

  # ── building ─────────────────────────────────────────────────────────────

  defp check_direct_post(%PresentationRequest{response_mode: "direct_post"}), do: :ok
  defp check_direct_post(_request), do: {:error, :unsupported_response_mode}

  defp build_one(id, held, request, opts) do
    with {:ok, holder_key} <- holder_key_for(id, opts),
         :ok <- check_holder_key(holder_key, held) do
      dispatch_build(held, request, holder_key, claim_filter(request, id), opts)
    end
  end

  # The signing key must be the one the selected credential is bound to. Checking
  # locally - by RFC 7638 thumbprint against the credential's `cnf.jwk` / mdoc
  # device key - fails BEFORE any issuer JWT or Disclosure is disclosed to the
  # verifier, so a wrong-key selection cannot leak the credential's contents.
  defp check_holder_key(holder_key, held) do
    with {:ok, jwk} <- Builder.normalize_key(holder_key),
         {:ok, bound_jwk} <- presentation_binding_jwk(held) do
      {_type, holder_public} = JOSE.JWK.to_public_map(jwk)

      with {:ok, holder_thumb} <- Thumbprint.of_jwk(holder_public),
           {:ok, bound_thumb} <- Thumbprint.of_jwk(bound_jwk) do
        if holder_thumb == bound_thumb, do: :ok, else: {:error, :holder_key_mismatch}
      end
    end
  end

  defp presentation_binding_jwk(%{holder_binding: %{"jwk" => jwk}}) when is_map(jwk),
    do: {:ok, jwk}

  defp presentation_binding_jwk(%{format: @mdoc_format, holder_binding: device_key})
       when is_map(device_key),
       do: {:ok, device_key}

  defp presentation_binding_jwk(_held), do: {:error, :missing_holder_binding}

  defp holder_key_for(id, opts) do
    case Keyword.get(opts, :holder_keys) do
      keys when is_map(keys) ->
        case Map.fetch(keys, id) do
          {:ok, key} -> {:ok, key}
          :error -> {:error, :missing_holder_key}
        end

      _invalid ->
        {:error, :missing_holder_keys}
    end
  end

  defp dispatch_build(%{format: format} = held, request, holder_key, claim_filter, opts)
       when format in @sd_jwt_vc_formats do
    build_sd_jwt_presentation(held, request, holder_key, claim_filter, opts)
  end

  defp dispatch_build(%{format: @mdoc_format} = held, request, holder_key, _claim_filter, opts) do
    Mdoc.build_device_response(held, request, holder_key, opts)
  end

  defp dispatch_build(_held, _request, _holder_key, _claim_filter, _opts),
    do: {:error, :unsupported_format}

  defp build_sd_jwt_presentation(held, request, holder_key, claim_filter, opts) do
    with {:ok, filtered} <- filter_disclosures(held.credential, claim_filter),
         {:ok, jose_jwk} <- Builder.normalize_key(holder_key),
         {:ok, alg} <- Builder.resolve_alg(jose_jwk, opts) do
      # `sd_hash` per draft-ietf-oauth-selective-disclosure-jwt §4.3:
      # base64url(SHA-256(<Issuer JWT>~<D1>~...~<Dn>~)) - `Attesto.SdJwt`
      # computes this identically (`JWS.encode64/1` is the same primitive it
      # uses) but does not expose it, since it is a verifier-side concern
      # there; here it is what the holder must sign over.
      sd_hash = filtered |> then(&:crypto.hash(:sha256, &1)) |> JWS.encode64()

      claims = %{
        "nonce" => request.nonce,
        "aud" => request.client_id,
        "iat" => Builder.now(opts),
        "sd_hash" => sd_hash
      }

      header = %{"alg" => alg, "typ" => @kb_typ} |> Builder.put_kid(jose_jwk, opts)

      with {:ok, kb_jwt} <- Builder.sign(jose_jwk, header, claims) do
        {:ok, filtered <> kb_jwt}
      end
    end
  end

  defp claim_filter(request, id) do
    request.dcql_query
    |> Map.get("credentials", [])
    |> Enum.find(&(Map.get(&1, "id") == id))
    |> claim_filter_from_query()
  end

  defp claim_filter_from_query(%{"claims" => claims}) when is_list(claims) and claims != [] do
    case Enum.reduce_while(claims, [], &collect_top_level_name/2) do
      :all -> :all
      names -> {:only, Enum.reverse(names)}
    end
  end

  defp claim_filter_from_query(_query), do: :all

  defp collect_top_level_name(%{"path" => [name]}, acc) when is_binary(name),
    do: {:cont, [name | acc]}

  defp collect_top_level_name(_claim, _acc), do: {:halt, :all}

  defp filter_disclosures(credential, :all), do: {:ok, credential}

  defp filter_disclosures(credential, {:only, names}) do
    case String.split(credential, "~") do
      [issuer_jwt | rest] when issuer_jwt != "" and rest != [] ->
        filter_split_disclosures(issuer_jwt, rest, names)

      _invalid ->
        {:error, :invalid_credential}
    end
  end

  defp filter_split_disclosures(issuer_jwt, rest, names) do
    if List.last(rest) == "" do
      with {:ok, claims} <- issuer_payload(issuer_jwt),
           {:ok, hash_alg} <- sd_hash_alg(claims) do
        # Only object-property Disclosures whose digest appears in the issuer
        # payload's TOP-LEVEL `_sd` are top-level claims. Matching by leaf name
        # alone would also keep a nested Disclosure (e.g. `medical.name`) that
        # happens to share a requested top-level name, leaking it to the verifier.
        root_sd = MapSet.new(List.wrap(Map.get(claims, "_sd", [])))
        disclosures = Enum.drop(rest, -1)
        kept = Enum.filter(disclosures, &keep_disclosure?(&1, names, root_sd, hash_alg))
        {:ok, Enum.join([issuer_jwt | kept] ++ [""], "~")}
      end
    else
      {:error, :invalid_credential}
    end
  end

  defp keep_disclosure?(disclosure, names, root_sd, hash_alg) do
    digest = hash_alg |> :crypto.hash(disclosure) |> JWS.encode64()
    MapSet.member?(root_sd, digest) and disclosure_name_in?(disclosure, names)
  end

  defp issuer_payload(issuer_jwt) do
    with [_header, payload | _] <- String.split(issuer_jwt, "."),
         {:ok, bytes} <- Base.url_decode64(payload, padding: false),
         {:ok, claims} when is_map(claims) <- JSON.decode(bytes) do
      {:ok, claims}
    else
      _other -> {:error, :invalid_credential}
    end
  end

  # draft-ietf-oauth-selective-disclosure-jwt §4.1.1: `_sd_alg` names the hash;
  # its absence defaults to sha-256. An unknown value fails closed rather than
  # silently disabling top-level scoping (which would reintroduce the leak).
  defp sd_hash_alg(claims) do
    case Map.get(claims, "_sd_alg", "sha-256") do
      "sha-256" -> {:ok, :sha256}
      "sha-384" -> {:ok, :sha384}
      "sha-512" -> {:ok, :sha512}
      _other -> {:error, :unsupported_sd_alg}
    end
  end

  defp disclosure_name_in?(disclosure, names) do
    case decode_disclosure_name(disclosure) do
      {:ok, name} -> name in names
      :error -> false
    end
  end

  defp decode_disclosure_name(disclosure) do
    with {:ok, bytes} <- Base.url_decode64(disclosure, padding: false),
         {:ok, [_salt, name, _value]} <- JSON.decode(bytes) do
      {:ok, name}
    else
      _other -> :error
    end
  end

  # ── selection matching ──────────────────────────────────────────────────

  defp find_match(%{"id" => id, "format" => format} = query, held_credentials)
       when is_binary(id) and is_binary(format) do
    held_credentials
    |> Enum.find(&candidate_matches?(&1, format, query))
    |> wrap_found()
  end

  defp find_match(_query, _held_credentials), do: :error

  defp wrap_found(nil), do: :error
  defp wrap_found(held), do: {:ok, held}

  defp candidate_matches?(%{format: format} = held, format, query) do
    meta_matches?(held, format, Map.get(query, "meta")) and
      claims_present?(held, Map.get(query, "claims"))
  end

  defp candidate_matches?(_held, _format, _query), do: false

  defp meta_matches?(held, format, meta) when format in @sd_jwt_vc_formats,
    do: sd_jwt_meta_matches?(held, meta)

  defp meta_matches?(held, @mdoc_format, meta), do: mdoc_meta_matches?(held, meta)
  defp meta_matches?(_held, _format, _meta), do: true

  defp sd_jwt_meta_matches?(_held, nil), do: true

  defp sd_jwt_meta_matches?(held, %{"vct_values" => values}) when is_list(values) do
    Map.get(held.claims, "vct") in values
  end

  defp sd_jwt_meta_matches?(_held, _meta), do: true

  defp mdoc_meta_matches?(_held, nil), do: true

  defp mdoc_meta_matches?(held, %{"doctype_value" => doc_type}) when is_binary(doc_type) do
    Map.get(held, :doc_type) == doc_type
  end

  defp mdoc_meta_matches?(_held, _meta), do: true

  defp claims_present?(_held, nil), do: true

  defp claims_present?(held, claims) when is_list(claims) do
    Enum.all?(claims, &claim_present?(held, &1))
  end

  defp claims_present?(_held, _claims), do: true

  defp claim_present?(%{format: format} = held, %{"path" => [name]})
       when is_binary(name) and format in @sd_jwt_vc_formats do
    Map.has_key?(held.claims, name)
  end

  defp claim_present?(%{format: @mdoc_format} = held, %{"path" => [namespace, element]})
       when is_binary(namespace) and is_binary(element) do
    case Map.fetch(held.claims, namespace) do
      {:ok, elements} -> Map.has_key?(elements, element)
      :error -> false
    end
  end

  defp claim_present?(_held, _claim), do: true

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)
end
