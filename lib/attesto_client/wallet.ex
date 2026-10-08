defmodule AttestoClient.Wallet do
  @moduledoc """
  OpenID4VCI 1.0 Wallet (Holder) issuance flow.

  `request_credential/3` drives the pre-authorized_code issuance flow end to
  end:

    1. exchange the offer's pre-authorized code for an access token
       (`AttestoClient.Token.exchange_pre_authorized_code/2`) - skipped when
       an `:access_token` is already supplied, e.g. obtained separately
       through the authorization_code flow
       (`AttestoClient.AuthorizationCode`);
    2. fetch a fresh `c_nonce` when the issuer advertises a nonce endpoint;
    3. build the holder key proof (`AttestoClient.Wallet.Proof`);
    4. POST the Credential Request and parse the Credential Response
       (`Attesto.CredentialResponse`), decrypting an encrypted response when
       negotiated with the issuer; a deferred response is polled when a
       Deferred Credential Endpoint is supplied; and
    5. verify each returned credential with the attesto verifier matching
       `:format` (`Attesto.SdJwtVc`, `Attesto.JwtVc`, or `Attesto.Mdoc`).

  All HTTP goes through `AttestoClient.OAuthHTTP`, so the flow is mockable
  the same way as the rest of this library (`req_options: [plug: ...]`).
  """

  alias Attesto.Thumbprint
  alias AttestoClient.AuthorizationProfile
  alias AttestoClient.Builder
  alias AttestoClient.OAuthHTTP
  alias AttestoClient.Token
  alias AttestoClient.TokenSet
  alias AttestoClient.Wallet.CredentialEncryption
  alias AttestoClient.Wallet.CredentialOffer
  alias AttestoClient.Wallet.CredentialTrust
  alias AttestoClient.Wallet.Deferred
  alias AttestoClient.Wallet.Proof

  @sd_jwt_vc_formats ~w(vc+sd-jwt dc+sd-jwt)
  @jwt_vc_format "jwt_vc_json"
  @mdoc_format "mso_mdoc"

  @type held_credential :: %{
          required(:format) => String.t(),
          required(:credential) => String.t(),
          required(:claims) => map(),
          required(:holder_binding) => map() | nil,
          optional(:doc_type) => String.t(),
          optional(:authority_key_identifiers) => [String.t()],
          optional(:issuer_certificate_chain) => [binary()]
        }

  @type pending_credential :: %{
          status: :pending,
          transaction_id: String.t(),
          notification_id: String.t() | nil
        }

  @type result :: %{
          credentials: [held_credential() | pending_credential()],
          c_nonce: String.t() | nil
        }

  @type opt ::
          {:credential_configuration_id, String.t()}
          | {:credential_endpoint, String.t()}
          | {:credential_issuer_metadata, map()}
          | {:credential_encryption, :auto | :required | :disabled}
          | {:credential_response_encryption_key, Proof.jwk()}
          | {:deferred_credential_endpoint, String.t()}
          | {:deferred_poll, boolean()}
          | {:deferred_timeout, pos_integer()}
          | {:deferred_max_attempts, pos_integer()}
          | {:deferred_clock, (-> integer())}
          | {:deferred_sleep, (non_neg_integer() -> :ok | {:error, term()})}
          | {:token_endpoint, String.t()}
          | {:nonce_endpoint, String.t()}
          | {:notification_endpoint, String.t()}
          | {:notification_event, String.t()}
          | {:access_token, String.t() | TokenSet.t()}
          | {:tx_code, String.t()}
          | {:client_id, String.t()}
          | {:client_auth, term()}
          | {:format, String.t()}
          | {:trusted, term()}
          | {:haip, boolean()}
          | {:trusted_certificates, [binary()]}
          | {:certificate_trust, ([binary()] -> :ok | {:error, term()})}
          | {:verify_opts, keyword()}
          | {:proof_alg, String.t()}
          | {:proof_kid, String.t()}
          | {:key_attestation,
             String.t() | ([map()], String.t() | nil -> {:ok, String.t()} | {:error, term()})}
          | {:dpop, Proof.jwk()}
          | {:now, integer()}
          | {:req_options, keyword()}
          | {:timeout, pos_integer()}

  @doc """
  Run the wallet-holder issuance flow for `offer` and return the verified,
  held credential(s) (or a pending marker for deferred issuance).

  Required options: `:credential_endpoint`, `:format` (one of `"vc+sd-jwt"`,
  `"dc+sd-jwt"`, `"jwt_vc_json"`, or `"mso_mdoc"`), and `:trusted` (the
  Credential Issuer's verification key material, in the shape the matching
  attesto verifier expects - a JWKS/JWK list for `Attesto.SdJwtVc` and
  `Attesto.JwtVc`, a single JWK/PEM for `Attesto.Mdoc`). `:verify_opts` are
  forwarded to that verifier (e.g. `:accepted_algs`, `:now`).

  Unless `:access_token` is supplied, the flow performs the
  pre-authorized_code token exchange itself and requires `:token_endpoint`
  and, when the offer's grant carries one, `:tx_code`. `:client_id` and
  `:client_auth` authenticate that token request exactly as in
  `AttestoClient.Token`, and, when present, `:client_id` is also carried as
  the proof's `iss`.

  `:nonce_endpoint`, when supplied, is used to fetch a fresh `c_nonce` before
  building the proof. `:credential_configuration_id` selects which of the
  offer's configuration ids to request; it defaults to the offer's only id
  when there is exactly one.

  `:dpop` (a `JOSE.JWK` or JWK map) sender-constrains the flow with RFC 9449
  DPoP proofs. The one key is used at the token endpoint (binding the access
  token to its `jkt`) and at the Credential Endpoint (where the proof carries
  the `ath` binding to that token), and a `use_dpop_nonce` challenge is retried
  once - see `AttestoClient.DPoP`.

  HAIP requires DPoP and authenticated token acquisition. When supplying an
  existing token, pass `access_token: tokens` with the complete locally bound
  `AttestoClient.TokenSet` and the same DPoP private key. Bare token strings
  remain available for generic flows only. A retained HAIP profile cannot be
  disabled by passing `haip: false` to credential issuance.

  `:key_attestation` (a compact JWT from `AttestoClient.KeyAttestation.build/2`)
  is carried in the holder proof's `key_attestation` header, vouching to the
  issuer that the holder key is held in secure storage (a HAIP requirement).

  `:notification_endpoint`, when supplied, makes the wallet POST an OID4VCI §11
  Notification acknowledging the credential once issuance succeeds and the
  response carried a `notification_id`; `:notification_event` overrides the
  default `"credential_accepted"`. The returned result always includes the
  issuer's `notification_id` (or `nil`).

  `:credential_issuer_metadata` accepts metadata already fetched and validated
  by the caller. Its `credential_issuer` must equal the offer's issuer. Endpoint
  options may be omitted when present in this metadata; conflicting endpoint
  overrides are rejected. Encryption uses ECDH-ES/P-256 and A128GCM or A256GCM.
  `:credential_encryption` defaults to `:auto`, which requests encryption when
  advertised. `:required` requires encrypted requests and responses; `:disabled`
  is allowed only when the issuer does not require encryption. Response
  encryption always also encrypts the request, as required by §8.2.

  `:deferred_credential_endpoint` enables bounded polling of a deferred result.
  `:deferred_poll` can be set to `false` to retain a pending marker. Polling
  respects the issuer's positive `interval`, with at most 10 attempts and a
  120-second overall deadline by default. `:deferred_max_attempts` (1–100) and
  `:deferred_timeout` (milliseconds, at most one hour) customize these bounds;
  `:deferred_clock` and `:deferred_sleep` provide injectable monotonic clock and
  wait functions. The response encryption key remains private to this flow.
  """
  @spec request_credential(CredentialOffer.t(), Proof.jwk() | [Proof.jwk()], [opt()]) ::
          {:ok, result()} | {:error, term()}
  def request_credential(%CredentialOffer{} = offer, holder_key, opts) when is_list(opts) do
    with {:ok, opts} <- issuer_options(offer, opts),
         {:ok, opts} <- issuance_profile(opts),
         :ok <- Deferred.validate_options(opts),
         {:ok, encryption} <- CredentialEncryption.prepare(opts),
         {:ok, holder_keys} <- holder_keys(holder_key),
         {:ok, holder_publics} <- holder_public_keys(holder_keys),
         :ok <- validate_trusted(opts),
         {:ok, format} <- required_format(opts),
         {:ok, configuration_id} <- configuration_id(offer, opts),
         {:ok, type_binding} <- configuration_type_binding(format, configuration_id, opts),
         {:ok, access_token} <- access_token(offer, opts),
         {:ok, c_nonce} <- fetch_nonce(opts),
         {:ok, key_attestation} <- resolve_key_attestation(opts, holder_publics, c_nonce),
         {:ok, proofs} <- build_proofs(offer, holder_keys, c_nonce, key_attestation, opts),
         {:ok, response} <-
           post_credential_request(configuration_id, proofs, access_token, encryption, opts),
         {:ok, response} <- deferred_response(response, access_token, encryption, opts) do
      finalize(response, format, c_nonce, access_token, holder_publics, opts, type_binding)
    end
  end

  def request_credential(_offer, _holder_key, _opts), do: {:error, :invalid_offer}

  defp issuer_options(offer, opts) do
    case Keyword.fetch(opts, :credential_issuer_metadata) do
      :error ->
        {:ok, opts}

      {:ok, %{"credential_issuer" => issuer} = metadata} when issuer == offer.credential_issuer ->
        metadata_endpoints(metadata, opts)

      {:ok, _invalid} ->
        {:error, :credential_issuer_metadata_mismatch}
    end
  end

  defp metadata_endpoints(metadata, opts) do
    ~w(credential_endpoint nonce_endpoint deferred_credential_endpoint notification_endpoint)a
    |> Enum.reduce_while({:ok, opts}, fn key, {:ok, accumulated} ->
      case metadata_endpoint(metadata, accumulated, key) do
        {:ok, updated} -> {:cont, {:ok, updated}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp metadata_endpoint(metadata, opts, key) do
    case {Map.get(metadata, Atom.to_string(key)), Keyword.get(opts, key)} do
      {nil, _configured} ->
        {:ok, opts}

      {advertised, configured} when is_binary(advertised) and advertised != "" ->
        if configured in [nil, advertised],
          do: {:ok, Keyword.put(opts, key, advertised)},
          else: {:error, {:credential_endpoint_mismatch, key}}

      _invalid ->
        {:error, {:invalid_credential_endpoint_metadata, key}}
    end
  end

  defp required_format(opts) do
    case Keyword.get(opts, :format) do
      format when format in @sd_jwt_vc_formats or format in [@jwt_vc_format, @mdoc_format] ->
        supported_format(format)

      _invalid ->
        {:error, :missing_format}
    end
  end

  if Code.ensure_loaded?(CBOR) do
    defp supported_format(format), do: {:ok, format}
  else
    defp supported_format(@mdoc_format), do: {:error, :unsupported_mdoc}
    defp supported_format(format), do: {:ok, format}
  end

  defp configuration_id(offer, opts) do
    case Keyword.get(opts, :credential_configuration_id) do
      id when is_binary(id) and id != "" ->
        {:ok, id}

      nil ->
        case offer.credential_configuration_ids do
          [id] -> {:ok, id}
          _many -> {:error, :ambiguous_credential_configuration_id}
        end

      _invalid ->
        {:error, :invalid_credential_configuration_id}
    end
  end

  defp configuration_type_binding(format, id, opts) do
    metadata = Keyword.get(opts, :credential_issuer_metadata, %{})

    case Map.fetch(metadata, "credential_configurations_supported") do
      :error ->
        {:ok, nil}

      {:ok, configurations} ->
        advertised_configuration_type(configurations, format, id)
    end
  end

  defp advertised_configuration_type(configurations, format, id) when is_map(configurations) do
    with true <- valid_configuration_catalog?(configurations),
         {:ok, configuration} <- fetch_configuration(configurations, id),
         :ok <- configuration_format(configuration, format) do
      configuration_type(configuration, format)
    else
      false -> {:error, :invalid_credential_configuration_metadata}
      {:error, _reason} = error -> error
    end
  end

  defp advertised_configuration_type(_configurations, _format, _id),
    do: {:error, :invalid_credential_configuration_metadata}

  defp valid_configuration_catalog?(configurations) do
    map_size(configurations) > 0 and
      Enum.all?(configurations, fn {id, configuration} ->
        is_binary(id) and id != "" and is_map(configuration) and
          is_binary(configuration["format"]) and configuration["format"] != ""
      end)
  end

  defp fetch_configuration(configurations, id) do
    case Map.fetch(configurations, id) do
      {:ok, configuration} -> {:ok, configuration}
      :error -> {:error, :credential_configuration_not_advertised}
    end
  end

  defp configuration_format(%{"format" => format}, format), do: :ok

  defp configuration_format(_configuration, _format),
    do: {:error, :credential_configuration_format_mismatch}

  defp configuration_type(configuration, format) when format in @sd_jwt_vc_formats,
    do: required_configuration_type(configuration, "vct", :vct)

  defp configuration_type(configuration, @mdoc_format),
    do: required_configuration_type(configuration, "doctype", :doc_type)

  defp configuration_type(_configuration, _format), do: {:ok, nil}

  defp required_configuration_type(configuration, field, binding) do
    case Map.get(configuration, field) do
      value when is_binary(value) and value != "" -> {:ok, {binding, value}}
      _invalid -> {:error, :invalid_credential_configuration_metadata}
    end
  end

  defp access_token(offer, opts) do
    case Keyword.get(opts, :access_token) do
      %TokenSet{} = tokens ->
        with :ok <- check_token_binding(tokens, opts), do: {:ok, tokens.access_token}

      token when is_binary(token) and token != "" ->
        {:ok, token}

      nil ->
        exchange_pre_authorized_code(offer, opts)

      _invalid ->
        {:error, :invalid_token_set}
    end
  end

  defp issuance_profile(opts) do
    tokens = Keyword.get(opts, :access_token)

    stored =
      if is_struct(tokens, TokenSet), do: Map.get(tokens, :profile, :generic), else: :generic

    with {:ok, requested} <- AuthorizationProfile.select(opts),
         true <- stored in [:generic, :haip, :fapi],
         true <- stored == :generic or requested in [:generic, stored] do
      profile = if stored == :generic, do: requested, else: stored
      opts = opts |> Keyword.put(:haip, profile == :haip) |> Keyword.put(:fapi?, profile == :fapi)

      with {:ok, jkt} <- TokenSet.dpop_thumbprint(opts),
           :ok <- AuthorizationProfile.require_dpop(profile, jkt),
           :ok <- AuthorizationProfile.dpop_policy(profile, opts),
           :ok <- require_profile_tokens(profile, tokens) do
        {:ok, opts}
      end
    else
      false -> {:error, :profile_mismatch}
      error -> error
    end
  end

  defp require_profile_tokens(:generic, _tokens), do: :ok
  defp require_profile_tokens(_profile, nil), do: :ok

  defp require_profile_tokens(profile, %TokenSet{profile: profile, client_auth_binding: binding})
       when is_map(binding), do: :ok

  defp require_profile_tokens(_profile, _tokens), do: {:error, :profile_token_set_required}

  defp exchange_pre_authorized_code(%CredentialOffer{grants: %{pre_authorized_code: nil}}, _opts),
    do: {:error, :missing_pre_authorized_code_grant}

  defp exchange_pre_authorized_code(%CredentialOffer{grants: %{pre_authorized_code: grant}}, opts) do
    with {:ok, tx_code} <- required_tx_code(grant, opts),
         {:ok, tokens} <-
           Token.exchange_pre_authorized_code(grant.code, Keyword.put(opts, :tx_code, tx_code)),
         :ok <- check_token_binding(tokens, opts) do
      {:ok, tokens.access_token}
    end
  end

  defp check_token_binding(tokens, opts) do
    with {:ok, jkt} <- TokenSet.dpop_thumbprint(opts),
         {:ok, _bound} <- TokenSet.bind_dpop(tokens, jkt) do
      cond do
        not is_binary(tokens.access_token) or tokens.access_token == "" ->
          {:error, :invalid_token_set}

        TokenSet.dpop?(tokens.token_type) and Map.get(tokens, :dpop_jkt) != jkt ->
          {:error, :dpop_key_mismatch}

        true ->
          :ok
      end
    end
  end

  defp required_tx_code(%{tx_code: nil}, _opts), do: {:ok, nil}

  defp required_tx_code(%{tx_code: %{}}, opts) do
    case Keyword.get(opts, :tx_code) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _missing -> {:error, :missing_tx_code}
    end
  end

  defp fetch_nonce(opts) do
    case Keyword.get(opts, :nonce_endpoint) do
      nil -> {:ok, nil}
      endpoint when is_binary(endpoint) and endpoint != "" -> request_nonce(endpoint, opts)
      _invalid -> {:error, :invalid_nonce_endpoint}
    end
  end

  defp request_nonce(endpoint, opts) do
    case OAuthHTTP.post_form(endpoint, %{}, opts) do
      {:ok, %{"c_nonce" => c_nonce}} when is_binary(c_nonce) and c_nonce != "" -> {:ok, c_nonce}
      {:ok, _invalid} -> {:error, :invalid_nonce_response}
      {:error, reason} -> {:error, reason}
    end
  end

  # A single holder key issues one credential; a non-empty list requests batch
  # issuance (OID4VCI §8.2) - one proof per key, one credential returned per
  # proof, each bound to its own key.
  defp holder_keys(keys) when is_list(keys) and keys != [], do: {:ok, keys}
  defp holder_keys([]), do: {:error, :missing_holder_key}
  defp holder_keys(key), do: {:ok, [key]}

  # The ordered public halves of the holder keys - used both to attest them
  # (key attestation) and to check that each issued credential is bound to the
  # key whose proof of possession requested it.
  defp holder_public_keys(keys) do
    keys
    |> Enum.reduce_while({:ok, []}, fn key, {:ok, acc} ->
      case Builder.normalize_key(key) do
        {:ok, jwk} ->
          {_type, public} = JOSE.JWK.to_public_map(jwk)
          {:cont, {:ok, [public | acc]}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, publics} -> {:ok, Enum.reverse(publics)}
      {:error, reason} -> {:error, reason}
    end
  end

  # Fail closed before any network side effect if the caller supplied no issuer
  # trust anchor: without it the issued credential's signature cannot be
  # verified (and `Attesto.SdJwtVc.verify/3` would raise on `nil`).
  defp validate_trusted(opts) do
    with :ok <- CredentialTrust.validate_options(opts) do
      if Keyword.get(opts, :haip, false), do: :ok, else: validate_fixed_trust(opts)
    end
  end

  defp validate_fixed_trust(opts) do
    case Keyword.get(opts, :trusted) do
      %{} = trusted when map_size(trusted) > 0 -> :ok
      [_ | _] -> :ok
      trusted when is_binary(trusted) and trusted != "" -> :ok
      _ -> {:error, :missing_trusted}
    end
  end

  # `:key_attestation` may be a pre-built compact JWT, or a 2-arity builder
  # `(holder_public_jwks, c_nonce) -> {:ok, jwt} | {:error, reason}` so the
  # attestation can be minted AFTER the issuer's `c_nonce` is fetched (a HAIP
  # issuer that rotates nonces requires the attestation to echo the current one).
  defp resolve_key_attestation(opts, holder_publics, c_nonce) do
    case Keyword.get(opts, :key_attestation) do
      nil ->
        {:ok, nil}

      jwt when is_binary(jwt) and jwt != "" ->
        {:ok, jwt}

      fun when is_function(fun, 2) ->
        build_key_attestation(fun, holder_publics, c_nonce)

      _invalid ->
        {:error, :invalid_key_attestation}
    end
  end

  defp build_key_attestation(fun, holder_publics, c_nonce) do
    case fun.(holder_publics, c_nonce) do
      {:ok, jwt} when is_binary(jwt) and jwt != "" -> {:ok, jwt}
      {:error, reason} -> {:error, {:key_attestation, reason}}
      _invalid -> {:error, :invalid_key_attestation}
    end
  end

  defp build_proofs(offer, keys, c_nonce, key_attestation, opts) do
    keys
    |> Enum.reduce_while({:ok, []}, fn key, {:ok, acc} ->
      case build_proof(offer, key, c_nonce, key_attestation, opts) do
        {:ok, proof} -> {:cont, {:ok, [proof | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, proofs} -> {:ok, Enum.reverse(proofs)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_proof(offer, holder_key, c_nonce, key_attestation, opts) do
    proof_opts =
      [credential_issuer: offer.credential_issuer]
      |> put_optional(:nonce, c_nonce)
      |> put_optional(:client_id, Keyword.get(opts, :client_id))
      |> put_optional(:now, Keyword.get(opts, :now))
      |> put_optional(:alg, Keyword.get(opts, :proof_alg))
      |> put_optional(:kid, Keyword.get(opts, :proof_kid))
      |> put_optional(:key_attestation, key_attestation)

    Proof.build(holder_key, proof_opts)
  end

  defp post_credential_request(configuration_id, proofs, access_token, encryption, opts) do
    with {:ok, endpoint} <-
           required_string(opts, :credential_endpoint, :missing_credential_endpoint) do
      # OID4VCI 1.0 final §8.2: a Credential Request carries `proofs`, an object
      # keyed by proof type whose value is an array of proofs (the singular
      # `proof` of earlier drafts was removed). A multi-proof array is a batch
      # request - one credential is returned per proof.
      body = %{
        "credential_configuration_id" => configuration_id,
        "proofs" => %{"jwt" => proofs}
      }

      CredentialEncryption.post(endpoint, body, access_token, encryption, opts)
    end
  end

  defp deferred_response(response, access_token, encryption, opts) do
    Deferred.resolve(response, opts, fn transaction_id, poll_opts ->
      with {:ok, endpoint} <-
             required_string(poll_opts, :deferred_credential_endpoint, :missing_deferred_endpoint) do
        CredentialEncryption.post(
          endpoint,
          %{"transaction_id" => transaction_id},
          access_token,
          encryption,
          poll_opts
        )
      end
    end)
  end

  defp finalize(
         %{"transaction_id" => transaction_id} = response,
         _format,
         c_nonce,
         _access_token,
         _holder_publics,
         _opts,
         _type_binding
       )
       when is_binary(transaction_id) and transaction_id != "" do
    pending = %{
      status: :pending,
      transaction_id: transaction_id,
      notification_id: Map.get(response, "notification_id")
    }

    {:ok, %{credentials: [pending], c_nonce: c_nonce}}
  end

  defp finalize(
         %{"credentials" => credentials} = response,
         format,
         c_nonce,
         access_token,
         holder_publics,
         opts,
         type_binding
       )
       when is_list(credentials) and credentials != [] do
    with {:ok, held} <-
           verify_credentials(credentials, format, holder_publics, opts, type_binding),
         :ok <- maybe_notify(response, access_token, opts) do
      {:ok,
       %{
         credentials: held,
         c_nonce: c_nonce,
         notification_id: Map.get(response, "notification_id")
       }}
    end
  end

  defp finalize(
         _response,
         _format,
         _c_nonce,
         _access_token,
         _holder_publics,
         _opts,
         _type_binding
       ),
       do: {:error, :invalid_credential_response}

  # OID4VCI §10: when the caller supplies a `:notification_endpoint` and the
  # issuer returned a `notification_id`, POST a Notification acknowledging the
  # credential. No endpoint or no id means nothing to notify.
  defp maybe_notify(response, access_token, opts) do
    endpoint = Keyword.get(opts, :notification_endpoint)
    notification_id = Map.get(response, "notification_id")

    if is_binary(endpoint) and endpoint != "" and is_binary(notification_id) and
         notification_id != "" do
      event = Keyword.get(opts, :notification_event, "credential_accepted")
      body = %{"notification_id" => notification_id, "event" => event}

      case OAuthHTTP.post_json_unit(endpoint, body, access_token, opts) do
        :ok -> :ok
        {:error, reason} -> {:error, {:notification, reason}}
      end
    else
      :ok
    end
  end

  # OID4VCI §8.3 permits fewer credentials than submitted proofs. Every returned
  # credential must still bind to a distinct requested holder key. Reject extra
  # credentials and any key the wallet did not prove possession of.
  defp verify_credentials(credentials, _format, holder_publics, _opts, _type_binding)
       when length(credentials) > length(holder_publics),
       do: {:error, :credential_count_mismatch}

  defp verify_credentials(credentials, format, holder_publics, opts, type_binding) do
    with {:ok, expected} <- expected_thumbprints(holder_publics) do
      # Each returned credential must be bound to a DISTINCT holder key the
      # wallet proved possession of. Membership + distinctness is order-
      # independent (the issuer need not echo proof order) yet still enforces a
      # one-to-one binding between proofs and credentials.
      credentials
      |> Enum.reduce_while({:ok, [], MapSet.new()}, fn entry, acc ->
        verify_credential_entry(entry, acc, format, opts, expected, type_binding)
      end)
      |> case do
        {:ok, held, _used} -> {:ok, Enum.reverse(held)}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp verify_credential_entry(entry, {:ok, acc, used}, format, opts, expected, type_binding) do
    with {:ok, credential} <- credential_value(entry),
         {:ok, held} <- verify_credential(format, credential, opts),
         :ok <- check_configuration_type(held, type_binding),
         {:ok, thumb} <- held_binding_thumbprint(held),
         :ok <- check_binding_membership(thumb, expected, used) do
      {:cont, {:ok, [held | acc], MapSet.put(used, thumb)}}
    else
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp check_configuration_type(_held, nil), do: :ok

  defp check_configuration_type(%{claims: %{"vct" => type}}, {:vct, type}), do: :ok
  defp check_configuration_type(%{doc_type: type}, {:doc_type, type}), do: :ok

  defp check_configuration_type(_held, _binding),
    do: {:error, :credential_configuration_type_mismatch}

  defp expected_thumbprints(holder_publics) do
    holder_publics
    |> Enum.reduce_while({:ok, MapSet.new()}, fn public, {:ok, set} ->
      case Thumbprint.of_jwk(public) do
        {:ok, thumb} -> {:cont, {:ok, MapSet.put(set, thumb)}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  # The credential's holder binding (SD-JWT/JWT `cnf.jwk`, or the mdoc device
  # key) as an RFC 7638 thumbprint.
  defp held_binding_thumbprint(held) do
    with {:ok, bound_jwk} <- binding_jwk(held), do: Thumbprint.of_jwk(bound_jwk)
  end

  defp check_binding_membership(thumb, expected, used) do
    cond do
      not MapSet.member?(expected, thumb) -> {:error, :holder_binding_mismatch}
      MapSet.member?(used, thumb) -> {:error, :holder_binding_mismatch}
      true -> :ok
    end
  end

  defp binding_jwk(%{holder_binding: %{"jwk" => jwk}}) when is_map(jwk), do: {:ok, jwk}

  defp binding_jwk(%{format: @mdoc_format, holder_binding: device_key}) when is_map(device_key),
    do: {:ok, device_key}

  defp binding_jwk(_held), do: {:error, :missing_holder_binding}

  defp credential_value(%{"credential" => credential})
       when is_binary(credential) and credential != "",
       do: {:ok, credential}

  defp credential_value(_entry), do: {:error, :invalid_credential_response}

  defp verify_credential(format, credential, opts) do
    with {:ok, key, provenance} <- CredentialTrust.resolve(format, credential, opts),
         {:ok, held} <- verify_format(format, credential, key, opts) do
      {:ok, CredentialTrust.attach(held, provenance)}
    end
  end

  defp verify_format(format, credential, key, opts) when format in @sd_jwt_vc_formats do
    with {:ok, %{claims: claims, cnf: cnf}} <-
           Attesto.SdJwtVc.verify(credential, key, verify_opts(opts)) do
      {:ok, %{format: format, credential: credential, claims: claims, holder_binding: cnf}}
    end
  end

  defp verify_format(@jwt_vc_format, credential, key, opts) do
    with {:ok, %{claims: claims, cnf: cnf}} <-
           Attesto.JwtVc.verify(credential, key, verify_opts(opts)) do
      {:ok,
       %{format: @jwt_vc_format, credential: credential, claims: claims, holder_binding: cnf}}
    end
  end

  if Code.ensure_loaded?(CBOR) do
    defp verify_format(@mdoc_format, credential, key, opts) do
      with {:ok, %{namespaces: namespaces, device_key: device_key, doc_type: doc_type}} <-
             Attesto.Mdoc.verify(credential, key, verify_opts(opts)) do
        {:ok,
         %{
           format: @mdoc_format,
           credential: credential,
           claims: namespaces,
           holder_binding: device_key,
           doc_type: doc_type
         }}
      end
    end
  else
    defp verify_format(@mdoc_format, _credential, _key, _opts),
      do: {:error, :unsupported_mdoc}
  end

  defp verify_format(_format, _credential, _key, _opts), do: {:error, :unsupported_format}

  defp verify_opts(opts) do
    verify_opts = Keyword.get(opts, :verify_opts, [])

    if Keyword.get(opts, :haip, false) do
      # CredentialTrust has already enforced certificate provenance and PS256
      # RSA strength. HAIP also supports the larger ECDSA curves; that broader
      # algorithm policy is explicit at this composition boundary.
      verify_opts
      |> Keyword.put(:issuer_identity, :certificate)
      |> Keyword.put_new(:enforce_fapi_alg_policy, false)
    else
      verify_opts
    end
  end

  defp put_optional(opts, _key, nil), do: opts
  defp put_optional(opts, key, value), do: Keyword.put(opts, key, value)

  defp required_string(opts, key, error) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, error}
    end
  end
end
