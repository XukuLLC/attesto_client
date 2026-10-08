defmodule AttestoClient.Wallet.PresentationRequest do
  @moduledoc """
  Verify signed OID4VP 1.0 wallet authorization requests.

  `from_uri/3` binds the outer `client_id` to the signed request and ignores
  other outer authorization parameters. Request URI POST sends a fresh wallet
  nonce, which must be echoed in the signed object. Requests using `x509_hash`
  require explicit DER trust anchors in `:trusted_certificates`; the embedded
  leaf certificate supplies the signing key, never the trust decision.
  An optional `:certificate_trust` callback adds ecosystem/revocation policy.

  Pre-registered signed requests retain the temporal verification options from
  `Attesto.RequestObject`. All signed requests require `oauth-authz-req+jwt`;
  `iss` is ignored and the verified `client_id` identifies the verifier.
  Algorithm policies must be nonempty and can only narrow supported algorithms.
  HAIP retains the wallet signature and key-strength policy. An explicit
  `enforce_fapi_alg_policy: true` additionally narrows algorithms to FAPI.
  This module supports `direct_post` and encrypted `direct_post.jwt`.
  Unsupported transaction data fails closed before credential selection.

  Verifier metadata must contain a nonempty `vp_formats_supported` object.
  Registered clients may supply authoritative metadata through
  `:verifier_metadata`; its fields take precedence over the signed metadata.
  For `x509_hash`, all metadata must come from the signed `client_metadata`.
  Advertised issuer and holder algorithms constrain the actual presentation.
  """

  alias Attesto.{Claims, JWS, RequestObject, SigningAlg}
  alias AttestoClient.OAuthHTTP
  alias AttestoClient.Wallet.Presentation.{CertificateTrust, DCQL, Encryption, Formats}

  @wallet_algorithms ~w(ES256 ES384 ES512 PS256 EdDSA Ed25519)

  @enforce_keys [:client_id, :nonce, :response_uri, :response_mode, :dcql_query]
  defstruct [
    :client_id,
    :nonce,
    :response_uri,
    :response_mode,
    :dcql_query,
    profile: :generic,
    state: nil,
    client_metadata: %{}
  ]

  @type t :: %__MODULE__{
          client_id: String.t(),
          nonce: String.t(),
          response_uri: String.t(),
          response_mode: String.t(),
          dcql_query: map(),
          profile: :generic | :haip,
          state: String.t() | nil,
          client_metadata: map()
        }
  @type error :: atom() | term()

  @doc false
  def validate_bindings(%__MODULE__{} = request) do
    claims = %{"nonce" => request.nonce}
    claims = if is_nil(request.state), do: claims, else: Map.put(claims, "state", request.state)

    with {:ok, _nonce} <- url_safe_string(claims, "nonce", :invalid_nonce),
         {:ok, _state} <- optional_url_safe_string(claims, "state", :invalid_state),
         do: :ok
  end

  @doc "Verify a compact request JWT. Pass :client_id to bind an outer authorization request."
  def verify(jwt, trusted, opts \\ []) when is_binary(jwt) and is_list(opts) do
    with :ok <- algorithm_policy(opts),
         {:ok, claims} <- verified_claims(jwt, trusted, opts),
         :ok <- bind_outer(claims, opts),
         :ok <- wallet_nonce(claims, opts),
         :ok <- profile_request(claims, opts) do
      from_claims(claims, opts)
    end
  end

  @doc "Fetch and verify a request URI; :request_uri_method may be get or post."
  def fetch(uri, trusted, opts \\ []) when is_binary(uri) and is_list(opts) do
    with :ok <- algorithm_policy(opts),
         {:ok, jwt, verify_opts} <- fetch_jwt(uri, opts),
         do: verify(jwt, trusted, verify_opts)
  end

  @doc "Parse an authorization deep link and verify its by-value or by-reference signed request."
  def from_uri(uri, trusted, opts \\ []) when is_binary(uri) and is_list(opts) do
    with true <- byte_size(uri) <= 65_536,
         {:ok, params} <- outer_params(uri),
         {:ok, client_id} <- required_string(params, "client_id", :invalid_client_id) do
      verify_opts = Keyword.put(opts, :client_id, client_id)
      resolve_outer(params, trusted, verify_opts)
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_request_object}
    end
  end

  defp outer_params(uri) do
    pairs = URI.query_decoder(URI.parse(uri).query || "") |> Enum.to_list()
    keys = Enum.map(pairs, &elem(&1, 0))

    if length(keys) == length(Enum.uniq(keys)),
      do: {:ok, Map.new(pairs)},
      else: {:error, :invalid_request_object}
  rescue
    _ -> {:error, :invalid_request_object}
  end

  defp resolve_outer(%{"request" => jwt} = params, trusted, opts) do
    if Map.has_key?(params, "request_uri") or Map.has_key?(params, "request_uri_method") or
         Keyword.get(opts, :haip, false),
       do: {:error, :invalid_request_object},
       else: verify(jwt, trusted, opts)
  end

  defp resolve_outer(%{"request_uri" => uri} = params, trusted, opts),
    do:
      fetch(
        uri,
        trusted,
        Keyword.put(opts, :request_uri_method, Map.get(params, "request_uri_method", "get"))
      )

  defp resolve_outer(_params, _trusted, _opts), do: {:error, :invalid_request_object}

  defp fetch_jwt(uri, opts) do
    case Keyword.get(opts, :request_uri_method, "get") do
      "get" -> with {:ok, jwt} <- OAuthHTTP.get_text(uri, opts), do: {:ok, jwt, opts}
      "post" -> post_request(uri, opts)
      _ -> {:error, :invalid_request_uri_method}
    end
  end

  defp post_request(uri, opts) do
    nonce = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

    with {:ok, jwt} <- OAuthHTTP.post_text_open(uri, %{"wallet_nonce" => nonce}, opts),
         do: {:ok, jwt, Keyword.put(opts, :wallet_nonce, nonce)}
  end

  defp verified_claims(jwt, trusted, opts) do
    with {:ok, claims} <- JWS.peek_json(jwt, :payload) do
      case Map.get(claims, "client_id") do
        "x509_hash:" <> _hash ->
          verify_x509(jwt, claims, opts)

        "origin:" <> _ ->
          {:error, :invalid_client_id}

        client_id when is_binary(client_id) ->
          verify_registered(jwt, trusted, Keyword.put_new(opts, :client_id, client_id))

        _ ->
          {:error, :invalid_client_id}
      end
    end
  end

  defp verify_registered(jwt, trusted, opts) do
    client_id = Keyword.get(opts, :client_id)

    if is_binary(client_id) and recognized_prefix?(client_id) do
      {:error, :unsupported_client_id_prefix}
    else
      opts =
        opts
        |> Keyword.put(:profile, :oid4vp)
        |> Keyword.put(:accepted_typ, ["oauth-authz-req+jwt"])
        |> Keyword.put(:accepted_algs, accepted_algorithms(opts))
        |> Keyword.put(:enforce_fapi_alg_policy, enforce_fapi_policy?(opts))
        |> Keyword.put_new(:audience, "https://self-issued.me/v2")

      case RequestObject.verify_with_claims(jwt, trusted, opts) do
        {:ok, _params, claims} -> {:ok, claims}
        error -> error
      end
    end
  end

  defp recognized_prefix?(id) do
    prefix = id |> String.split(":", parts: 2) |> hd()

    String.contains?(id, ":") and prefix not in ["https", "http"]
  end

  defp profile_request(claims, opts) do
    if Keyword.get(opts, :haip, false) and
         (not String.starts_with?(claims["client_id"] || "", "x509_hash:") or
            claims["response_mode"] != "direct_post.jwt"),
       do: {:error, :invalid_request},
       else: :ok
  end

  defp verify_x509(jwt, unverified, opts) do
    with {:ok, header} <- JWS.peek_json(jwt, :protected),
         true <- header["typ"] == "oauth-authz-req+jwt",
         :ok <- JWS.reject_unsupported_crit(header),
         {:ok, chain} <- CertificateTrust.decode_x5c(header["x5c"]),
         :ok <- leaf_hash(unverified["client_id"], hd(chain)),
         {:ok, %{public_key: key}} <-
           CertificateTrust.verify(chain, Keyword.put(opts, :purpose, :generic)),
         {:ok, claims} <- signed_claims(jwt, header, key, opts),
         :ok <- temporal_claims(claims, opts),
         :ok <- request_audience(claims, opts) do
      {:ok, claims}
    else
      false -> {:error, :invalid_typ}
      {:error, _} = error -> error
      _ -> {:error, :invalid_request_object}
    end
  end

  defp signed_claims(jwt, header, key, opts) do
    algorithms = accepted_algorithms(opts)

    candidates =
      JWS.verification_candidates(key,
        alg: header["alg"],
        accepted_algs: algorithms,
        fapi?: enforce_fapi_policy?(opts) or header["alg"] == "PS256"
      )

    JWS.verify_strict(jwt, candidates, claims_map?: true)
  end

  defp accepted_algorithms(opts) do
    defaults = if enforce_fapi_policy?(opts), do: SigningAlg.fapi_algs(), else: @wallet_algorithms
    Keyword.get(opts, :accepted_algs, defaults)
  end

  defp enforce_fapi_policy?(opts),
    do: Keyword.get(opts, :enforce_fapi_alg_policy, false)

  defp algorithm_policy(opts) do
    if Keyword.keyword?(opts) and is_boolean(Keyword.get(opts, :haip, false)) and
         is_boolean(Keyword.get(opts, :enforce_fapi_alg_policy, false)) do
      algorithms = accepted_algorithms(opts)

      allowed =
        if enforce_fapi_policy?(opts), do: SigningAlg.fapi_algs(), else: @wallet_algorithms

      if is_list(algorithms) and length(algorithms) in 1..length(@wallet_algorithms) and
           Enum.all?(algorithms, &(is_binary(&1) and &1 in allowed)),
         do: :ok,
         else: {:error, :invalid_algorithm_policy}
    else
      {:error, :invalid_algorithm_policy}
    end
  end

  defp leaf_hash("x509_hash:" <> expected, der) do
    actual = :crypto.hash(:sha256, der) |> Base.url_encode64(padding: false)
    if expected == actual, do: :ok, else: {:error, :invalid_client_id}
  end

  defp leaf_hash(_client_id, _der), do: {:error, :invalid_client_id}

  defp temporal_claims(claims, opts) do
    now = Keyword.get(opts, :now, System.system_time(:second))
    now = if match?(%DateTime{}, now), do: DateTime.to_unix(now), else: now

    cond do
      not valid_numeric_dates?(claims) ->
        {:error, :invalid_request_object}

      is_integer(claims["exp"]) and claims["exp"] <= now ->
        {:error, :expired}

      future_date?(claims, now) ->
        {:error, :not_yet_valid}

      true ->
        :ok
    end
  end

  defp valid_numeric_dates?(claims),
    do: Enum.all?(~w(exp iat nbf), &(not Map.has_key?(claims, &1) or is_integer(claims[&1])))

  defp future_date?(claims, now),
    do: Enum.any?(~w(iat nbf), &(is_integer(claims[&1]) and claims[&1] > now + 60))

  defp request_audience(claims, opts) do
    audience = Keyword.get(opts, :audience, "https://self-issued.me/v2")

    # OID4VP 1.0 §5 requires ignoring iss. The verified client_id and
    # certificate identify the verifier; aud retains the §5.8 wallet binding.
    if audience_matches?(claims["aud"], audience),
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp audience_matches?(actual, expected),
    do: Claims.audience_matches?(actual, expected, :array)

  defp bind_outer(claims, opts) do
    case Keyword.get(opts, :client_id) do
      nil -> :ok
      expected -> if claims["client_id"] == expected, do: :ok, else: {:error, :invalid_client_id}
    end
  end

  defp wallet_nonce(claims, opts) do
    case Keyword.get(opts, :wallet_nonce) do
      nil ->
        :ok

      expected ->
        if claims["wallet_nonce"] == expected, do: :ok, else: {:error, :invalid_wallet_nonce}
    end
  end

  defp from_claims(claims, opts) do
    with :ok <- request_constraints(claims),
         {:ok, client_id} <- required_string(claims, "client_id", :invalid_client_id),
         {:ok, nonce} <- url_safe_string(claims, "nonce", :invalid_nonce),
         {:ok, response_uri} <- required_string(claims, "response_uri", :invalid_response_uri),
         true <- valid_response_uri?(response_uri),
         {:ok, mode} <- response_mode(claims),
         :ok <- DCQL.validate(claims["dcql_query"]),
         {:ok, state} <- optional_url_safe_string(claims, "state", :invalid_state),
         {:ok, metadata} <-
           Formats.resolve(client_id, Map.get(claims, "client_metadata", %{}), opts) do
      request = %__MODULE__{
        client_id: client_id,
        nonce: nonce,
        response_uri: response_uri,
        response_mode: mode,
        dcql_query: claims["dcql_query"],
        profile: if(Keyword.get(opts, :haip, false), do: :haip, else: :generic),
        state: state,
        client_metadata: metadata
      }

      with {:ok, _context} <- Encryption.context(request), do: {:ok, request}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_request_object}
    end
  end

  defp request_constraints(claims) do
    cond do
      claims["response_type"] != "vp_token" ->
        {:error, :invalid_response_type}

      Map.has_key?(claims, "redirect_uri") ->
        {:error, :invalid_request}

      Map.has_key?(claims, "request") or Map.has_key?(claims, "request_uri") ->
        {:error, :invalid_request_object}

      Map.has_key?(claims, "request_uri_method") ->
        {:error, :invalid_request_uri_method}

      Map.has_key?(claims, "transaction_data") ->
        {:error, :invalid_transaction_data}

      true ->
        :ok
    end
  end

  defp response_mode(claims) do
    case Map.get(claims, "response_mode") do
      mode when mode in ["direct_post", "direct_post.jwt"] -> {:ok, mode}
      _ -> {:error, :invalid_response_mode}
    end
  end

  defp valid_response_uri?(uri) do
    parsed = URI.parse(uri)

    parsed.scheme == "https" and is_binary(parsed.host) and parsed.host != "" and
      is_nil(parsed.userinfo) and is_nil(parsed.fragment)
  end

  defp required_string(claims, key, error) do
    case Map.get(claims, key) do
      value when is_binary(value) and value != "" and byte_size(value) <= 8192 -> {:ok, value}
      _ -> {:error, error}
    end
  end

  defp url_safe_string(claims, key, error) do
    with {:ok, value} <- required_string(claims, key, error),
         true <- Regex.match?(~r/\A[A-Za-z0-9._~-]+\z/, value) do
      {:ok, value}
    else
      _ -> {:error, error}
    end
  end

  defp optional_url_safe_string(claims, key, error) do
    if Map.has_key?(claims, key), do: url_safe_string(claims, key, error), else: {:ok, nil}
  end
end
