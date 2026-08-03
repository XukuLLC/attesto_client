defmodule AttestoClient.OAuthHTTP do
  @moduledoc false

  alias AttestoClient.ClientAssertion
  alias AttestoClient.Deadline
  alias AttestoClient.DPoP
  alias AttestoClient.WalletAttestation

  @default_timeout_ms 10_000

  @spec post_form(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def post_form(endpoint, form, opts) when is_map(form) and is_list(opts) do
    with :ok <- validate_endpoint(endpoint, opts),
         {:ok, timeout_ms} <- timeout(opts) do
      Deadline.run(
        fn -> request(endpoint, form, timeout_ms, :json, opts) end,
        timeout_ms
      )
    end
  end

  @spec post_form_unit(String.t(), map(), keyword()) :: :ok | {:error, term()}
  def post_form_unit(endpoint, form, opts) when is_map(form) and is_list(opts) do
    with :ok <- validate_endpoint(endpoint, opts),
         {:ok, timeout_ms} <- timeout(opts) do
      Deadline.run(
        fn -> request(endpoint, form, timeout_ms, :unit, opts) end,
        timeout_ms
      )
    end
  end

  @doc """
  POST a JSON body authenticated with an OAuth Bearer access token, returning
  the decoded JSON response.

  For endpoints that authenticate the caller with a previously issued access
  token rather than client credentials - the OID4VCI Credential Endpoint is
  the current use - not `post_form/3`'s client authentication.

  Pass `:dpop` (a `JOSE.JWK` or JWK map) to sender-constrain the request with an
  RFC 9449 DPoP proof; the proof carries the `ath` binding to `access_token` and
  a `use_dpop_nonce` challenge is retried once with the server's `DPoP-Nonce`.
  """
  @spec post_json(String.t(), map(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def post_json(endpoint, body, access_token, opts)
      when is_map(body) and is_binary(access_token) and access_token != "" and is_list(opts) do
    with :ok <- validate_endpoint(endpoint, opts),
         {:ok, timeout_ms} <- timeout(opts) do
      Deadline.run(
        fn -> json_request(endpoint, body, access_token, opts, timeout_ms, &classify_json/1) end,
        timeout_ms
      )
    end
  end

  @doc """
  POST a JSON body authenticated with an access token, expecting a 2xx with no
  meaningful body (`:ok` on success). Used for the OID4VCI Notification Endpoint,
  which answers `204 No Content`. `:dpop` behaves as in `post_json/4`.
  """
  @spec post_json_unit(String.t(), map(), String.t(), keyword()) :: :ok | {:error, term()}
  def post_json_unit(endpoint, body, access_token, opts)
      when is_map(body) and is_binary(access_token) and access_token != "" and is_list(opts) do
    with :ok <- validate_endpoint(endpoint, opts),
         {:ok, timeout_ms} <- timeout(opts) do
      Deadline.run(
        fn ->
          json_request(endpoint, body, access_token, opts, timeout_ms, &classify_json_unit/1)
        end,
        timeout_ms
      )
    end
  end

  @doc """
  GET a JSON document, returning the decoded body.

  Used for by-reference fetches initiated by the caller (e.g. an OID4VCI
  `credential_offer_uri`) rather than a discovery document (see
  `AttestoClient.Discovery` for that, which additionally enforces the
  issuer-identifier matching RFC 8414 §3.3 requires).
  """
  @spec get_json(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_json(url, opts) when is_binary(url) and is_list(opts) do
    with :ok <- validate_endpoint(url, opts),
         {:ok, timeout_ms} <- timeout(opts) do
      Deadline.run(
        fn -> get_request(url, req_options(opts), timeout_ms) end,
        timeout_ms
      )
    end
  end

  @doc """
  GET a raw text document, returning the response body unparsed.

  Used for by-reference fetches whose body is not JSON - an OID4VP
  `request_uri` serves a compact JWT (`application/oauth-authz-req+jwt`),
  not a JSON object (see `AttestoClient.Wallet.PresentationRequest.fetch/3`).
  """
  @spec get_text(String.t(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def get_text(url, opts) when is_binary(url) and is_list(opts) do
    with :ok <- validate_endpoint(url, opts),
         {:ok, timeout_ms} <- timeout(opts) do
      Deadline.run(
        fn -> get_text_request(url, req_options(opts), timeout_ms) end,
        timeout_ms
      )
    end
  end

  @doc """
  POST a form body with no OAuth client authentication, returning the decoded
  JSON body when present (an empty/non-JSON success body decodes to `%{}`).

  Used for a submission the OAuth client-authentication model does not
  cover - the OID4VP `direct_post` `response_uri`, which a wallet POSTs to
  unauthenticated (see `AttestoClient.Wallet.Presentation.submit/3`) - unlike
  `post_form/3`'s token-endpoint requests.
  """
  @spec post_form_open(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def post_form_open(endpoint, form, opts) when is_map(form) and is_list(opts) do
    with :ok <- validate_endpoint(endpoint, opts),
         {:ok, timeout_ms} <- timeout(opts) do
      Deadline.run(
        fn -> open_request(endpoint, form, req_options(opts), timeout_ms) end,
        timeout_ms
      )
    end
  end

  defp validate_endpoint(endpoint, opts) do
    AttestoClient.Discovery.validate_endpoint(endpoint,
      req_options: Keyword.get(opts, :req_options, [])
    )
  end

  defp authenticate(form, endpoint, opts) do
    client_id = Keyword.get(opts, :client_id)
    authenticate_as(Keyword.get(opts, :client_auth, :none), client_id, form, endpoint, opts)
  end

  defp authenticate_as(:none, client_id, form, _endpoint, opts)
       when is_binary(client_id) and client_id != "" do
    {:ok, Map.put(form, "client_id", client_id), req_options(opts)}
  end

  defp authenticate_as({:client_secret_basic, secret}, client_id, form, _endpoint, opts)
       when is_binary(client_id) and client_id != "" and is_binary(secret) and secret != "" do
    credentials = "#{URI.encode_www_form(client_id)}:#{URI.encode_www_form(secret)}"
    {:ok, form, Keyword.put(req_options(opts), :auth, {:basic, credentials})}
  end

  defp authenticate_as({:client_secret_post, secret}, client_id, form, _endpoint, opts)
       when is_binary(client_id) and client_id != "" and is_binary(secret) and secret != "" do
    {:ok, Map.merge(form, %{"client_id" => client_id, "client_secret" => secret}),
     req_options(opts)}
  end

  defp authenticate_as({:private_key_jwt, jwk}, client_id, form, endpoint, opts)
       when is_binary(client_id) and client_id != "" do
    authenticate_as({:private_key_jwt, jwk, []}, client_id, form, endpoint, opts)
  end

  defp authenticate_as({:private_key_jwt, jwk, assertion_opts}, client_id, form, endpoint, opts)
       when is_binary(client_id) and client_id != "" and is_list(assertion_opts) do
    with {:ok, build_opts} <- client_assertion_options(assertion_opts, client_id, endpoint) do
      case ClientAssertion.build(jwk, build_opts) do
        {:ok, assertion} ->
          {:ok,
           Map.merge(form, %{
             "client_id" => client_id,
             "client_assertion_type" => ClientAssertion.assertion_type(),
             "client_assertion" => assertion
           }), req_options(opts)}

        {:error, reason} ->
          {:error, {:client_assertion, reason}}
      end
    end
  end

  # OAuth Attestation-Based Client Authentication (draft-ietf-oauth-attestation-
  # based-client-auth): present the long-lived Client Attestation JWT plus a
  # fresh per-request PoP in the `OAuth-Client-Attestation[-PoP]` headers. The
  # PoP's `aud` MUST be the server's own identifier (the AS issuer / RS resource
  # identifier), not the concrete endpoint URL, so the caller must pass an
  # explicit `:audience` in the auth opts; omitting it fails closed via
  # `WalletAttestation.pop/2` (`:invalid_audience`) rather than binding to the
  # wrong audience.
  defp authenticate_as(
         {:client_attestation, attestation, instance_key, ca_opts},
         client_id,
         form,
         _endpoint,
         opts
       )
       when is_binary(client_id) and client_id != "" and is_binary(attestation) and
              attestation != "" and is_list(ca_opts) do
    pop_opts = Keyword.put(ca_opts, :client_id, client_id)

    case WalletAttestation.pop(instance_key, pop_opts) do
      {:ok, pop} ->
        headers = [
          {"oauth-client-attestation", attestation},
          {"oauth-client-attestation-pop", pop}
        ]

        {:ok, Map.put(form, "client_id", client_id),
         Keyword.update(req_options(opts), :headers, headers, &(&1 ++ headers))}

      {:error, reason} ->
        {:error, {:client_attestation, reason}}
    end
  end

  defp authenticate_as(_invalid, _client_id, _form, _endpoint, _opts),
    do: {:error, :invalid_client_auth}

  defp client_assertion_options(opts, client_id, endpoint) do
    allowed = [:audience, :alg, :kid, :lifetime, :now, :jti]
    keys = if Keyword.keyword?(opts), do: Keyword.keys(opts), else: []

    if keys != [] or opts == [] do
      if Enum.all?(keys, &(&1 in allowed)) and length(keys) == length(Enum.uniq(keys)) do
        build_opts =
          opts
          |> Keyword.put_new(:audience, endpoint)
          |> Keyword.put(:client_id, client_id)

        {:ok, build_opts}
      else
        {:error, :invalid_client_assertion_options}
      end
    else
      {:error, :invalid_client_assertion_options}
    end
  end

  defp request(endpoint, form, timeout_ms, response_mode, opts) do
    # Re-authenticate per attempt: a DPoP `use_dpop_nonce` retry must carry a
    # FRESH client_assertion / client-attestation PoP (unique `jti`), not a
    # replay of the first attempt's - the server rejects reused assertion jtis.
    builder = fn retry? ->
      # On a nonce retry, force fresh client-auth `jti`s even if the caller
      # pinned one, so the retried assertion/PoP cannot be a replay of the first.
      attempt_opts = if retry?, do: drop_client_auth_jti(opts), else: opts

      with {:ok, form2, req_options} <- authenticate(form, endpoint, attempt_opts) do
        {:ok,
         req_options ++
           [
             url: endpoint,
             method: :post,
             form: form2,
             redirect: false,
             retry: false,
             receive_timeout: timeout_ms
           ]}
      end
    end

    # A DPoP-bound token request carries no `ath` (there is no access token yet).
    run_with_dpop(
      dpop_context(opts, "POST", endpoint, nil),
      builder,
      &classify_form(&1, response_mode)
    )
  end

  defp classify_form(%Req.Response{status: status}, :unit) when status in 200..299, do: :ok

  defp classify_form(%Req.Response{status: status, body: body}, _mode)
       when status in 200..299 and is_map(body),
       do: {:ok, body}

  defp classify_form(%Req.Response{status: status, body: %{} = body}, _mode),
    do: {:error, {:oauth_error, status, Map.take(body, ["error", "error_description"])}}

  defp classify_form(%Req.Response{status: status}, _mode), do: {:error, {:http_status, status}}

  defp json_request(endpoint, body, access_token, opts, timeout_ms, classify) do
    dpop_ctx = dpop_context(opts, "POST", endpoint, access_token)

    builder = fn ->
      base =
        req_options(opts) ++
          [
            url: endpoint,
            method: :post,
            json: body,
            redirect: false,
            retry: false,
            receive_timeout: timeout_ms
          ]

      {:ok, put_token_auth(base, access_token, dpop_ctx)}
    end

    # The credential/resource request has no client_assertion, so the retry only
    # needs a fresh DPoP proof (minted per attempt below); the base is identical.
    run_with_dpop(dpop_ctx, fn _retry? -> builder.() end, classify)
  end

  # Drop a caller-pinned client-auth `jti` so re-authentication mints a fresh
  # one; without this a pinned `jti` would replay across a nonce retry.
  defp drop_client_auth_jti(opts) do
    case Keyword.get(opts, :client_auth) do
      {:private_key_jwt, jwk, assertion_opts} when is_list(assertion_opts) ->
        Keyword.put(
          opts,
          :client_auth,
          {:private_key_jwt, jwk, Keyword.delete(assertion_opts, :jti)}
        )

      {:client_attestation, attestation, key, ca_opts} when is_list(ca_opts) ->
        Keyword.put(
          opts,
          :client_auth,
          {:client_attestation, attestation, key, Keyword.delete(ca_opts, :jti)}
        )

      _other ->
        opts
    end
  end

  # RFC 9449 §7.1: a DPoP-sender-constrained access token is presented with the
  # `DPoP` authentication scheme, not `Bearer`. Without DPoP, use Bearer.
  defp put_token_auth(base, access_token, nil),
    do: Keyword.put(base, :auth, {:bearer, access_token})

  defp put_token_auth(base, access_token, _dpop_ctx) do
    # Strip any caller-supplied Authorization header before installing the
    # protocol-owned one, so the request never carries two Authorization values
    # (which a server may reject or resolve to the wrong credential).
    headers =
      base
      |> Keyword.get(:headers, [])
      |> Enum.reject(fn {name, _value} -> String.downcase(to_string(name)) == "authorization" end)

    Keyword.put(base, :headers, [{"authorization", "DPoP " <> access_token} | headers])
  end

  defp classify_json(%Req.Response{status: status, body: body})
       when status in 200..299 and is_map(body),
       do: {:ok, body}

  defp classify_json(%Req.Response{status: status, body: %{} = body}),
    do:
      {:error,
       {:oauth_error, status,
        Map.take(body, ["error", "error_description", "c_nonce", "c_nonce_expires_in"])}}

  defp classify_json(%Req.Response{status: status}), do: {:error, {:http_status, status}}

  defp classify_json_unit(%Req.Response{status: status}) when status in 200..299, do: :ok

  defp classify_json_unit(%Req.Response{status: status, body: %{} = body}),
    do: {:error, {:oauth_error, status, Map.take(body, ["error", "error_description"])}}

  defp classify_json_unit(%Req.Response{status: status}), do: {:error, {:http_status, status}}

  # RFC 9449: when `:dpop` is set, attach a fresh proof header per attempt and
  # retry once against a `use_dpop_nonce` challenge, echoing the server's
  # `DPoP-Nonce`. `builder` is re-run per attempt so each retry also gets fresh
  # client-auth artifacts (a new client_assertion / client-attestation PoP),
  # never a replay. Without `:dpop`, build and send once.
  defp run_with_dpop(nil, builder, classify) do
    with {:ok, base} <- builder.(false) do
      send_and_classify(base, [], classify)
    end
  end

  defp run_with_dpop(ctx, builder, classify), do: dpop_attempt(ctx, builder, classify, nil, true)

  # `first?` is true for the initial attempt and false for the single retry; the
  # builder is told `retry? = not first?` so it can refresh client-auth `jti`s.
  defp dpop_attempt(ctx, builder, classify, nonce, first?) do
    with {:ok, base} <- builder.(not first?),
         {:ok, proof} <- dpop_proof(ctx, nonce) do
      case send_request(base, [{"dpop", proof}]) do
        {:ok, resp} ->
          if first? and dpop_nonce_challenge?(resp) do
            case dpop_nonce(resp) do
              nil -> classify.(resp)
              fresh -> dpop_attempt(ctx, builder, classify, fresh, false)
            end
          else
            classify.(resp)
          end

        {:error, _reason} ->
          {:error, :transport_error}
      end
    end
  end

  defp dpop_proof(ctx, nonce) do
    proof_opts =
      [access_token: ctx.access_token, nonce: nonce]
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    case DPoP.proof(ctx.key, ctx.method, ctx.url, proof_opts) do
      {:ok, proof} -> {:ok, proof}
      {:error, reason} -> {:error, {:dpop, reason}}
    end
  end

  defp dpop_context(opts, method, url, access_token) do
    case Keyword.get(opts, :dpop) do
      nil -> nil
      key -> %{key: key, method: method, url: url, access_token: access_token}
    end
  end

  # An AS challenges a DPoP token request with 400 `use_dpop_nonce`; a resource
  # server with 401. Either way a `DPoP-Nonce` header names the nonce to echo.
  defp dpop_nonce_challenge?(%Req.Response{status: status} = resp) when status in [400, 401] do
    dpop_error(resp) == "use_dpop_nonce" and dpop_nonce(resp) != nil
  end

  defp dpop_nonce_challenge?(_resp), do: false

  defp dpop_error(%Req.Response{body: %{"error" => error}}) when is_binary(error), do: error

  defp dpop_error(%Req.Response{} = resp) do
    # A resource server carries the error in WWW-Authenticate, not a JSON body.
    case Req.Response.get_header(resp, "www-authenticate") do
      [header | _] ->
        if String.contains?(header, "use_dpop_nonce"), do: "use_dpop_nonce", else: nil

      [] ->
        nil
    end
  end

  defp dpop_nonce(%Req.Response{} = resp) do
    case Req.Response.get_header(resp, "dpop-nonce") do
      [nonce | _] when is_binary(nonce) and nonce != "" -> nonce
      _ -> nil
    end
  end

  defp send_and_classify(base, headers, classify) do
    case send_request(base, headers) do
      {:ok, resp} -> classify.(resp)
      {:error, _reason} -> {:error, :transport_error}
    end
  end

  defp send_request(base, []), do: run_req(base)

  defp send_request(base, headers) do
    # Merge onto any headers the base already carries (e.g. client-attestation
    # headers set during authentication) rather than replacing them, so DPoP and
    # client attestation compose on the same request.
    base
    |> Keyword.update(:headers, headers, fn existing -> existing ++ headers end)
    |> run_req()
  end

  defp run_req(options) do
    Req.request(Req.new(options))
  rescue
    _error -> {:error, :transport_error}
  end

  # Cap by-reference fetches (a caller-supplied `credential_offer_uri` /
  # `request_uri`, i.e. attacker-influenceable): a hostile endpoint could
  # otherwise stream an unbounded body to exhaust memory. `raw: true` also skips
  # response decompression, so a small compressed body cannot inflate past the
  # cap either.
  @max_response_bytes 2_000_000

  defp get_request(url, req_options, timeout_ms) do
    case bounded_get(url, req_options, timeout_ms) do
      {:ok, %Req.Response{status: 200, body: body}} when is_binary(body) ->
        case JSON.decode(body) do
          {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
          _other -> {:error, :invalid_json}
        end

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_text_request(url, req_options, timeout_ms) do
    case bounded_get(url, req_options, timeout_ms) do
      {:ok, %Req.Response{status: 200, body: body}} when is_binary(body) -> {:ok, body}
      {:ok, %Req.Response{status: status}} -> {:error, {:http_status, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp bounded_get(url, req_options, timeout_ms) do
    collector = fn {:data, chunk}, {req, resp} ->
      body = (resp.body || "") <> chunk
      acc = {req, %{resp | body: body}}
      if byte_size(body) > @max_response_bytes, do: {:halt, acc}, else: {:cont, acc}
    end

    options =
      req_options ++
        [
          url: url,
          method: :get,
          redirect: false,
          retry: false,
          receive_timeout: timeout_ms,
          raw: true,
          into: collector
        ]

    case Req.request(Req.new(options)) do
      {:ok, %Req.Response{body: body} = resp} ->
        if is_binary(body) and byte_size(body) > @max_response_bytes,
          do: {:error, :response_too_large},
          else: {:ok, resp}

      {:error, _reason} ->
        {:error, :transport_error}
    end
  rescue
    _error -> {:error, :transport_error}
  end

  defp open_request(endpoint, form, req_options, timeout_ms) do
    options =
      req_options ++
        [
          url: endpoint,
          method: :post,
          form: form,
          redirect: false,
          retry: false,
          receive_timeout: timeout_ms
        ]

    case Req.request(Req.new(options)) do
      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
        {:ok, json_body(body)}

      {:ok, %Req.Response{status: status, body: %{} = body}} ->
        {:error, {:oauth_error, status, Map.take(body, ["error", "error_description"])}}

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, _reason} ->
        {:error, :transport_error}
    end
  rescue
    _error -> {:error, :transport_error}
  end

  defp json_body(body) when is_map(body), do: body
  defp json_body(_body), do: %{}

  defp req_options(opts), do: Keyword.get(opts, :req_options, [])

  defp timeout(opts) do
    case Keyword.get(opts, :timeout, @default_timeout_ms) do
      timeout when is_integer(timeout) and timeout > 0 -> {:ok, timeout}
      _invalid -> {:error, :invalid_timeout}
    end
  end
end
