defmodule AttestoClient.OAuthHTTP do
  @moduledoc false

  alias AttestoClient.Deadline
  alias AttestoClient.DPoP
  alias AttestoClient.HTTPPolicy
  alias AttestoClient.OAuthHTTP.{Challenge, ClientAuth}
  alias AttestoClient.PinnedRequest
  alias AttestoClient.ProtocolParams
  alias AttestoClient.Wallet.CredentialJSON

  @max_response_bytes 2_000_000
  @reserved_headers ~w(
    authorization
    content-length
    content-type
    dpop
    host
    oauth-client-attestation
    oauth-client-attestation-pop
  )

  # Validate the original encoded query before URI.decode_query can collapse
  # aliases or duplicates. Hosts may retain benign fixed endpoint parameters.
  @doc false
  @spec validate_endpoint_query(term(), [String.t()]) :: :ok | {:error, :invalid_endpoint_query}
  def validate_endpoint_query(endpoint, protected) when is_binary(endpoint) do
    case URI.parse(endpoint).query do
      nil ->
        :ok

      query when byte_size(query) <= 1_000_000 ->
        Enum.reduce_while(
          URI.query_decoder(query),
          MapSet.new(),
          &endpoint_query_pair(&1, &2, protected)
        )
        |> endpoint_query_result()

      _oversized ->
        {:error, :invalid_endpoint_query}
    end
  rescue
    _error -> {:error, :invalid_endpoint_query}
  end

  def validate_endpoint_query(_invalid, _protected), do: {:error, :invalid_endpoint_query}

  defp endpoint_query_pair({key, _value}, seen, protected) do
    root = ProtocolParams.root(key)

    if root in protected or MapSet.member?(seen, root),
      do: {:halt, {:error, :invalid_endpoint_query}},
      else: {:cont, MapSet.put(seen, root)}
  end

  defp endpoint_query_result(%MapSet{}), do: :ok
  defp endpoint_query_result(error), do: error

  @spec post_form(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def post_form(endpoint, form, opts) when is_map(form) and is_list(opts) do
    with :ok <- validate_endpoint_query(endpoint, ProtocolParams.protected()),
         {:ok, response_mode} <- form_response_mode(opts) do
      run_screened(endpoint, opts, fn target, prepared_opts, timeout_ms ->
        request(target, endpoint, form, timeout_ms, response_mode, prepared_opts)
      end)
    end
  end

  defp form_response_mode(opts) do
    case Keyword.get(opts, :expected_status) do
      nil -> {:ok, :json}
      status when is_integer(status) and status in 200..299 -> {:ok, {:json, status}}
      _invalid -> {:error, :invalid_expected_status}
    end
  end

  @spec post_form_unit(String.t(), map(), keyword()) :: :ok | {:error, term()}
  def post_form_unit(endpoint, form, opts) when is_map(form) and is_list(opts) do
    with :ok <- validate_endpoint_query(endpoint, ProtocolParams.protected()) do
      run_screened(endpoint, opts, fn target, prepared_opts, timeout_ms ->
        request(target, endpoint, form, timeout_ms, :unit, prepared_opts)
      end)
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
  `:alg`, `:kid`, and `:now` configure each freshly minted DPoP proof.
  """
  @spec post_json(String.t(), map(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def post_json(endpoint, body, access_token, opts)
      when is_map(body) and is_binary(access_token) and access_token != "" and is_list(opts) do
    run_screened(endpoint, opts, fn target, prepared_opts, timeout_ms ->
      json_request(
        target,
        endpoint,
        body,
        access_token,
        prepared_opts,
        timeout_ms,
        &classify_json/1
      )
    end)
  end

  # Credential and deferred endpoints can exchange either JSON or compact JWE.
  # Retain the status and headers so the wallet can validate media types and
  # distinguish immediate issuance from a deferred response before verification.
  @spec post_credential(String.t(), {:json, map()} | {:jwt, String.t()}, String.t(), keyword()) ::
          {:ok, %{status: integer(), headers: map(), body: term()}} | {:error, term()}
  def post_credential(endpoint, payload, access_token, opts)
      when is_binary(access_token) and access_token != "" and is_list(opts) do
    with {:ok, body_options} <- credential_body_options(payload) do
      run_screened(endpoint, opts, fn target, prepared_opts, timeout_ms ->
        credential_request(
          target,
          endpoint,
          body_options,
          access_token,
          prepared_opts,
          timeout_ms
        )
      end)
    end
  end

  defp credential_body_options({:json, body}) when is_map(body), do: {:ok, [json: body]}

  defp credential_body_options({:jwt, body}) when is_binary(body) and body != "",
    do: {:ok, [body: body, headers: [{"content-type", "application/jwt"}]]}

  defp credential_body_options(_payload), do: {:error, :invalid_credential_request}

  @doc """
  POST a JSON body authenticated with an access token, expecting a 2xx with no
  meaningful body (`:ok` on success). Used for the OID4VCI Notification Endpoint,
  which answers `204 No Content`. `:dpop` behaves as in `post_json/4`.
  """
  @spec post_json_unit(String.t(), map(), String.t(), keyword()) :: :ok | {:error, term()}
  def post_json_unit(endpoint, body, access_token, opts)
      when is_map(body) and is_binary(access_token) and access_token != "" and is_list(opts) do
    run_screened(endpoint, opts, fn target, prepared_opts, timeout_ms ->
      json_request(
        target,
        endpoint,
        body,
        access_token,
        prepared_opts,
        timeout_ms,
        &classify_json_unit/1
      )
    end)
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
    run_open_screened(url, opts, fn target, prepared_opts, timeout_ms ->
      options = accept_options(req_options(prepared_opts), "application/json")
      get_request(target, options, timeout_ms)
    end)
  end

  @doc """
  GET a raw text document, returning the response body unparsed.

  Used for by-reference fetches whose body is not JSON - an OID4VP
  `request_uri` serves a compact JWT (`application/oauth-authz-req+jwt`),
  not a JSON object (see `AttestoClient.Wallet.PresentationRequest.fetch/3`).
  """
  @spec get_text(String.t(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def get_text(url, opts) when is_binary(url) and is_list(opts) do
    run_open_screened(url, opts, fn target, prepared_opts, timeout_ms ->
      options = accept_options(req_options(prepared_opts), "application/oauth-authz-req+jwt")
      get_text_request(target, options, timeout_ms)
    end)
  end

  @doc """
  POST a form body with no OAuth client authentication, requiring HTTP 200,
  `application/json`, and a duplicate-free JSON object in the response.

  Used for a submission the OAuth client-authentication model does not
  cover - the OID4VP `direct_post` `response_uri`, which a wallet POSTs to
  unauthenticated (see `AttestoClient.Wallet.Presentation.submit/3`) - unlike
  `post_form/3`'s token-endpoint requests.
  """
  @spec post_form_open(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def post_form_open(endpoint, form, opts) when is_map(form) and is_list(opts) do
    run_open_screened(endpoint, opts, fn target, prepared_opts, timeout_ms ->
      open_request(target, form, req_options(prepared_opts), timeout_ms)
    end)
  end

  @doc """
  POST an unauthenticated form and return the raw response text. This is used
  by OID4VP `request_uri_method=post` to receive a signed request JWT.
  Endpoint screening, response limits and the overall deadline also apply.
  """
  @spec post_text_open(String.t(), map(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def post_text_open(endpoint, form, opts) when is_map(form) and is_list(opts) do
    run_open_screened(endpoint, opts, fn target, prepared_opts, timeout_ms ->
      options = accept_options(req_options(prepared_opts), "application/oauth-authz-req+jwt")
      open_request(target, form, options, timeout_ms, :text)
    end)
  end

  @spec post_challenge(String.t(), keyword()) :: {:ok, Req.Response.t()} | {:error, term()}
  def post_challenge(endpoint, opts) when is_list(opts) do
    run_screened(endpoint, opts, fn target, prepared_opts, timeout_ms ->
      options =
        prepared_opts
        |> req_options()
        |> accept_options("application/json")
        |> Keyword.merge(
          url: target.url,
          method: :post,
          body: "",
          redirect: false,
          retry: false,
          receive_timeout: timeout_ms,
          compressed: false,
          raw: true,
          into: PinnedRequest.bounded_response_into(16_384)
        )

      case run_req(options) do
        {:ok, %Req.Response{} = response} -> {:ok, response}
        {:error, :response_too_large} = error -> error
        {:error, _reason} -> {:error, :transport_error}
      end
    end)
  end

  defp accept_options(options, media_type) do
    headers =
      options
      |> Keyword.get(:headers, [])
      |> Enum.reject(fn
        {name, _value} -> name |> to_string() |> String.downcase() == "accept"
        _malformed -> false
      end)

    Keyword.put(options, :headers, [{"accept", media_type} | headers])
  end

  # By-reference endpoints are untrusted until their document is verified.
  # Only explicit in-process test transport, connection timeout and public CA
  # trust inputs may cross this boundary. In particular, no caller headers,
  # cookies, authentication, TLS client identity, plugins or nested routing
  # options reach either DNS screening or the request pipeline.
  defp run_open_screened(endpoint, opts, operation) do
    with {:ok, open_opts} <- open_options(opts) do
      run_screened(endpoint, open_opts, operation)
    end
  end

  defp open_options(opts) do
    with true <- PinnedRequest.unique_keyword?(opts),
         options = req_options(opts),
         :ok <- PinnedRequest.validate_options(options),
         connect = Keyword.get(options, :connect_options, []),
         transport = Keyword.get(connect, :transport_opts, []),
         :ok <- open_routing(options, connect) do
      safe_connect =
        connect
        |> Keyword.take([:timeout])
        |> Keyword.put(:transport_opts, Keyword.take(transport, [:cacerts, :cacertfile]))

      safe_options =
        options
        |> Keyword.take([:plug])
        |> Keyword.put(:connect_options, safe_connect)

      {:ok,
       opts |> Keyword.take([:timeout, :resolver]) |> Keyword.put(:req_options, safe_options)}
    else
      _unsafe -> {:error, :unsafe_transport_options}
    end
  end

  defp open_routing(options, connect) do
    in_process? = Keyword.get(options, :plug) not in [nil, false]
    routed? = Enum.any?([:adapter, :finch], &(Keyword.get(options, &1) not in [nil, false]))
    proxy? = Keyword.get(connect, :proxy) not in [nil, false]

    if Keyword.get(options, :unix_socket) not in [nil, false] or
         (not in_process? and (routed? or proxy?)) do
      {:error, :unsafe_transport_options}
    else
      :ok
    end
  end

  # The overall deadline includes DNS screening and request preparation, not
  # only the socket exchange. A slow or wedged resolver therefore cannot hold a
  # caller past the timeout promised by the higher-level flow.
  defp run_screened(endpoint, opts, operation) do
    with {:ok, timeout_ms} <- HTTPPolicy.timeout(opts),
         :ok <- initial_dpop_nonce(opts) do
      Deadline.run(
        fn -> execute_screened(endpoint, opts, timeout_ms, operation) end,
        timeout_ms
      )
    end
  end

  defp initial_dpop_nonce(opts) do
    case Keyword.get(opts, :dpop_nonce) do
      nil -> :ok
      nonce when is_binary(nonce) and byte_size(nonce) in 1..4_096 -> :ok
      _invalid -> {:error, :invalid_dpop_nonce}
    end
  end

  defp execute_screened(endpoint, opts, timeout_ms, operation) do
    with {:ok, target, prepared_opts} <- screen_request(endpoint, opts) do
      operation.(target, prepared_opts, timeout_ms)
    end
  end

  # Validate and resolve once, then retain the checked IP target for every
  # attempt belonging to this logical request. The original endpoint remains
  # separate because DPoP `htu` and private_key_jwt audiences name the external
  # URI, not the IP used for the socket.
  defp screen_request(endpoint, opts) when is_binary(endpoint) do
    if Attesto.URI.https_identifier?(endpoint) do
      with {:ok, request_opts} <- validate_req_options(opts),
           {:ok, screen_opts} <- screen_options(opts, request_opts),
           {:ok, target} <- AttestoClient.Discovery.screen_endpoint(endpoint, screen_opts),
           {:ok, prepared} <-
             PinnedRequest.prepare(target, request_opts, @reserved_headers, [:auth]) do
        {:ok, target, Keyword.put(opts, :req_options, prepared)}
      end
    else
      {:error, :invalid_endpoint}
    end
  end

  defp screen_request(_endpoint, _opts), do: {:error, :invalid_endpoint}

  defp screen_options(opts, request_opts) do
    screen_opts = [req_options: request_opts]

    case Keyword.fetch(opts, :resolver) do
      :error ->
        {:ok, screen_opts}

      {:ok, nil} ->
        {:ok, screen_opts}

      {:ok, resolver} when is_function(resolver, 2) ->
        {:ok, Keyword.put(screen_opts, :resolver, resolver)}

      {:ok, _invalid} ->
        {:error, :invalid_resolver}
    end
  end

  defp request(target, endpoint, form, timeout_ms, response_mode, opts) do
    # Re-authenticate per attempt: a DPoP `use_dpop_nonce` retry must carry a
    # FRESH client_assertion / client-attestation PoP (unique `jti`), not a
    # replay of the first attempt's - the server rejects reused assertion jtis.
    builder = fn retry?, challenge ->
      # On a nonce retry, force fresh client-auth `jti`s even if the caller
      # pinned one, so the retried assertion/PoP cannot be a replay of the first.
      attempt_opts = ClientAuth.attempt_options(opts, retry?, challenge)

      with {:ok, form2, req_options} <- ClientAuth.authenticate(form, endpoint, attempt_opts) do
        {:ok,
         req_options ++
           [
             url: target.url,
             method: :post,
             form: form2,
             redirect: false,
             retry: false,
             receive_timeout: timeout_ms,
             compressed: false,
             raw: false,
             into: PinnedRequest.bounded_response_into(@max_response_bytes)
           ]}
      end
    end

    # A DPoP-bound token request carries no `ath` (there is no access token yet).
    run_with_dpop(
      dpop_context(opts, "POST", endpoint, nil),
      builder,
      &classify_form(&1, response_mode),
      attestation: ClientAuth.attestation?(opts),
      challenge_received: Keyword.get(opts, :attestation_challenge_received)
    )
  end

  defp classify_form(%Req.Response{status: status}, {:json, expected})
       when status in 200..299 and status != expected,
       do: {:error, {:unexpected_http_status, status}}

  defp classify_form(response, {:json, _expected}), do: classify_form(response, :json)

  defp classify_form(%Req.Response{status: status}, :unit) when status in 200..299, do: :ok

  defp classify_form(%Req.Response{status: status, body: body}, _mode)
       when status in 200..299 and is_map(body),
       do: {:ok, body}

  defp classify_form(%Req.Response{status: status, body: %{} = body}, _mode),
    do: {:error, {:oauth_error, status, Map.take(body, ["error", "error_description"])}}

  defp classify_form(%Req.Response{status: status}, _mode), do: {:error, {:http_status, status}}

  defp json_request(target, endpoint, body, access_token, opts, timeout_ms, classify) do
    dpop_ctx = dpop_context(opts, "POST", endpoint, access_token)

    builder = fn ->
      base =
        req_options(opts) ++
          [
            url: target.url,
            method: :post,
            json: body,
            redirect: false,
            retry: false,
            receive_timeout: timeout_ms,
            compressed: false,
            raw: false,
            into: PinnedRequest.bounded_response_into(@max_response_bytes)
          ]

      {:ok, put_token_auth(base, access_token, dpop_ctx)}
    end

    # The credential/resource request has no client_assertion, so the retry only
    # needs a fresh DPoP proof (minted per attempt below); the base is identical.
    run_with_dpop(dpop_ctx, fn _retry?, _challenge -> builder.() end, classify)
  end

  defp credential_request(target, endpoint, body_options, access_token, opts, timeout_ms) do
    context = dpop_context(opts, "POST", endpoint, access_token)

    builder = fn _retry?, _challenge ->
      base =
        credential_request_options(opts, body_options)
        |> Keyword.merge(
          url: target.url,
          method: :post,
          redirect: false,
          retry: false,
          receive_timeout: timeout_ms,
          compressed: false,
          raw: true,
          into: PinnedRequest.bounded_response_into(@max_response_bytes)
        )

      {:ok, put_token_auth(base, access_token, context)}
    end

    run_with_dpop(context, builder, &classify_credential/1)
  end

  defp credential_request_options(opts, body_options) do
    headers =
      Keyword.get(req_options(opts), :headers, []) ++ Keyword.get(body_options, :headers, [])

    opts
    |> req_options()
    |> Keyword.merge(body_options)
    |> Keyword.put(:headers, headers)
  end

  defp classify_credential(%Req.Response{} = response) do
    with {:ok, response} <- credential_response_body(response) do
      classify_credential_response(response)
    end
  end

  defp credential_response_body(%Req.Response{body: body} = response) when is_binary(body) do
    if jwt_response?(response) do
      {:ok, response}
    else
      with {:ok, decoded} <- CredentialJSON.decode(body) do
        {:ok, %{response | body: decoded}}
      end
    end
  end

  defp credential_response_body(_response), do: {:error, :invalid_credential_response}

  defp classify_credential_response(%Req.Response{status: status, body: body} = response) do
    cond do
      status in [200, 202] ->
        {:ok, %{status: status, headers: response.headers, body: body}}

      is_binary(body) and jwt_response?(response) ->
        {:ok, %{status: status, headers: response.headers, body: body}}

      true ->
        classify_json(response)
    end
  end

  defp jwt_response?(response) do
    case Req.Response.get_header(response, "content-type") do
      [type] ->
        type |> String.split(";") |> hd() |> String.trim() |> String.downcase() ==
          "application/jwt"

      _invalid ->
        false
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

    base
    |> Keyword.delete(:auth)
    |> Keyword.put(:headers, [{"authorization", "DPoP " <> access_token} | headers])
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

  # Each logical request permits one retry for each independent challenge.
  # Rebuild all proofs on every retry and retain both challenge values, so
  # sequential attestation / DPoP challenges cannot replay proofs or loop.
  defp run_with_dpop(ctx, builder, classify, options \\ []) do
    state = %{
      nonce: if(ctx, do: ctx.nonce),
      challenge: nil,
      retry?: false,
      dpop_retry?: not is_nil(ctx),
      attestation_retry?: Keyword.get(options, :attestation, false),
      challenge_received: Keyword.get(options, :challenge_received)
    }

    auth_attempt(ctx, builder, classify, state)
  end

  defp auth_attempt(ctx, builder, classify, state) do
    with {:ok, base} <- builder.(state.retry?, state.challenge),
         {:ok, headers} <- dpop_headers(ctx, state.nonce) do
      case send_request(base, headers) do
        {:ok, resp} -> handle_auth_response(resp, ctx, builder, classify, state)
        {:error, :response_too_large} = error -> error
        {:error, _reason} -> {:error, :transport_error}
      end
    end
  end

  defp dpop_headers(nil, _nonce), do: {:ok, []}

  defp dpop_headers(ctx, nonce) do
    with {:ok, proof} <- dpop_proof(ctx, nonce), do: {:ok, [{"dpop", proof}]}
  end

  defp handle_auth_response(resp, ctx, builder, classify, state) do
    challenge = Challenge.attestation(resp)
    notify_attestation_challenge(state.challenge_received, challenge)
    state = if challenge, do: %{state | challenge: challenge}, else: state

    cond do
      state.attestation_retry? and Challenge.attestation_error?(resp) and challenge != nil ->
        auth_attempt(ctx, builder, classify, %{state | retry?: true, attestation_retry?: false})

      state.dpop_retry? and Challenge.dpop_nonce_challenge?(resp) ->
        auth_attempt(ctx, builder, classify, %{
          state
          | nonce: Challenge.dpop_nonce(resp),
            retry?: true,
            dpop_retry?: false
        })

      true ->
        classify.(resp)
    end
  end

  defp notify_attestation_challenge(_callback, nil), do: :ok
  defp notify_attestation_challenge(nil, _challenge), do: :ok

  defp notify_attestation_challenge(callback, challenge) when is_function(callback, 1),
    do: callback.(challenge)

  defp dpop_proof(ctx, nonce) do
    proof_opts =
      ctx.proof_opts
      |> Keyword.put(:access_token, ctx.access_token)
      |> Keyword.put(:nonce, nonce)
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)

    case DPoP.proof(ctx.key, ctx.method, ctx.url, proof_opts) do
      {:ok, proof} -> {:ok, proof}
      {:error, reason} -> {:error, {:dpop, reason}}
    end
  end

  defp dpop_context(opts, method, url, access_token) do
    case Keyword.get(opts, :dpop) do
      nil ->
        nil

      key ->
        %{
          key: key,
          method: method,
          url: url,
          access_token: access_token,
          nonce: Keyword.get(opts, :dpop_nonce),
          proof_opts: Keyword.take(opts, [:alg, :kid, :now])
        }
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
    case Req.request(PinnedRequest.new(options)) do
      {:ok, %Req.Response{private: %{attesto_client_response_too_large: true}}} ->
        {:error, :response_too_large}

      {:ok, %Req.Response{body: body}}
      when is_binary(body) and
             byte_size(body) > @max_response_bytes ->
        {:error, :response_too_large}

      result ->
        result
    end
  rescue
    _error -> {:error, :transport_error}
  end

  # Cap by-reference fetches (a caller-supplied `credential_offer_uri` /
  # `request_uri`, i.e. attacker-influenceable): a hostile endpoint could
  # otherwise stream an unbounded body to exhaust memory. `raw: true` also skips
  # response decompression, so a small compressed body cannot inflate past the
  # cap either.
  defp get_request(target, req_options, timeout_ms) do
    case bounded_get(target, req_options, timeout_ms) do
      {:ok, %Req.Response{status: 200} = response} ->
        open_response_body(response, :json)

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_text_request(target, req_options, timeout_ms) do
    case bounded_get(target, req_options, timeout_ms) do
      {:ok, %Req.Response{status: 200} = response} -> open_response_body(response, :text)
      {:ok, %Req.Response{status: status}} -> {:error, {:http_status, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp bounded_get(target, req_options, timeout_ms) do
    options =
      req_options ++
        [
          url: target.url,
          method: :get,
          redirect: false,
          retry: false,
          receive_timeout: timeout_ms,
          compressed: false,
          raw: true,
          into: PinnedRequest.bounded_response_into(@max_response_bytes)
        ]

    case run_req(options) do
      {:ok, %Req.Response{} = response} -> {:ok, response}
      {:error, :response_too_large} = error -> error
      {:error, _reason} -> {:error, :transport_error}
    end
  rescue
    _error -> {:error, :transport_error}
  end

  defp open_request(target, form, req_options, timeout_ms, response_mode \\ :json) do
    options =
      req_options ++
        [
          url: target.url,
          method: :post,
          form: form,
          redirect: false,
          retry: false,
          receive_timeout: timeout_ms,
          compressed: false,
          raw: true,
          into: PinnedRequest.bounded_response_into(@max_response_bytes)
        ]

    case run_req(options) do
      {:ok, %Req.Response{status: 200} = response} ->
        open_response_body(response, response_mode)

      {:ok, %Req.Response{} = response} ->
        open_error_response(response)

      {:error, :response_too_large} = error ->
        error

      {:error, _reason} ->
        {:error, :transport_error}
    end
  rescue
    _error -> {:error, :transport_error}
  end

  defp open_response_body(%Req.Response{body: body} = response, :text) do
    with :ok <- response_media_type(response, "application/oauth-authz-req+jwt"),
         true <- is_binary(body) do
      {:ok, body}
    else
      false -> {:error, :invalid_text_response}
      {:error, _reason} = error -> error
    end
  end

  defp open_response_body(%Req.Response{body: body} = response, :json) do
    with :ok <- response_media_type(response, "application/json"),
         {:ok, decoded} <- CredentialJSON.decode(body) do
      {:ok, decoded}
    else
      {:error, :invalid_credential_response} -> {:error, :invalid_json}
      {:error, _reason} = error -> error
    end
  end

  defp open_error_response(%Req.Response{status: status} = response) do
    case open_response_body(response, :json) do
      {:ok, %{"error" => _error} = body} when status not in 200..299 ->
        {:error, {:oauth_error, status, Map.take(body, ["error", "error_description"])}}

      _other ->
        {:error, {:http_status, status}}
    end
  end

  defp response_media_type(response, expected) do
    case Req.Response.get_header(response, "content-type") do
      [value] when is_binary(value) ->
        media_type =
          value |> String.split(";", parts: 2) |> hd() |> String.trim() |> String.downcase()

        if media_type == expected, do: :ok, else: {:error, :invalid_response_content_type}

      _invalid ->
        {:error, :invalid_response_content_type}
    end
  end

  defp validate_req_options(opts) do
    case Keyword.get(opts, :req_options, []) do
      request_opts when is_list(request_opts) ->
        with :ok <- PinnedRequest.validate_options(request_opts), do: {:ok, request_opts}

      _invalid ->
        {:error, :unsafe_transport_options}
    end
  end

  defp req_options(opts), do: Keyword.get(opts, :req_options, [])
end
