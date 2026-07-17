if Code.ensure_loaded?(Plug.Conn) do
  defmodule AttestoClient.ResourceServer.Plug do
    @moduledoc """
    Authenticate a Plug request with `AttestoClient.ResourceServer`.

    The plug accepts RFC 6750 Bearer presentation and RFC 9449 DPoP
    presentation, verifies any DPoP proof (including replay and optional nonce
    checks), computes an optional mTLS certificate thumbprint, verifies the
    remote issuer's access token, enforces configured scopes, and assigns the
    claims to the connection.

        plug AttestoClient.ResourceServer.Plug,
          server: MyApp.RemoteIssuer,
          required_scopes: ["documents.read"],
          replay_check: &MyApp.DPoPReplay.check_and_record/2,
          resource_metadata: "https://api.example/.well-known/oauth-protected-resource"

    ## Options

      * `:server` (required) - a `AttestoClient.ResourceServer` server or a
        zero-arity function returning one.
      * `:required_scopes` - exact OAuth scope tokens required by this route.
      * `:allowed_subjects` / `:allowed_client_ids` - optional exact
        token-acceptance allowlists for this route.
      * `:max_token_age_seconds` / `:max_token_lifetime_seconds` - optional
        token-age policy forwarded to the verifier.
      * `:claims_key` - the `conn.assigns` key (default `:attesto_claims`).
      * `:replay_check` - required for every DPoP request.
      * `:nonce_check` / `:nonce_issue` - RFC 9449 server nonce callbacks.
      * `:dpop_max_age_seconds` - maximum DPoP proof age passed to Attesto.
      * `:cert_der` - callback returning the authenticated client certificate's
        DER bytes or `nil`; the TLS terminator remains responsible for trust.
      * `:htu` - callback returning the externally visible request URI without
        query or fragment.
      * `:resource_metadata`, `:send_error`, `:www_authenticate`, `:no_store` -
        forwarded to Attesto's OAuth error transport.

    DPoP-bound and mTLS-bound tokens fail closed when the matching current
    request evidence is absent. Query-string and form-body access tokens are
    intentionally not accepted.
    """

    @behaviour Elixir.Plug

    import Elixir.Plug.Conn

    alias Attesto.DPoP
    alias Attesto.MTLS
    alias Attesto.Plug.OAuthError
    alias AttestoClient.ResourceServer

    @default_claims_key :attesto_claims
    @transport_keys [:resource_metadata, :send_error, :www_authenticate, :no_store]

    @impl Elixir.Plug
    def init(opts) when is_list(opts) do
      unless Keyword.has_key?(opts, :server) do
        raise ArgumentError, "AttestoClient.ResourceServer.Plug requires :server"
      end

      scopes = Keyword.get(opts, :required_scopes, [])

      unless is_list(scopes) and Enum.all?(scopes, &Attesto.Scope.valid_token?/1) do
        raise ArgumentError,
              "AttestoClient.ResourceServer.Plug: :required_scopes must contain valid OAuth scope tokens"
      end

      validate_optional_callback!(opts, :htu, 1)
      validate_optional_callback!(opts, :nonce_issue, 0)
      validate_optional_callback!(opts, :nonce_check, 1)
      validate_optional_callback!(opts, :cert_der, 1)
      validate_optional_callback!(opts, :replay_check, 2)
      validate_server!(Keyword.fetch!(opts, :server))
      validate_positive_integer!(opts, :dpop_max_age_seconds)
      validate_optional_string_list!(opts, :allowed_subjects)
      validate_optional_string_list!(opts, :allowed_client_ids)
      validate_non_negative_integer!(opts, :max_token_age_seconds)
      validate_positive_integer!(opts, :max_token_lifetime_seconds)

      if Keyword.get(opts, :nonce_check) != nil and Keyword.get(opts, :nonce_issue) == nil do
        raise ArgumentError,
              "AttestoClient.ResourceServer.Plug: :nonce_check requires :nonce_issue"
      end

      opts
    end

    @impl Elixir.Plug
    def call(conn, opts) do
      with {:ok, scheme, token} <- authorization(conn),
           {:ok, dpop_jkt} <- verify_dpop(conn, scheme, token, opts),
           {:ok, mtls_thumbprint} <- certificate_thumbprint(conn, opts),
           {:ok, claims} <-
             ResourceServer.verify(resolve_server(opts), token,
               required_scopes: Keyword.get(opts, :required_scopes, []),
               allowed_subjects: Keyword.get(opts, :allowed_subjects),
               allowed_client_ids: Keyword.get(opts, :allowed_client_ids),
               max_token_age_seconds: Keyword.get(opts, :max_token_age_seconds),
               max_token_lifetime_seconds: Keyword.get(opts, :max_token_lifetime_seconds),
               dpop_jkt: dpop_jkt,
               mtls_cert_thumbprint: mtls_thumbprint,
               now: Keyword.get(opts, :now)
             ) do
        assign(conn, Keyword.get(opts, :claims_key, @default_claims_key), claims)
      else
        :missing ->
          missing_credentials(conn, opts)

        :malformed ->
          OAuthError.unauthorized(
            conn,
            :bearer,
            "invalid_token",
            error_opts(opts, description: "malformed Authorization header")
          )

        {:dpop_error, :use_dpop_nonce} ->
          dpop_nonce_challenge(conn, opts)

        {:dpop_error, _reason} ->
          OAuthError.unauthorized(
            conn,
            :dpop,
            "invalid_dpop_proof",
            error_opts(opts)
          )

        {:certificate_error, _reason} ->
          OAuthError.unauthorized(
            conn,
            :bearer,
            "invalid_token",
            error_opts(opts)
          )

        {:error, {:jwks_refresh_failed, _reason}} ->
          service_unavailable(conn, opts)

        {:error, :insufficient_scope} ->
          OAuthError.insufficient_scope(
            conn,
            Keyword.get(opts, :required_scopes, []),
            request_scheme(conn),
            error_opts(opts)
          )

        {:error, reason} ->
          OAuthError.unauthorized(
            conn,
            token_error_scheme(conn, reason),
            "invalid_token",
            error_opts(opts)
          )
      end
    end

    defp authorization(conn) do
      case get_req_header(conn, "authorization") do
        [value] -> parse_authorization(value)
        [] -> :missing
        _multiple -> :malformed
      end
    end

    defp parse_authorization(value) do
      case String.split(value, " ", parts: 2) do
        [raw_scheme, raw_token] ->
          token = String.trim(raw_token)

          case {String.downcase(raw_scheme), token} do
            {_scheme, ""} -> :malformed
            {"bearer", token} -> {:ok, :bearer, token}
            {"dpop", token} -> {:ok, :dpop, token}
            _other -> :malformed
          end

        _other ->
          :malformed
      end
    end

    defp verify_dpop(conn, :bearer, _token, _opts) do
      case get_req_header(conn, "dpop") do
        [] -> {:ok, nil}
        _present -> {:dpop_error, :dpop_scheme_required}
      end
    end

    defp verify_dpop(conn, :dpop, token, opts) do
      case get_req_header(conn, "dpop") do
        [proof] -> verify_dpop_proof(conn, proof, token, opts)
        _other -> {:dpop_error, :missing_proof}
      end
    end

    defp verify_dpop_proof(conn, proof, token, opts) do
      if replay_protected?(opts) do
        case htu(conn, opts) do
          {:ok, http_uri} -> verify_dpop_signature(conn, proof, token, http_uri, opts)
          {:error, reason} -> {:dpop_error, reason}
        end
      else
        {:dpop_error, :replay_check_unconfigured}
      end
    end

    defp verify_dpop_signature(conn, proof, token, http_uri, opts) do
      verify_opts =
        [http_method: conn.method, http_uri: http_uri, access_token: token]
        |> put_if_present(:replay_check, Keyword.get(opts, :replay_check))
        |> put_if_present(:nonce_check, Keyword.get(opts, :nonce_check))
        |> put_if_present(:now, Keyword.get(opts, :now))
        |> put_if_present(:max_age_seconds, Keyword.get(opts, :dpop_max_age_seconds))

      case DPoP.verify_proof(proof, verify_opts) do
        {:ok, %{jkt: jkt}} -> {:ok, jkt}
        {:error, reason} -> {:dpop_error, reason}
      end
    end

    defp replay_protected?(opts) do
      is_function(Keyword.get(opts, :replay_check), 2)
    end

    defp certificate_thumbprint(conn, opts) do
      case Keyword.get(opts, :cert_der) do
        nil ->
          {:ok, nil}

        callback when is_function(callback, 1) ->
          case callback.(conn) do
            nil -> {:ok, nil}
            der when is_binary(der) -> wrap_thumbprint(MTLS.compute_thumbprint(der))
            _invalid -> {:certificate_error, :invalid_certificate}
          end

        _invalid ->
          {:certificate_error, :invalid_certificate_callback}
      end
    end

    defp wrap_thumbprint({:ok, thumbprint}), do: {:ok, thumbprint}
    defp wrap_thumbprint({:error, reason}), do: {:certificate_error, reason}

    defp resolve_server(opts) do
      case Keyword.fetch!(opts, :server) do
        callback when is_function(callback, 0) -> callback.()
        server -> server
      end
    end

    defp htu(conn, opts) do
      case Keyword.get(opts, :htu) do
        callback when is_function(callback, 1) ->
          case callback.(conn) do
            value when is_binary(value) and value != "" -> {:ok, value}
            _invalid -> {:error, :invalid_http_uri}
          end

        _other ->
          scheme = Atom.to_string(conn.scheme)

          {:ok,
           scheme <> "://" <> conn.host <> port_suffix(scheme, conn.port) <> conn.request_path}
      end
    end

    defp port_suffix("https", 443), do: ""
    defp port_suffix("http", 80), do: ""
    defp port_suffix(_scheme, port), do: ":" <> Integer.to_string(port)

    defp request_scheme(conn) do
      case get_req_header(conn, "authorization") do
        [value] ->
          if String.starts_with?(String.downcase(value), "dpop "), do: :dpop, else: :bearer

        _other ->
          :bearer
      end
    end

    defp token_error_scheme(_conn, :dpop_proof_required), do: :dpop
    defp token_error_scheme(conn, _reason), do: request_scheme(conn)

    defp issue_nonce(opts) do
      case Keyword.get(opts, :nonce_issue) do
        callback when is_function(callback, 0) ->
          case callback.() do
            nonce when is_binary(nonce) and nonce != "" -> {:ok, nonce}
            _invalid -> {:error, :invalid_nonce}
          end

        _other ->
          {:error, :invalid_nonce}
      end
    end

    defp dpop_nonce_challenge(conn, opts) do
      case issue_nonce(opts) do
        {:ok, nonce} ->
          OAuthError.unauthorized(
            conn,
            :dpop,
            "use_dpop_nonce",
            error_opts(opts, dpop_nonce: nonce)
          )

        {:error, _reason} ->
          OAuthError.unauthorized(
            conn,
            :dpop,
            "invalid_dpop_proof",
            error_opts(opts)
          )
      end
    end

    defp missing_credentials(conn, opts) do
      transport_opts = error_opts(opts)

      conn
      |> put_no_store(transport_opts)
      |> put_www_authenticate(bearer_challenge(opts), transport_opts)
      |> send_transport_response(401, %{}, transport_opts)
    end

    defp bearer_challenge(opts) do
      case Keyword.get(opts, :resource_metadata) do
        url when is_binary(url) ->
          if metadata_url?(url),
            do: ~s(Bearer resource_metadata="#{escape_challenge_value(url)}"),
            else: "Bearer"

        _other ->
          "Bearer"
      end
    end

    defp metadata_url?(url) do
      not Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, url) and
        match?(
          {:ok, %URI{scheme: "https", host: host, fragment: nil}}
          when is_binary(host) and host != "",
          URI.new(url)
        )
    end

    defp escape_challenge_value(value) do
      value
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")
    end

    defp service_unavailable(conn, opts) do
      transport_opts = error_opts(opts)

      conn
      |> put_no_store(transport_opts)
      |> send_service_unavailable(transport_opts)
    end

    defp send_service_unavailable(conn, opts) do
      send_transport_response(conn, 503, %{"error" => "temporarily_unavailable"}, opts)
    end

    defp send_transport_response(conn, status, body, opts) do
      case Keyword.get(opts, :send_error) do
        callback when is_function(callback, 3) ->
          callback.(conn, status, body)

        {module, function} when is_atom(module) and is_atom(function) ->
          apply(module, function, [conn, status, body])

        {module, function, extra}
        when is_atom(module) and is_atom(function) and is_list(extra) ->
          apply(module, function, [conn, status, body | extra])

        _other ->
          conn
          |> put_resp_content_type("application/json")
          |> send_resp(status, JSON.encode!(body))
          |> halt()
      end
    end

    defp put_www_authenticate(conn, challenge, opts) do
      case Keyword.get(opts, :www_authenticate) do
        callback when is_function(callback, 2) ->
          callback.(conn, challenge)

        {module, function} when is_atom(module) and is_atom(function) ->
          apply(module, function, [conn, challenge])

        {module, function, extra}
        when is_atom(module) and is_atom(function) and is_list(extra) ->
          apply(module, function, [conn, challenge | extra])

        _other ->
          put_resp_header(conn, "www-authenticate", challenge)
      end
    end

    defp put_no_store(conn, opts) do
      case Keyword.get(opts, :no_store) do
        callback when is_function(callback, 1) ->
          callback.(conn)

        {module, function} when is_atom(module) and is_atom(function) ->
          apply(module, function, [conn])

        {module, function, extra}
        when is_atom(module) and is_atom(function) and is_list(extra) ->
          apply(module, function, [conn | extra])

        _other ->
          conn
          |> put_resp_header("cache-control", "no-store")
          |> put_resp_header("pragma", "no-cache")
      end
    end

    defp validate_optional_callback!(opts, key, arity) do
      case Keyword.get(opts, key) do
        nil ->
          :ok

        callback when is_function(callback, arity) ->
          :ok

        _invalid ->
          raise ArgumentError,
                "AttestoClient.ResourceServer.Plug: #{inspect(key)} must be a #{arity}-arity function"
      end
    end

    defp validate_server!(server) when is_function(server, 0), do: :ok

    defp validate_server!(server) when is_function(server) do
      raise ArgumentError,
            "AttestoClient.ResourceServer.Plug: :server function must have arity 0"
    end

    defp validate_server!(_server), do: :ok

    defp validate_positive_integer!(opts, key) do
      case Keyword.get(opts, key) do
        nil ->
          :ok

        value when is_integer(value) and value > 0 ->
          :ok

        _invalid ->
          raise ArgumentError,
                "AttestoClient.ResourceServer.Plug: #{inspect(key)} must be a positive integer"
      end
    end

    defp validate_non_negative_integer!(opts, key) do
      case Keyword.get(opts, key) do
        nil ->
          :ok

        value when is_integer(value) and value >= 0 ->
          :ok

        _invalid ->
          raise ArgumentError,
                "AttestoClient.ResourceServer.Plug: #{inspect(key)} must be a non-negative integer"
      end
    end

    defp validate_optional_string_list!(opts, key) do
      case Keyword.get(opts, key) do
        nil ->
          :ok

        values when is_list(values) ->
          unless Enum.all?(values, &(is_binary(&1) and &1 != "")) do
            raise ArgumentError,
                  "AttestoClient.ResourceServer.Plug: #{inspect(key)} must contain non-empty strings"
          end

        _invalid ->
          raise ArgumentError,
                "AttestoClient.ResourceServer.Plug: #{inspect(key)} must be a list"
      end
    end

    defp put_if_present(opts, _key, nil), do: opts
    defp put_if_present(opts, key, value), do: Keyword.put(opts, key, value)

    defp error_opts(opts, extra \\ []) do
      opts
      |> Keyword.take(@transport_keys)
      |> Keyword.merge(extra)
    end
  end
end
