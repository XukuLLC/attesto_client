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

    alias Attesto.Plug.Authenticate, as: AttestoAuthenticate
    alias AttestoClient.ResourceServer

    @default_claims_key :attesto_claims
    @policy_keys [
      :required_scopes,
      :allowed_subjects,
      :allowed_client_ids,
      :max_token_age_seconds,
      :max_token_lifetime_seconds,
      :now
    ]

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

      AttestoAuthenticate.init(core_opts(opts))
    end

    @impl Elixir.Plug
    def call(conn, opts) do
      AttestoAuthenticate.call(conn, ensure_core_opts(opts))
    end

    @doc false
    def verify_token(server, token, verify_opts, policy_opts) do
      ResourceServer.verify(
        server,
        token,
        Keyword.merge(policy_opts, Keyword.take(verify_opts, [:dpop_jkt, :mtls_cert_thumbprint]))
      )
    end

    defp ensure_core_opts(opts) do
      if Keyword.has_key?(opts, :verify), do: opts, else: init(opts)
    end

    defp core_opts(opts) do
      policy =
        opts
        |> Keyword.take(@policy_keys)
        |> Keyword.put_new(:required_scopes, [])

      opts
      |> Keyword.drop([
        :server,
        :dpop_replay_unprotected_acknowledged?,
        :allow_http | @policy_keys
      ])
      |> Keyword.merge(
        config: Keyword.fetch!(opts, :server),
        verify: {__MODULE__, :verify_token, [policy]},
        required_scopes: Keyword.get(opts, :required_scopes, []),
        claims_key: Keyword.get(opts, :claims_key, @default_claims_key),
        bearer_methods: [:header],
        dpop_replay_unprotected_acknowledged?: false,
        allow_ambient_mtls: true,
        missing_credentials_challenge: :bare_bearer,
        include_error_description: false,
        now: Keyword.get(opts, :now)
      )
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
  end
end
