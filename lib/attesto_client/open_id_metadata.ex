defmodule AttestoClient.OpenIDMetadata do
  @moduledoc false

  alias AttestoClient.Discovery
  alias AttestoClient.OAuthHTTP
  alias AttestoClient.ProtocolParams

  @required_string_fields ~w(authorization_endpoint token_endpoint jwks_uri)

  @spec resolve(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def resolve(issuer, opts) do
    with :ok <- Discovery.validate_issuer_identifier(issuer, opts),
         {:ok, metadata} <- fetch_or_use(issuer, opts),
         :ok <- validate_document(metadata, issuer, Keyword.get(opts, :protocol, :oidc), opts) do
      {:ok, metadata}
    end
  end

  @doc false
  # The one document check behind `resolve/2`, and so behind
  # `AttestoClient.AuthorizationCode.start/2`, `AttestoClient.Logout.url/1`,
  # `AttestoClient.Discovery.validate_metadata/3` and an
  # `AttestoClient.Issuer` started with `:protocol`. It depends on the document
  # and the expected issuer, and on no client option except `:outbound`, which
  # decides whether a loopback `http` endpoint is acceptable. `opts` must
  # already have passed `AttestoClient.Outbound.validate/1`.
  @spec validate_document(term(), String.t(), :oidc | :oauth, keyword()) ::
          :ok | {:error, :invalid_metadata | :issuer_mismatch | term()}
  def validate_document(metadata, issuer, protocol, opts \\ []) do
    with :ok <- validate_protocol(metadata, issuer, protocol, opts) do
      validate_endpoint_queries(metadata)
    end
  end

  @spec validate(map(), String.t()) ::
          :ok | {:error, :invalid_metadata | :issuer_mismatch | term()}
  def validate(%{"issuer" => issuer} = metadata, issuer) do
    validate_oidc(metadata, [])
  end

  def validate(%{"issuer" => _other}, _issuer), do: {:error, :issuer_mismatch}
  def validate(_metadata, _issuer), do: {:error, :invalid_metadata}

  defp validate_oidc(metadata, opts) do
    with :ok <- validate_required_strings(metadata),
         :ok <- validate_endpoints(metadata, opts),
         :ok <- validate_string_list(metadata, "response_types_supported", "code"),
         :ok <- validate_string_list(metadata, "subject_types_supported"),
         :ok <- validate_string_list(metadata, "id_token_signing_alg_values_supported") do
      validate_pkce(metadata)
    end
  end

  defp validate_protocol(%{"issuer" => issuer} = metadata, issuer, :oidc, opts),
    do: validate_oidc(metadata, opts)

  defp validate_protocol(metadata, issuer, :oidc, _opts), do: validate(metadata, issuer)

  defp validate_protocol(%{"issuer" => issuer} = metadata, issuer, :oauth, opts) do
    with true <-
           Enum.all?(
             ~w(authorization_endpoint token_endpoint),
             &non_empty_string?(Map.get(metadata, &1))
           ),
         :ok <- validate_endpoints(metadata, opts),
         :ok <- optional_string_list(metadata, "response_types_supported", "code"),
         :ok <- optional_string_list(metadata, "grant_types_supported", "authorization_code"),
         :ok <- validate_pkce(metadata) do
      :ok
    else
      false -> {:error, :invalid_metadata}
      {:error, _reason} = error -> error
    end
  end

  defp validate_protocol(%{"issuer" => _other}, _issuer, :oauth, _opts),
    do: {:error, :issuer_mismatch}

  defp validate_protocol(_metadata, _issuer, _protocol, _opts), do: {:error, :invalid_metadata}

  # A request endpoint whose own query already carries a protocol parameter
  # would let the document override one this client sends.
  defp validate_endpoint_queries(metadata) do
    Enum.reduce_while(
      ~w(authorization_endpoint pushed_authorization_request_endpoint token_endpoint),
      :ok,
      fn name, :ok ->
        case validate_endpoint_query(metadata[name]) do
          :ok -> {:cont, :ok}
          error -> {:halt, error}
        end
      end
    )
  end

  defp validate_endpoint_query(nil), do: :ok

  defp validate_endpoint_query(endpoint),
    do: OAuthHTTP.validate_endpoint_query(endpoint, ProtocolParams.protected())

  defp optional_string_list(metadata, field, required) do
    if Map.has_key?(metadata, field),
      do: validate_string_list(metadata, field, required),
      else: :ok
  end

  defp fetch_or_use(issuer, opts) do
    case Keyword.fetch(opts, :metadata) do
      {:ok, %{} = metadata} ->
        {:ok, metadata}

      {:ok, _invalid} ->
        {:error, :invalid_metadata}

      :error ->
        fetch(issuer, opts)
    end
  end

  # With `issuer: {AttestoClient.Issuer, name}` the metadata comes from that
  # cache (`AttestoClient.Issuer.expand_option/1` recorded it); otherwise it is
  # fetched for this call.
  defp fetch(issuer, opts) do
    case Keyword.get(opts, :issuer_cache) do
      nil ->
        Discovery.fetch(
          issuer,
          Keyword.take(opts, [
            :well_known,
            :req_options,
            :resolver,
            :outbound,
            :max_response_bytes,
            :timeout
          ])
          |> Keyword.put_new(
            :well_known,
            if(Keyword.get(opts, :protocol) == :oauth,
              do: :oauth_authorization_server,
              else: :openid_configuration
            )
          )
        )

      server ->
        AttestoClient.Issuer.metadata(server)
    end
  end

  defp validate_required_strings(metadata) do
    if Enum.all?(@required_string_fields, &non_empty_string?(Map.get(metadata, &1))),
      do: :ok,
      else: {:error, :invalid_metadata}
  end

  defp validate_endpoints(metadata, opts) do
    fields = ~w(
      authorization_endpoint
      end_session_endpoint
      token_endpoint
      jwks_uri
      revocation_endpoint
      pushed_authorization_request_endpoint
    )

    Enum.reduce_while(fields, :ok, fn field, :ok ->
      case Map.fetch(metadata, field) do
        :error ->
          {:cont, :ok}

        {:ok, endpoint} ->
          endpoint_validation_result(Discovery.validate_browser_endpoint(endpoint, opts))
      end
    end)
  end

  defp endpoint_validation_result(result) do
    case result do
      :ok -> {:cont, :ok}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp validate_string_list(metadata, field, required \\ nil) do
    case Map.get(metadata, field) do
      values when is_list(values) and values != [] ->
        valid? = Enum.all?(values, &non_empty_string?/1)
        required? = is_nil(required) or required in values
        if valid? and required?, do: :ok, else: {:error, :invalid_metadata}

      _invalid ->
        {:error, :invalid_metadata}
    end
  end

  defp validate_pkce(metadata) do
    case Map.fetch(metadata, "code_challenge_methods_supported") do
      :error ->
        :ok

      {:ok, methods} when is_list(methods) ->
        if Enum.all?(methods, &non_empty_string?/1) and "S256" in methods,
          do: :ok,
          else: {:error, :invalid_metadata}

      {:ok, _invalid} ->
        {:error, :invalid_metadata}
    end
  end

  defp non_empty_string?(value), do: is_binary(value) and value != ""
end
