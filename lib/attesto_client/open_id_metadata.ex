defmodule AttestoClient.OpenIDMetadata do
  @moduledoc false

  alias AttestoClient.Discovery

  @required_string_fields ~w(authorization_endpoint token_endpoint jwks_uri)

  @spec resolve(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def resolve(issuer, opts) do
    with :ok <- Discovery.validate_issuer_identifier(issuer),
         {:ok, metadata} <- fetch_or_use(issuer, opts),
         :ok <- validate(metadata, issuer) do
      {:ok, metadata}
    end
  end

  @spec validate(map(), String.t()) ::
          :ok | {:error, :invalid_metadata | :issuer_mismatch | term()}
  def validate(%{"issuer" => issuer} = metadata, issuer) do
    with :ok <- validate_required_strings(metadata),
         :ok <- validate_endpoints(metadata),
         :ok <- validate_string_list(metadata, "response_types_supported", "code"),
         :ok <- validate_string_list(metadata, "subject_types_supported"),
         :ok <- validate_string_list(metadata, "id_token_signing_alg_values_supported", "RS256") do
      validate_pkce(metadata)
    end
  end

  def validate(%{"issuer" => _other}, _issuer), do: {:error, :issuer_mismatch}
  def validate(_metadata, _issuer), do: {:error, :invalid_metadata}

  defp fetch_or_use(issuer, opts) do
    case Keyword.fetch(opts, :metadata) do
      {:ok, %{} = metadata} -> {:ok, metadata}
      {:ok, _invalid} -> {:error, :invalid_metadata}
      :error -> Discovery.fetch(issuer, Keyword.take(opts, [:well_known, :req_options]))
    end
  end

  defp validate_required_strings(metadata) do
    if Enum.all?(@required_string_fields, &non_empty_string?(Map.get(metadata, &1))),
      do: :ok,
      else: {:error, :invalid_metadata}
  end

  defp validate_endpoints(metadata) do
    fields = @required_string_fields ++ ~w(revocation_endpoint end_session_endpoint)

    Enum.reduce_while(fields, :ok, fn field, :ok ->
      case Map.fetch(metadata, field) do
        :error ->
          {:cont, :ok}

        {:ok, endpoint} ->
          endpoint_validation_step(endpoint)
      end
    end)
  end

  defp endpoint_validation_step(endpoint) do
    case Discovery.validate_endpoint(endpoint) do
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
