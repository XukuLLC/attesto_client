defmodule AttestoClient.DynamicClientRegistration do
  @moduledoc """
  Minimal RFC 7591 Dynamic Client Registration client.

  `register/3` sends caller-supplied client metadata to a registration endpoint
  and returns the validated registration response. It deliberately does not
  decide when dynamic registration is appropriate, choose client metadata, or
  persist the resulting credentials; those are application or protocol-profile
  policy decisions.

  The endpoint is subject to the same outbound screening, DNS pinning,
  deadline, redirect refusal, response-size limit, JSON media-type check, and
  duplicate-member rejection as the package's other OAuth HTTP operations.
  RFC 7591 requires HTTP 201 for a successful registration.
  """

  alias AttestoClient.OAuthHTTP
  alias AttestoClient.Outbound

  @type error :: :invalid_client_metadata | :invalid_registration_response | term()

  @doc """
  Register `client_metadata` at `endpoint`.

  Metadata keys must be non-empty strings. Transport options are the standard
  AttestoClient outbound options accepted by OAuth endpoint requests. When the
  endpoint came from authorization-server metadata, pass that server's exact
  `:issuer`; this binds any loopback development exception to the issuer rather
  than to the endpoint it advertised.
  """
  @spec register(String.t(), map(), keyword()) :: {:ok, map()} | {:error, error()}
  def register(endpoint, client_metadata, opts \\ [])

  def register(endpoint, client_metadata, opts)
      when is_binary(endpoint) and is_map(client_metadata) and is_list(opts) do
    with :ok <- Outbound.validate(opts),
         :ok <- Outbound.check_issuer(Keyword.get(opts, :issuer, endpoint), opts),
         :ok <- validate_client_metadata(client_metadata),
         {:ok, response} <-
           OAuthHTTP.post_json_open(
             endpoint,
             client_metadata,
             Keyword.put(opts, :expected_status, 201)
           ),
         :ok <- validate_response(response) do
      {:ok, response}
    end
  end

  def register(_endpoint, _client_metadata, _opts), do: {:error, :invalid_client_metadata}

  defp validate_client_metadata(metadata) when map_size(metadata) > 0 do
    if Enum.all?(metadata, fn {key, _value} ->
         is_binary(key) and key != "" and String.valid?(key)
       end),
       do: :ok,
       else: {:error, :invalid_client_metadata}
  end

  defp validate_client_metadata(_metadata), do: {:error, :invalid_client_metadata}

  defp validate_response(%{"client_id" => client_id} = response)
       when is_binary(client_id) and client_id != "" do
    checks = [
      optional_non_empty(response, "client_secret"),
      optional_non_empty(response, "registration_access_token"),
      optional_non_empty(response, "registration_client_uri"),
      optional_non_empty(response, "token_endpoint_auth_method"),
      optional_non_negative_integer(response, "client_id_issued_at"),
      optional_non_negative_integer(response, "client_secret_expires_at")
    ]

    if String.valid?(client_id) and Enum.all?(checks, &(&1 == :ok)),
      do: :ok,
      else: {:error, :invalid_registration_response}
  end

  defp validate_response(_response), do: {:error, :invalid_registration_response}

  defp optional_non_empty(response, key) do
    case Map.fetch(response, key) do
      :error -> :ok
      {:ok, value} when is_binary(value) and value != "" -> :ok
      _invalid -> :error
    end
  end

  defp optional_non_negative_integer(response, key) do
    case Map.fetch(response, key) do
      :error -> :ok
      {:ok, value} when is_integer(value) and value >= 0 -> :ok
      _invalid -> :error
    end
  end
end
