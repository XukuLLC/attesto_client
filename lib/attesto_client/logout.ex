defmodule AttestoClient.Logout do
  @moduledoc """
  Build an OpenID Connect RP-Initiated Logout request.

  The returned URL directs the user agent to the provider's discovered
  `end_session_endpoint`. This module constructs the standards-based request;
  it does not destroy an application session. The caller owns logout-state
  correlation and decides when local session termination is appropriate.
  """

  alias AttestoClient.OpenIDMetadata

  @doc """
  Build an RP-Initiated Logout URL.

  Required options: `:issuer` and either `:id_token_hint` or `:logout_hint`.
  Discovery is fetched unless `:metadata` is supplied. Optional parameters are
  `:client_id`, `:post_logout_redirect_uri`, `:state`, and `:ui_locales`.
  """
  @spec url(keyword()) :: {:ok, String.t()} | {:error, term()}
  def url(opts) when is_list(opts) do
    with {:ok, issuer} <- required_string(opts, :issuer),
         {:ok, metadata} <- OpenIDMetadata.resolve(issuer, opts),
         {:ok, endpoint} <- end_session_endpoint(metadata),
         {:ok, params} <- logout_params(opts) do
      uri = URI.parse(endpoint)
      existing = if uri.query, do: URI.decode_query(uri.query), else: %{}
      {:ok, %{uri | query: URI.encode_query(Map.merge(existing, params))} |> URI.to_string()}
    end
  end

  def url(_opts), do: {:error, :invalid_options}

  defp logout_params(opts) do
    keys = [
      :id_token_hint,
      :logout_hint,
      :client_id,
      :post_logout_redirect_uri,
      :state,
      :ui_locales
    ]

    params =
      Enum.reduce(keys, %{}, fn key, acc ->
        case Keyword.get(opts, key) do
          value when is_binary(value) and value != "" -> Map.put(acc, Atom.to_string(key), value)
          _other -> acc
        end
      end)

    if Map.has_key?(params, "id_token_hint") or Map.has_key?(params, "logout_hint"),
      do: {:ok, params},
      else: {:error, :missing_logout_hint}
  end

  defp end_session_endpoint(%{"end_session_endpoint" => endpoint})
       when is_binary(endpoint) and endpoint != "",
       do: {:ok, endpoint}

  defp end_session_endpoint(_metadata), do: {:error, :missing_end_session_endpoint}

  defp required_string(opts, key) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, missing_error(key)}
    end
  end

  defp missing_error(:issuer), do: :missing_issuer
end
