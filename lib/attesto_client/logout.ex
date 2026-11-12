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

  `:issuer` is required. Discovery is fetched unless `:metadata` is supplied.
  `:outbound` names deliberate exceptions to the HTTPS and public-address
  rules for the issuer and its endpoints (`AttestoClient.Outbound`).
  The request parameters are all optional, as in RP-Initiated Logout 1.0 §2:
  `:id_token_hint`, `:logout_hint`, `:client_id`, `:post_logout_redirect_uri`,
  `:state`, and `:ui_locales`.

  Send `:id_token_hint` when the ID Token is still at hand; the specification
  recommends it. Without one, the URL is the validated `end_session_endpoint`
  with whatever parameters were given, and the provider decides whether to ask
  the End-User to confirm (§2).

  `:post_logout_redirect_uri` without `:id_token_hint` requires `:client_id`:
  the provider validates the redirect against a client's registration, and
  with no ID Token the `client_id` parameter is the only thing that names the
  client (§2, §3). That combination without `:client_id` returns
  `{:error, :missing_client_id}`.
  """
  @spec url(keyword()) :: {:ok, String.t()} | {:error, term()}
  def url(opts) when is_list(opts) do
    with {:ok, issuer} <- required_string(opts, :issuer),
         {:ok, metadata} <- OpenIDMetadata.resolve(issuer, opts),
         {:ok, endpoint} <- end_session_endpoint(metadata),
         {:ok, params} <- logout_params(opts) do
      uri = URI.parse(endpoint)
      existing = if uri.query, do: URI.decode_query(uri.query), else: %{}
      {:ok, %{uri | query: query(Map.merge(existing, params))} |> URI.to_string()}
    end
  end

  def url(_opts), do: {:error, :invalid_options}

  # No parameters means no query, not a trailing "?".
  defp query(params) when map_size(params) == 0, do: nil
  defp query(params), do: URI.encode_query(params)

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

    if redirect_client_unidentified?(params),
      do: {:error, :missing_client_id},
      else: {:ok, params}
  end

  defp redirect_client_unidentified?(params) do
    Map.has_key?(params, "post_logout_redirect_uri") and
      not Map.has_key?(params, "id_token_hint") and not Map.has_key?(params, "client_id")
  end

  defp end_session_endpoint(%{"end_session_endpoint" => endpoint})
       when is_binary(endpoint) and endpoint != "",
       do: {:ok, endpoint}

  defp end_session_endpoint(_metadata), do: {:error, :missing_end_session_endpoint}

  defp required_string(opts, key) do
    AttestoClient.InputValidation.required_string(opts, key, missing_error(key))
  end

  defp missing_error(:issuer), do: :missing_issuer
end
