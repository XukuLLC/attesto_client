defmodule AttestoClient.TokenSet do
  @moduledoc """
  Validated token-endpoint response.

  The struct carries protocol output only. The application decides whether,
  where, and for how long to retain access, refresh, and ID tokens. In
  particular, this library never creates a login session or makes an
  authorization decision from token claims.
  """

  @enforce_keys [:access_token, :token_type]
  defstruct [
    :access_token,
    :token_type,
    :expires_in,
    :refresh_token,
    :id_token,
    :scope,
    extra: %{}
  ]

  @type t :: %__MODULE__{
          access_token: String.t(),
          token_type: String.t(),
          expires_in: non_neg_integer() | nil,
          refresh_token: String.t() | nil,
          id_token: String.t() | nil,
          scope: String.t() | nil,
          extra: map()
        }

  @doc false
  @spec from_response(map(), String.t() | nil, String.t() | nil) ::
          {:ok, t()} | {:error, :invalid_token_response}
  def from_response(response, old_refresh, old_scope \\ nil)

  def from_response(
        %{"access_token" => access_token, "token_type" => token_type} = response,
        old_refresh,
        old_scope
      )
      when is_binary(access_token) and access_token != "" and is_binary(token_type) and
             token_type != "" do
    with :ok <- optional_non_negative_integer(response, "expires_in"),
         :ok <- optional_string(response, "refresh_token"),
         :ok <- optional_string(response, "id_token"),
         :ok <- optional_string(response, "scope") do
      known = ~w(access_token token_type expires_in refresh_token id_token scope)

      {:ok,
       %__MODULE__{
         access_token: access_token,
         token_type: token_type,
         expires_in: Map.get(response, "expires_in"),
         refresh_token: Map.get(response, "refresh_token", old_refresh),
         id_token: Map.get(response, "id_token"),
         scope: Map.get(response, "scope", old_scope),
         extra: Map.drop(response, known)
       }}
    end
  end

  def from_response(_response, _old_refresh, _old_scope), do: {:error, :invalid_token_response}

  defp optional_non_negative_integer(response, key) do
    case Map.fetch(response, key) do
      :error -> :ok
      {:ok, value} when is_integer(value) and value >= 0 -> :ok
      {:ok, _invalid} -> {:error, :invalid_token_response}
    end
  end

  defp optional_string(response, key) do
    case Map.fetch(response, key) do
      :error -> :ok
      {:ok, value} when is_binary(value) and value != "" -> :ok
      {:ok, _invalid} -> {:error, :invalid_token_response}
    end
  end
end
