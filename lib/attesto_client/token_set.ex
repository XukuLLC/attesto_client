defmodule AttestoClient.TokenSet do
  @moduledoc """
  Validated token-endpoint response.

  The struct carries protocol output and optional local DPoP key provenance.
  The application decides whether, where, and for how long to retain tokens. In
  particular, this library never creates a login session or makes an
  authorization decision from token claims.

  The optional `:refresh_token_timeout` and `:authorization_expires_in`
  durations follow `draft-ietf-oauth-refresh-token-expiration-03`. They are
  literal seconds from the response time; absence is not proof that the
  server implements the draft or that a credential cannot expire early.

  `:dpop_jkt` is the public-key thumbprint derived locally when a DPoP token
  response is accepted. It never comes from token-endpoint JSON. Persist it
  with the tokens and retain the corresponding private key for refresh. Older
  token sets may omit it; their original key cannot be verified retrospectively.

  Profile flows also retain `:profile`, `:client_auth_binding`, `:client_id`
  and `:issuer` locally. Persist these fields for authenticated refresh and
  pass the complete token set to HAIP credential issuance. They never come
  from server JSON, and the authentication binding contains no private key.

  `:id_token_alg` retains the locally selected ID Token verification algorithm
  from authorization or refresh. Persist it with the token set so refresh uses
  the same policy. It never comes from token-endpoint JSON.
  """

  alias Attesto.Thumbprint
  alias AttestoClient.Builder
  alias AttestoClient.DPoP

  @enforce_keys [:access_token, :token_type]
  defstruct [
    :access_token,
    :token_type,
    :expires_in,
    :refresh_token_timeout,
    :authorization_expires_in,
    :refresh_token,
    :id_token,
    :id_token_alg,
    :scope,
    :dpop_jkt,
    :client_id,
    :issuer,
    :client_auth_binding,
    profile: :generic,
    extra: %{}
  ]

  @type t :: %__MODULE__{
          access_token: String.t(),
          token_type: String.t(),
          expires_in: non_neg_integer() | nil,
          refresh_token_timeout: non_neg_integer() | nil,
          authorization_expires_in: non_neg_integer() | nil,
          refresh_token: String.t() | nil,
          id_token: String.t() | nil,
          id_token_alg: String.t() | nil,
          scope: String.t() | nil,
          dpop_jkt: String.t() | nil,
          client_id: String.t() | nil,
          issuer: String.t() | nil,
          client_auth_binding: map() | nil,
          profile: :generic | :haip | :fapi,
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
         :ok <- optional_non_negative_integer(response, "refresh_token_timeout"),
         :ok <- optional_non_negative_integer(response, "authorization_expires_in"),
         :ok <- validate_refresh_expiry_order(response),
         :ok <- optional_string(response, "refresh_token"),
         :ok <- optional_string(response, "id_token"),
         :ok <- optional_string(response, "scope") do
      known =
        ~w(access_token token_type expires_in refresh_token_timeout authorization_expires_in refresh_token id_token scope)

      {:ok,
       %__MODULE__{
         access_token: access_token,
         token_type: token_type,
         expires_in: Map.get(response, "expires_in"),
         refresh_token_timeout: Map.get(response, "refresh_token_timeout"),
         authorization_expires_in: Map.get(response, "authorization_expires_in"),
         refresh_token: Map.get(response, "refresh_token", old_refresh),
         id_token: Map.get(response, "id_token"),
         scope: Map.get(response, "scope", old_scope),
         extra: Map.drop(response, known)
       }}
    end
  end

  def from_response(_response, _old_refresh, _old_scope), do: {:error, :invalid_token_response}

  @doc false
  @spec dpop_thumbprint(keyword()) :: {:ok, String.t() | nil} | {:error, :invalid_dpop_key}
  def dpop_thumbprint(opts) do
    case Keyword.get(opts, :dpop) do
      nil -> {:ok, nil}
      key -> signing_thumbprint(key)
    end
  end

  @doc false
  @spec bind_dpop(t(), String.t() | nil) ::
          {:ok, t()} | {:error, :invalid_token_type | :missing_dpop_key}
  def bind_dpop(tokens, nil) do
    if dpop?(tokens.token_type), do: {:error, :missing_dpop_key}, else: {:ok, tokens}
  end

  def bind_dpop(tokens, jkt) do
    if dpop?(tokens.token_type),
      do: {:ok, %{tokens | dpop_jkt: jkt}},
      else: {:error, :invalid_token_type}
  end

  @doc false
  @spec dpop?(term()) :: boolean()
  def dpop?(type) when is_binary(type),
    do: String.valid?(type) and String.downcase(type) == "dpop"

  def dpop?(_invalid), do: false

  defp signing_thumbprint(key) do
    # Prove that the key can sign before discovery or token HTTP. This local
    # probe is never transmitted or reused as a protocol proof.
    with {:ok, jwk} <- Builder.normalize_key(key),
         {:ok, _proof} <- DPoP.proof(jwk, "POST", "https://dpop-validation.invalid"),
         {:ok, jkt} <- jwk |> Builder.public_jwk() |> Thumbprint.of_jwk() do
      {:ok, jkt}
    else
      _invalid -> {:error, :invalid_dpop_key}
    end
  rescue
    _error -> {:error, :invalid_dpop_key}
  end

  defp validate_refresh_expiry_order(%{
         "refresh_token_timeout" => timeout,
         "authorization_expires_in" => authorization
       })
       when timeout > authorization, do: {:error, :invalid_token_response}

  defp validate_refresh_expiry_order(_response), do: :ok

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
