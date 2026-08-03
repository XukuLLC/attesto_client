defmodule AttestoClient.Wallet.PresentationRequest do
  @moduledoc """
  Parse and verify an OID4VP Authorization Request the wallet receives
  (`draft-ietf-oauth-openid4vp` §5) - the holder-side mirror of
  `Attesto.PresentationRequest.build/1`.

  The verifier's request arrives as a signed request object (JAR, RFC 9101):
  by value, in the deep link's `request` parameter, or by reference, in its
  `request_uri` parameter. Both forms are signed; only the transport differs
  - `verify/3` handles the former, `fetch/3` GETs the JWT (through
  `AttestoClient.OAuthHTTP.get_text/2`, so it is mockable the same way as the
  rest of this library) and then calls `verify/3`. Signature verification
  delegates entirely to `Attesto.RequestObject.verify_with_claims/3`, so
  `trusted` and `opts` behave exactly as there (e.g. `:audience`,
  `:accepted_algs`, `:accepted_typ`).

  Only `response_type=vp_token` and `response_mode=direct_post` /
  `direct_post.jwt` are recognised (OID4VP §5, §8.2). `direct_post.jwt`
  parses successfully - the request is reported faithfully - but
  `AttestoClient.Wallet.Presentation` does not build a response for it yet
  (encrypted responses are a follow-up).
  """

  alias Attesto.RequestObject
  alias AttestoClient.OAuthHTTP

  @response_type "vp_token"
  @default_response_mode "direct_post"
  @response_modes ~w(direct_post direct_post.jwt)

  @type t :: %__MODULE__{
          client_id: String.t(),
          nonce: String.t(),
          response_uri: String.t(),
          response_mode: String.t(),
          dcql_query: map(),
          state: String.t() | nil
        }

  @enforce_keys [:client_id, :nonce, :response_uri, :response_mode, :dcql_query]
  defstruct [:client_id, :nonce, :response_uri, :response_mode, :dcql_query, state: nil]

  @type error ::
          :invalid_response_type
          | :invalid_response_mode
          | :invalid_client_id
          | :invalid_nonce
          | :invalid_response_uri
          | :invalid_dcql_query
          | :invalid_state
          | RequestObject.verify_error()

  @doc """
  Verify a signed OID4VP Authorization Request object (a by-value `request`
  JWT) and return its parsed parameters.
  """
  @spec verify(String.t(), map() | [map()], RequestObject.verify_opts()) ::
          {:ok, t()} | {:error, error()}
  def verify(jwt, trusted, opts \\ []) when is_binary(jwt) and is_list(opts) do
    with {:ok, _params, claims} <- RequestObject.verify_with_claims(jwt, trusted, opts) do
      from_claims(claims)
    end
  end

  @doc """
  Fetch a by-reference request object from `request_uri` and verify it.

  Options are shared between the fetch (`AttestoClient.OAuthHTTP.get_text/2`
  - `:req_options`, `:timeout`) and the verification (`verify/3` - `trusted`,
  `RequestObject.verify_opts`); each side reads only the options it
  recognises.
  """
  @spec fetch(String.t(), map() | [map()], RequestObject.verify_opts()) ::
          {:ok, t()} | {:error, term()}
  def fetch(request_uri, trusted, opts \\ []) when is_binary(request_uri) and is_list(opts) do
    with {:ok, jwt} <- OAuthHTTP.get_text(request_uri, opts) do
      verify(jwt, trusted, opts)
    end
  end

  defp from_claims(claims) do
    with :ok <- check_response_type(claims),
         {:ok, client_id} <- required_string(claims, "client_id", :invalid_client_id),
         {:ok, nonce} <- required_string(claims, "nonce", :invalid_nonce),
         {:ok, response_uri} <- required_string(claims, "response_uri", :invalid_response_uri),
         {:ok, response_mode} <- response_mode(claims),
         {:ok, dcql_query} <- valid_dcql_query(claims),
         {:ok, state} <- optional_string(claims, "state", :invalid_state) do
      {:ok,
       %__MODULE__{
         client_id: client_id,
         nonce: nonce,
         response_uri: response_uri,
         response_mode: response_mode,
         dcql_query: dcql_query,
         state: state
       }}
    end
  end

  defp check_response_type(%{"response_type" => @response_type}), do: :ok
  defp check_response_type(_claims), do: {:error, :invalid_response_type}

  defp response_mode(claims) do
    case Map.get(claims, "response_mode", @default_response_mode) do
      mode when mode in @response_modes -> {:ok, mode}
      _invalid -> {:error, :invalid_response_mode}
    end
  end

  defp required_string(claims, key, error) do
    case Map.get(claims, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, error}
    end
  end

  # Validate the DCQL query shape here so a signed-but-malformed request from a
  # trusted-but-buggy (or compromised) verifier cannot crash later selection
  # (`Presentation.select/2` indexes each query with `Map.get/2`). Requires a
  # non-empty `credentials` list of maps, each with a non-empty string `id`
  # (unique across the list) and `format`.
  defp valid_dcql_query(claims) do
    case Map.get(claims, "dcql_query") do
      %{"credentials" => credentials} = query when is_list(credentials) and credentials != [] ->
        if Enum.all?(credentials, &valid_credential_query?/1) and unique_ids?(credentials),
          do: {:ok, query},
          else: {:error, :invalid_dcql_query}

      _invalid ->
        {:error, :invalid_dcql_query}
    end
  end

  defp valid_credential_query?(%{"id" => id, "format" => format})
       when is_binary(id) and id != "" and is_binary(format) and format != "",
       do: true

  defp valid_credential_query?(_query), do: false

  defp unique_ids?(credentials) do
    ids = Enum.map(credentials, &Map.get(&1, "id"))
    length(ids) == length(Enum.uniq(ids))
  end

  defp optional_string(claims, key, error) do
    case Map.get(claims, key) do
      nil -> {:ok, nil}
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, error}
    end
  end
end
