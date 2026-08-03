defmodule AttestoClient.Wallet.CredentialOffer do
  @moduledoc """
  Parse an OID4VCI Credential Offer (`draft-ietf-oauth-openid4vci` §4.1) the
  wallet receives - the holder-side mirror of `Attesto.CredentialOffer.build/1`.

  A Credential Offer reaches the wallet in one of three shapes:

    * by value, as a decoded JSON object or a raw JSON string;
    * as an `openid-credential-offer://` deep link carrying the offer, JSON
      encoded, in its `credential_offer` query parameter; or
    * as an `openid-credential-offer://` deep link carrying a
      `credential_offer_uri` query parameter, from which the wallet fetches
      the offer object itself.

  `parse/1` handles the first two forms directly and returns `{:fetch, uri}`
  for the third, deferring the network fetch to `fetch/2`. This keeps parsing
  conn-free and testable without a live issuer; `fetch/2` performs the GET
  (through `AttestoClient.OAuthHTTP`, so it is mockable the same way as the
  rest of this library) and parses the result the same way.
  """

  alias Attesto.MapParams
  alias AttestoClient.OAuthHTTP

  @scheme "openid-credential-offer"
  @pre_authorized_code_grant_type "urn:ietf:params:oauth:grant-type:pre-authorized_code"

  @type tx_code :: %{
          input_mode: String.t() | nil,
          length: pos_integer() | nil,
          description: String.t() | nil
        }

  @type pre_authorized_code_grant :: %{
          code: String.t(),
          tx_code: tx_code() | nil,
          authorization_server: String.t() | nil
        }

  @type authorization_code_grant :: %{
          issuer_state: String.t() | nil,
          authorization_server: String.t() | nil
        }

  @type grants :: %{
          pre_authorized_code: pre_authorized_code_grant() | nil,
          authorization_code: authorization_code_grant() | nil
        }

  @type t :: %__MODULE__{
          credential_issuer: String.t(),
          credential_configuration_ids: [String.t()],
          grants: grants()
        }

  @enforce_keys [:credential_issuer, :credential_configuration_ids, :grants]
  defstruct [:credential_issuer, :credential_configuration_ids, :grants]

  @type error ::
          :invalid_credential_offer
          | :invalid_json
          | :invalid_credential_issuer
          | :invalid_credential_configuration_ids
          | :invalid_grants
          | :invalid_authorization_code_grant
          | :invalid_pre_authorized_code_grant
          | :invalid_tx_code
          | :missing_credential_offer
          | :ambiguous_credential_offer

  @doc """
  Parse an offer the wallet received: a decoded JSON object, a raw JSON
  string, or an `openid-credential-offer://` deep link.

  Returns `{:ok, offer}` for a by-value offer, `{:fetch, uri}` when the deep
  link carries `credential_offer_uri` (pass `uri` to `fetch/2`), or
  `{:error, reason}`.
  """
  @spec parse(term()) :: {:ok, t()} | {:fetch, String.t()} | {:error, error()}
  def parse(%__MODULE__{} = offer), do: {:ok, offer}
  def parse(%{} = offer), do: from_map(offer)

  def parse(input) when is_binary(input) do
    if deep_link?(input), do: parse_deep_link(input), else: parse_json(input)
  end

  def parse(_other), do: {:error, :invalid_credential_offer}

  @doc """
  Fetch a by-reference offer from `credential_offer_uri` and parse it.

  HTTP goes through `AttestoClient.OAuthHTTP.get_json/2`, so it is mockable
  the same way as the rest of this library (`req_options: [plug: ...]`).
  """
  @spec fetch(String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def fetch(uri, opts \\ []) when is_binary(uri) and is_list(opts) do
    with {:ok, body} <- OAuthHTTP.get_json(uri, opts) do
      from_map(body)
    end
  end

  defp deep_link?(input), do: String.starts_with?(input, "#{@scheme}://")

  defp parse_deep_link(link) do
    query = link |> URI.parse() |> Map.get(:query) |> decode_query()

    case {non_empty(Map.get(query, "credential_offer")),
          non_empty(Map.get(query, "credential_offer_uri"))} do
      {value, nil} when is_binary(value) -> parse_json(value)
      {nil, uri} when is_binary(uri) -> {:fetch, uri}
      {nil, nil} -> {:error, :missing_credential_offer}
      {_value, _uri} -> {:error, :ambiguous_credential_offer}
    end
  end

  defp decode_query(nil), do: %{}
  defp decode_query(query), do: URI.decode_query(query)

  defp non_empty(value) when is_binary(value) and value != "", do: value
  defp non_empty(_value), do: nil

  defp parse_json(value) do
    case JSON.decode(value) do
      {:ok, %{} = offer} -> from_map(offer)
      {:ok, _other} -> {:error, :invalid_credential_offer}
      {:error, _reason} -> {:error, :invalid_json}
    end
  end

  defp from_map(offer) do
    with {:ok, credential_issuer} <-
           required_string(offer, :credential_issuer, :invalid_credential_issuer),
         {:ok, ids} <- credential_configuration_ids(offer),
         {:ok, grants} <- grants(offer) do
      {:ok,
       %__MODULE__{
         credential_issuer: credential_issuer,
         credential_configuration_ids: ids,
         grants: grants
       }}
    end
  end

  defp credential_configuration_ids(offer) do
    case MapParams.fetch(offer, :credential_configuration_ids) do
      ids when is_list(ids) and ids != [] ->
        if Enum.all?(ids, &(is_binary(&1) and &1 != "")),
          do: {:ok, ids},
          else: {:error, :invalid_credential_configuration_ids}

      _invalid ->
        {:error, :invalid_credential_configuration_ids}
    end
  end

  # OID4VCI §4.1: when `grants` is absent, the Wallet MUST behave as if a
  # single `authorization_code` grant (no `issuer_state`) had been supplied.
  defp grants(offer) do
    case MapParams.fetch(offer, :grants) do
      nil ->
        {:ok,
         %{
           pre_authorized_code: nil,
           authorization_code: %{issuer_state: nil, authorization_server: nil}
         }}

      %{} = grants ->
        normalize_grants(grants)

      _invalid ->
        {:error, :invalid_grants}
    end
  end

  defp normalize_grants(grants) do
    with {:ok, authorization_code} <- authorization_code_grant(grants),
         {:ok, pre_authorized_code} <- pre_authorized_code_grant(grants) do
      if is_nil(authorization_code) and is_nil(pre_authorized_code) do
        {:error, :invalid_grants}
      else
        {:ok, %{authorization_code: authorization_code, pre_authorized_code: pre_authorized_code}}
      end
    end
  end

  defp authorization_code_grant(grants) do
    case MapParams.fetch(grants, :authorization_code) do
      nil -> {:ok, nil}
      %{} = grant -> normalize_authorization_code_grant(grant)
      _invalid -> {:error, :invalid_authorization_code_grant}
    end
  end

  defp normalize_authorization_code_grant(grant) do
    with {:ok, issuer_state} <-
           optional_string(grant, :issuer_state, :invalid_authorization_code_grant),
         {:ok, authorization_server} <-
           optional_string(grant, :authorization_server, :invalid_authorization_code_grant) do
      {:ok, %{issuer_state: issuer_state, authorization_server: authorization_server}}
    end
  end

  defp pre_authorized_code_grant(grants) do
    case pre_authorized_code_grant_value(grants) do
      nil -> {:ok, nil}
      %{} = grant -> normalize_pre_authorized_code_grant(grant)
      _invalid -> {:error, :invalid_pre_authorized_code_grant}
    end
  end

  # A caller may spell the grant with the full URN (always the on-the-wire
  # JSON key) or the atom-friendly hyphen/underscore forms.
  defp pre_authorized_code_grant_value(grants) do
    Map.get(grants, @pre_authorized_code_grant_type) ||
      MapParams.fetch(grants, :"pre-authorized_code") ||
      MapParams.fetch(grants, :pre_authorized_code)
  end

  defp normalize_pre_authorized_code_grant(grant) do
    with {:ok, code} <- required_pre_authorized_code(grant),
         {:ok, authorization_server} <-
           optional_string(grant, :authorization_server, :invalid_pre_authorized_code_grant),
         {:ok, tx_code} <- tx_code(grant) do
      {:ok, %{code: code, tx_code: tx_code, authorization_server: authorization_server}}
    end
  end

  defp required_pre_authorized_code(grant) do
    value = Map.get(grant, "pre-authorized_code") || MapParams.fetch(grant, :pre_authorized_code)

    if is_binary(value) and value != "",
      do: {:ok, value},
      else: {:error, :invalid_pre_authorized_code_grant}
  end

  defp tx_code(grant) do
    case MapParams.fetch(grant, :tx_code) do
      nil -> {:ok, nil}
      %{} = tx_code -> normalize_tx_code(tx_code)
      _invalid -> {:error, :invalid_tx_code}
    end
  end

  defp normalize_tx_code(tx_code) do
    with {:ok, input_mode} <- tx_code_input_mode(tx_code),
         {:ok, length} <- tx_code_length(tx_code),
         {:ok, description} <- optional_string(tx_code, :description, :invalid_tx_code) do
      {:ok, %{input_mode: input_mode, length: length, description: description}}
    end
  end

  defp tx_code_input_mode(tx_code) do
    case MapParams.fetch(tx_code, :input_mode) do
      nil -> {:ok, nil}
      mode when mode in ["numeric", "text"] -> {:ok, mode}
      _invalid -> {:error, :invalid_tx_code}
    end
  end

  defp tx_code_length(tx_code) do
    case MapParams.fetch(tx_code, :length) do
      nil -> {:ok, nil}
      length when is_integer(length) and length > 0 -> {:ok, length}
      _invalid -> {:error, :invalid_tx_code}
    end
  end

  defp required_string(map, key, error) do
    case MapParams.fetch(map, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, error}
    end
  end

  defp optional_string(map, key, error) do
    case MapParams.fetch(map, key) do
      nil -> {:ok, nil}
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, error}
    end
  end
end
