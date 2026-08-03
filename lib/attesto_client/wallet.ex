defmodule AttestoClient.Wallet do
  @moduledoc """
  OID4VCI Wallet (Holder) issuance flow (`draft-ietf-oauth-openid4vci`).

  `request_credential/3` drives the pre-authorized_code issuance flow end to
  end:

    1. exchange the offer's pre-authorized code for an access token
       (`AttestoClient.Token.exchange_pre_authorized_code/2`) - skipped when
       an `:access_token` is already supplied, e.g. obtained separately
       through the authorization_code flow
       (`AttestoClient.AuthorizationCode`);
    2. fetch a fresh `c_nonce` when the issuer advertises a nonce endpoint;
    3. build the holder key proof (`AttestoClient.Wallet.Proof`);
    4. POST the Credential Request and parse the Credential Response
       (`Attesto.CredentialResponse` shape) - a `transaction_id` response is
       returned as a `:pending` marker (deferred issuance is not polled
       here); and
    5. verify each returned credential with the attesto verifier matching
       `:format` (`Attesto.SdJwtVc`, `Attesto.JwtVc`, or `Attesto.Mdoc`).

  All HTTP goes through `AttestoClient.OAuthHTTP`, so the flow is mockable
  the same way as the rest of this library (`req_options: [plug: ...]`).
  """

  alias AttestoClient.OAuthHTTP
  alias AttestoClient.Token
  alias AttestoClient.Wallet.CredentialOffer
  alias AttestoClient.Wallet.Proof

  @sd_jwt_vc_formats ~w(vc+sd-jwt dc+sd-jwt)
  @jwt_vc_format "jwt_vc_json"
  @mdoc_format "mso_mdoc"

  @type held_credential :: %{
          required(:format) => String.t(),
          required(:credential) => String.t(),
          required(:claims) => map(),
          required(:holder_binding) => map() | nil,
          optional(:doc_type) => String.t()
        }

  @type pending_credential :: %{
          status: :pending,
          transaction_id: String.t(),
          notification_id: String.t() | nil
        }

  @type result :: %{
          credentials: [held_credential() | pending_credential()],
          c_nonce: String.t() | nil
        }

  @type opt ::
          {:credential_configuration_id, String.t()}
          | {:credential_endpoint, String.t()}
          | {:token_endpoint, String.t()}
          | {:nonce_endpoint, String.t()}
          | {:access_token, String.t()}
          | {:tx_code, String.t()}
          | {:client_id, String.t()}
          | {:client_auth, term()}
          | {:format, String.t()}
          | {:trusted, term()}
          | {:verify_opts, keyword()}
          | {:proof_alg, String.t()}
          | {:proof_kid, String.t()}
          | {:key_attestation, String.t()}
          | {:dpop, Proof.jwk()}
          | {:now, integer()}
          | {:req_options, keyword()}
          | {:timeout, pos_integer()}

  @doc """
  Run the wallet-holder issuance flow for `offer` and return the verified,
  held credential(s) (or a pending marker for deferred issuance).

  Required options: `:credential_endpoint`, `:format` (one of `"vc+sd-jwt"`,
  `"dc+sd-jwt"`, `"jwt_vc_json"`, or `"mso_mdoc"`), and `:trusted` (the
  Credential Issuer's verification key material, in the shape the matching
  attesto verifier expects - a JWKS/JWK list for `Attesto.SdJwtVc` and
  `Attesto.JwtVc`, a single JWK/PEM for `Attesto.Mdoc`). `:verify_opts` are
  forwarded to that verifier (e.g. `:accepted_algs`, `:now`).

  Unless `:access_token` is supplied, the flow performs the
  pre-authorized_code token exchange itself and requires `:token_endpoint`
  and, when the offer's grant carries one, `:tx_code`. `:client_id` and
  `:client_auth` authenticate that token request exactly as in
  `AttestoClient.Token`, and, when present, `:client_id` is also carried as
  the proof's `iss`.

  `:nonce_endpoint`, when supplied, is used to fetch a fresh `c_nonce` before
  building the proof. `:credential_configuration_id` selects which of the
  offer's configuration ids to request; it defaults to the offer's only id
  when there is exactly one.

  `:dpop` (a `JOSE.JWK` or JWK map) sender-constrains the flow with RFC 9449
  DPoP proofs. The one key is used at the token endpoint (binding the access
  token to its `jkt`) and at the Credential Endpoint (where the proof carries
  the `ath` binding to that token), and a `use_dpop_nonce` challenge is retried
  once - see `AttestoClient.DPoP`.

  `:key_attestation` (a compact JWT from `AttestoClient.KeyAttestation.build/2`)
  is carried in the holder proof's `key_attestation` header, vouching to the
  issuer that the holder key is held in secure storage (a HAIP requirement).
  """
  @spec request_credential(CredentialOffer.t(), Proof.jwk(), [opt()]) ::
          {:ok, result()} | {:error, term()}
  def request_credential(%CredentialOffer{} = offer, holder_key, opts) when is_list(opts) do
    with {:ok, format} <- required_format(opts),
         {:ok, configuration_id} <- configuration_id(offer, opts),
         {:ok, access_token} <- access_token(offer, opts),
         {:ok, c_nonce} <- fetch_nonce(opts),
         {:ok, proof} <- build_proof(offer, holder_key, c_nonce, opts),
         {:ok, response} <- post_credential_request(configuration_id, proof, access_token, opts) do
      finalize(response, format, c_nonce, opts)
    end
  end

  def request_credential(_offer, _holder_key, _opts), do: {:error, :invalid_offer}

  defp required_format(opts) do
    case Keyword.get(opts, :format) do
      format when format in @sd_jwt_vc_formats or format in [@jwt_vc_format, @mdoc_format] ->
        {:ok, format}

      _invalid ->
        {:error, :missing_format}
    end
  end

  defp configuration_id(offer, opts) do
    case Keyword.get(opts, :credential_configuration_id) do
      id when is_binary(id) and id != "" ->
        {:ok, id}

      nil ->
        case offer.credential_configuration_ids do
          [id] -> {:ok, id}
          _many -> {:error, :ambiguous_credential_configuration_id}
        end

      _invalid ->
        {:error, :invalid_credential_configuration_id}
    end
  end

  defp access_token(offer, opts) do
    case Keyword.get(opts, :access_token) do
      token when is_binary(token) and token != "" -> {:ok, token}
      _missing -> exchange_pre_authorized_code(offer, opts)
    end
  end

  defp exchange_pre_authorized_code(%CredentialOffer{grants: %{pre_authorized_code: nil}}, _opts),
    do: {:error, :missing_pre_authorized_code_grant}

  defp exchange_pre_authorized_code(%CredentialOffer{grants: %{pre_authorized_code: grant}}, opts) do
    with {:ok, tx_code} <- required_tx_code(grant, opts),
         {:ok, tokens} <-
           Token.exchange_pre_authorized_code(grant.code, Keyword.put(opts, :tx_code, tx_code)) do
      {:ok, tokens.access_token}
    end
  end

  defp required_tx_code(%{tx_code: nil}, _opts), do: {:ok, nil}

  defp required_tx_code(%{tx_code: %{}}, opts) do
    case Keyword.get(opts, :tx_code) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _missing -> {:error, :missing_tx_code}
    end
  end

  defp fetch_nonce(opts) do
    case Keyword.get(opts, :nonce_endpoint) do
      nil -> {:ok, nil}
      endpoint when is_binary(endpoint) and endpoint != "" -> request_nonce(endpoint, opts)
      _invalid -> {:error, :invalid_nonce_endpoint}
    end
  end

  defp request_nonce(endpoint, opts) do
    case OAuthHTTP.post_form(endpoint, %{}, opts) do
      {:ok, %{"c_nonce" => c_nonce}} when is_binary(c_nonce) and c_nonce != "" -> {:ok, c_nonce}
      {:ok, _invalid} -> {:error, :invalid_nonce_response}
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_proof(offer, holder_key, c_nonce, opts) do
    proof_opts =
      [credential_issuer: offer.credential_issuer]
      |> put_optional(:nonce, c_nonce)
      |> put_optional(:client_id, Keyword.get(opts, :client_id))
      |> put_optional(:now, Keyword.get(opts, :now))
      |> put_optional(:alg, Keyword.get(opts, :proof_alg))
      |> put_optional(:kid, Keyword.get(opts, :proof_kid))
      |> put_optional(:key_attestation, Keyword.get(opts, :key_attestation))

    Proof.build(holder_key, proof_opts)
  end

  defp post_credential_request(configuration_id, proof, access_token, opts) do
    with {:ok, endpoint} <-
           required_string(opts, :credential_endpoint, :missing_credential_endpoint) do
      body = %{
        "credential_configuration_id" => configuration_id,
        "proof" => %{"proof_type" => "jwt", "jwt" => proof}
      }

      OAuthHTTP.post_json(endpoint, body, access_token, opts)
    end
  end

  defp finalize(%{"transaction_id" => transaction_id} = response, _format, c_nonce, _opts)
       when is_binary(transaction_id) and transaction_id != "" do
    pending = %{
      status: :pending,
      transaction_id: transaction_id,
      notification_id: Map.get(response, "notification_id")
    }

    {:ok, %{credentials: [pending], c_nonce: c_nonce}}
  end

  defp finalize(%{"credentials" => credentials}, format, c_nonce, opts)
       when is_list(credentials) and credentials != [] do
    with {:ok, held} <- verify_credentials(credentials, format, opts) do
      {:ok, %{credentials: held, c_nonce: c_nonce}}
    end
  end

  defp finalize(_response, _format, _c_nonce, _opts), do: {:error, :invalid_credential_response}

  defp verify_credentials(credentials, format, opts) do
    credentials
    |> Enum.reduce_while({:ok, []}, fn entry, {:ok, acc} ->
      case credential_value(entry) do
        {:ok, credential} -> reduce_verify(credential, format, opts, acc)
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, held} -> {:ok, Enum.reverse(held)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp reduce_verify(credential, format, opts, acc) do
    case verify_credential(format, credential, opts) do
      {:ok, held} -> {:cont, {:ok, [held | acc]}}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp credential_value(%{"credential" => credential})
       when is_binary(credential) and credential != "",
       do: {:ok, credential}

  defp credential_value(_entry), do: {:error, :invalid_credential_response}

  defp verify_credential(format, credential, opts) when format in @sd_jwt_vc_formats do
    with {:ok, %{claims: claims, cnf: cnf}} <-
           Attesto.SdJwtVc.verify(credential, trusted(opts), verify_opts(opts)) do
      {:ok, %{format: format, credential: credential, claims: claims, holder_binding: cnf}}
    end
  end

  defp verify_credential(@jwt_vc_format, credential, opts) do
    with {:ok, %{claims: claims, cnf: cnf}} <-
           Attesto.JwtVc.verify(credential, trusted(opts), verify_opts(opts)) do
      {:ok,
       %{format: @jwt_vc_format, credential: credential, claims: claims, holder_binding: cnf}}
    end
  end

  defp verify_credential(@mdoc_format, credential, opts) do
    with {:ok, %{namespaces: namespaces, device_key: device_key, doc_type: doc_type}} <-
           Attesto.Mdoc.verify(credential, trusted(opts), verify_opts(opts)) do
      {:ok,
       %{
         format: @mdoc_format,
         credential: credential,
         claims: namespaces,
         holder_binding: device_key,
         doc_type: doc_type
       }}
    end
  end

  defp verify_credential(_format, _credential, _opts), do: {:error, :unsupported_format}

  defp trusted(opts), do: Keyword.get(opts, :trusted)
  defp verify_opts(opts), do: Keyword.get(opts, :verify_opts, [])

  defp put_optional(opts, _key, nil), do: opts
  defp put_optional(opts, key, value), do: Keyword.put(opts, key, value)

  defp required_string(opts, key, error) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, error}
    end
  end
end
