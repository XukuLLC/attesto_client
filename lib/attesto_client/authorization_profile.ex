defmodule AttestoClient.AuthorizationProfile do
  @moduledoc false

  alias Attesto.SigningAlg
  alias Attesto.Thumbprint
  alias AttestoClient.Builder
  alias AttestoClient.ClientAssertion
  alias AttestoClient.Wallet.Presentation.CertificateTrust
  alias AttestoClient.WalletAttestation

  @assertion_options ~w(audience alg kid typ lifetime now jti)a
  @attestation_options ~w(audience challenge alg kid lifetime now jti)a

  @spec select(keyword()) :: {:ok, :generic | :haip | :fapi} | {:error, atom()}
  def select(opts) do
    case {Keyword.get(opts, :haip, false), Keyword.get(opts, :fapi?, false)} do
      {false, false} -> {:ok, :generic}
      {true, false} -> {:ok, :haip}
      {false, true} -> {:ok, :fapi}
      {true, true} -> {:error, :conflicting_profiles}
      {haip, _fapi} when not is_boolean(haip) -> {:error, :invalid_haip}
      _invalid -> {:error, :invalid_fapi}
    end
  end

  @spec require_dpop(atom(), String.t() | nil) :: :ok | {:error, atom()}
  def require_dpop(:generic, _jkt), do: :ok

  def require_dpop(profile, jkt) when profile in [:haip, :fapi] and is_binary(jkt) and jkt != "",
    do: :ok

  def require_dpop(_profile, _jkt), do: {:error, :profile_dpop_required}

  @spec dpop_policy(atom(), keyword()) :: :ok | {:error, atom()}
  def dpop_policy(:generic, _opts), do: :ok
  def dpop_policy(:haip, _opts), do: :ok

  def dpop_policy(:fapi, opts) do
    with {:ok, jwk} <- Builder.normalize_key(Keyword.get(opts, :dpop)),
         {:ok, alg} <- Builder.resolve_alg(jwk, []),
         true <- SigningAlg.fapi_compatible?(alg, jwk) do
      :ok
    else
      _invalid -> {:error, :invalid_profile_dpop_key}
    end
  end

  @spec metadata(map() | nil, map()) :: :ok | {:error, atom()}
  def metadata(nil, _metadata), do: :ok

  def metadata(%{method: method}, metadata) do
    wire_method =
      if method == :client_attestation, do: "attest_jwt_client_auth", else: Atom.to_string(method)

    case metadata["token_endpoint_auth_methods_supported"] do
      nil ->
        :ok

      methods when is_list(methods) ->
        if Enum.all?(methods, &is_binary/1) and wire_method in methods,
          do: :ok,
          else: {:error, :unsupported_profile_client_auth}

      _invalid ->
        {:error, :invalid_metadata}
    end
  end

  @spec bind(atom(), String.t(), String.t(), keyword()) :: {:ok, map() | nil} | {:error, atom()}
  def bind(:generic, _client_id, _issuer, _opts), do: {:ok, nil}

  def bind(profile, client_id, issuer, opts) when profile in [:haip, :fapi] do
    with :ok <- fixed_identity(opts, client_id, issuer) do
      bind_auth(Keyword.get(opts, :client_auth, :none), profile, client_id, issuer)
    end
  rescue
    _error -> {:error, :invalid_profile_client_auth}
  catch
    _kind, _reason -> {:error, :invalid_profile_client_auth}
  end

  def bind(_invalid, _client_id, _issuer, _opts), do: {:error, :invalid_profile}

  @spec check(atom(), map() | nil, String.t(), String.t(), keyword()) :: :ok | {:error, atom()}
  def check(:generic, _binding, _client_id, _issuer, _opts), do: :ok

  def check(profile, binding, client_id, issuer, opts) do
    with {:ok, presented} <- bind(profile, client_id, issuer, opts) do
      if is_map(binding) and binding == presented,
        do: :ok,
        else: {:error, :client_auth_mismatch}
    end
  end

  defp fixed_identity(opts, client_id, issuer) do
    if Keyword.get(opts, :client_id, client_id) == client_id and
         Keyword.get(opts, :issuer, issuer) == issuer,
       do: :ok,
       else: {:error, :client_auth_mismatch}
  end

  defp bind_auth(auth, _profile, _client_id, _issuer) when auth in [:none, nil],
    do: {:error, :profile_client_auth_required}

  defp bind_auth({method, secret}, :haip, _client_id, _issuer)
       when method in [:client_secret_basic, :client_secret_post] and is_binary(secret) and
              byte_size(secret) > 0 do
    {:ok, %{method: method, secret_digest: :crypto.hash(:sha256, secret)}}
  end

  defp bind_auth({:private_key_jwt, key}, profile, client_id, issuer),
    do: bind_auth({:private_key_jwt, key, []}, profile, client_id, issuer)

  defp bind_auth({:private_key_jwt, key, opts}, profile, client_id, issuer) do
    with :ok <- auth_options(opts, @assertion_options),
         :ok <- assertion_audience(opts, issuer),
         {:ok, jwk} <- Builder.normalize_key(key),
         {:ok, alg} <- Builder.resolve_alg(jwk, opts),
         :ok <- algorithm_policy(profile, alg, jwk),
         {:ok, _probe} <-
           ClientAssertion.build(jwk, Keyword.merge(opts, client_id: client_id, audience: issuer)),
         {:ok, jkt} <- jwk |> Builder.public_jwk() |> Thumbprint.of_jwk() do
      {:ok, %{method: :private_key_jwt, jkt: jkt, alg: alg}}
    else
      _invalid -> {:error, :invalid_profile_client_auth}
    end
  end

  defp bind_auth({:client_attestation, attestation, key, opts}, :haip, client_id, issuer) do
    with :ok <- auth_options(opts, @attestation_options),
         true <- Keyword.get(opts, :audience) == issuer,
         {:ok, jwk} <- Builder.normalize_key(key),
         {:ok, alg} <- Builder.resolve_alg(jwk, opts),
         {:ok, _probe} <- WalletAttestation.pop(jwk, Keyword.put(opts, :client_id, client_id)),
         {:ok, jkt} <- jwk |> Builder.public_jwk() |> Thumbprint.of_jwk(),
         :ok <- attestation_identity(attestation, client_id, jkt) do
      {:ok,
       %{
         method: :client_attestation,
         jkt: jkt,
         alg: alg,
         subject: client_id
       }}
    else
      _invalid -> {:error, :invalid_profile_client_auth}
    end
  end

  defp bind_auth(_auth, _profile, _client_id, _issuer),
    do: {:error, :unsupported_profile_client_auth}

  defp auth_options(opts, allowed) do
    if Keyword.keyword?(opts) and Enum.all?(Keyword.keys(opts), &(&1 in allowed)) and
         length(opts) == length(Enum.uniq_by(opts, &elem(&1, 0))),
       do: :ok,
       else: {:error, :invalid_profile_client_auth}
  end

  defp assertion_audience(opts, issuer) do
    if Keyword.get(opts, :audience, issuer) == issuer,
      do: :ok,
      else: {:error, :invalid_profile_client_auth}
  end

  defp algorithm_policy(:fapi, alg, jwk) do
    if SigningAlg.fapi_compatible?(alg, jwk),
      do: :ok,
      else: {:error, :invalid_profile_client_auth}
  end

  defp algorithm_policy(:haip, _alg, _jwk), do: :ok

  # This is a local consistency check, not attester authentication. The
  # authorization server must verify the attestation's signature and trust.
  defp attestation_identity(attestation, client_id, jkt) do
    with {:ok, _compact} <- Attesto.JWS.decode_compact(attestation),
         {:ok, %{"typ" => "oauth-client-attestation+jwt", "alg" => alg, "x5c" => chain}} <-
           Attesto.JWS.peek_json(attestation, :protected),
         true <- alg in SigningAlg.allowed(),
         {:ok, certificates} <- CertificateTrust.decode_x5c(chain),
         true <- Enum.all?(certificates, &complete_certificate?/1),
         {:ok, %{"sub" => ^client_id, "cnf" => %{"jwk" => public}}} <-
           Attesto.JWS.peek_json(attestation, :payload),
         {:ok, ^jkt} <- Thumbprint.of_jwk(public) do
      :ok
    else
      _invalid -> {:error, :invalid_profile_client_auth}
    end
  end

  # Only certificate structure is checked here. Certificate trust, the attester
  # signature and attestation validity are the authorization server's responsibility.
  defp complete_certificate?(der) do
    certificate = :public_key.der_decode(:Certificate, der)
    :public_key.der_encode(:Certificate, certificate) == der
  rescue
    _invalid -> false
  catch
    _kind, _reason -> false
  end
end
