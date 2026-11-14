defmodule AttestoClient.OAuthHTTP.ClientAuth do
  @moduledoc false

  alias AttestoClient.{ClientAssertion, ClientAuthOptions, WalletAttestation}

  @spec authenticate(map(), String.t(), keyword()) ::
          {:ok, map(), keyword()} | {:error, term()}
  def authenticate(form, endpoint, opts) do
    authenticate_as(
      Keyword.get(opts, :client_auth, :none),
      Keyword.get(opts, :client_id),
      form,
      endpoint,
      opts
    )
  end

  @spec attempt_options(keyword(), boolean(), String.t() | nil) :: keyword()
  def attempt_options(opts, retry?, challenge) do
    opts = if retry?, do: drop_client_auth_jti(opts), else: opts
    put_attestation_challenge(opts, challenge)
  end

  @spec attestation?(keyword()) :: boolean()
  def attestation?(opts),
    do: match?({:client_attestation, _, _, _}, Keyword.get(opts, :client_auth))

  defp authenticate_as(:none, client_id, form, _endpoint, opts)
       when is_binary(client_id) and client_id != "" do
    {:ok, Map.put(form, "client_id", client_id), req_options(opts)}
  end

  defp authenticate_as(:none, nil, form, _endpoint, opts),
    do: {:ok, form, req_options(opts)}

  defp authenticate_as({:client_secret_basic, secret}, client_id, form, _endpoint, opts)
       when is_binary(client_id) and client_id != "" and is_binary(secret) and secret != "" do
    credentials = "#{URI.encode_www_form(client_id)}:#{URI.encode_www_form(secret)}"
    {:ok, form, Keyword.put(req_options(opts), :auth, {:basic, credentials})}
  end

  defp authenticate_as({:client_secret_post, secret}, client_id, form, _endpoint, opts)
       when is_binary(client_id) and client_id != "" and is_binary(secret) and secret != "" do
    {:ok, Map.merge(form, %{"client_id" => client_id, "client_secret" => secret}),
     req_options(opts)}
  end

  defp authenticate_as({:private_key_jwt, jwk}, client_id, form, endpoint, opts)
       when is_binary(client_id) and client_id != "" do
    authenticate_as({:private_key_jwt, jwk, []}, client_id, form, endpoint, opts)
  end

  defp authenticate_as({:private_key_jwt, jwk, assertion_opts}, client_id, form, _endpoint, opts)
       when is_binary(client_id) and client_id != "" and is_list(assertion_opts) do
    with {:ok, build_opts} <- client_assertion_options(assertion_opts, client_id, opts),
         {:ok, assertion} <- ClientAssertion.build(jwk, build_opts) do
      {:ok,
       Map.merge(form, %{
         "client_id" => client_id,
         "client_assertion_type" => ClientAssertion.assertion_type(),
         "client_assertion" => assertion
       }), req_options(opts)}
    else
      {:error, :invalid_client_assertion_options} = error -> error
      {:error, reason} -> {:error, {:client_assertion, reason}}
    end
  end

  defp authenticate_as(
         {:client_attestation, attestation, instance_key, ca_opts},
         client_id,
         form,
         _endpoint,
         opts
       )
       when is_binary(client_id) and client_id != "" and is_binary(attestation) and
              attestation != "" and is_list(ca_opts) do
    case WalletAttestation.pop(instance_key, Keyword.put(ca_opts, :client_id, client_id)) do
      {:ok, pop} ->
        headers = [
          {"oauth-client-attestation", attestation},
          {"oauth-client-attestation-pop", pop}
        ]

        {:ok, Map.put(form, "client_id", client_id),
         Keyword.update(req_options(opts), :headers, headers, &(&1 ++ headers))}

      {:error, reason} ->
        {:error, {:client_attestation, reason}}
    end
  end

  defp authenticate_as(_invalid, _client_id, _form, _endpoint, _opts),
    do: {:error, :invalid_client_auth}

  # RFC 10070 §4: the assertion's sole audience is the authorization server's
  # issuer identifier, and the token endpoint URL MUST NOT be used as one. The
  # audience therefore comes from the caller's trusted `:issuer` (or
  # an explicit assertion `:audience`), never from the endpoint URL. With
  # neither, no audience is set and `ClientAssertion.build/2` answers
  # `:invalid_audience`, so nothing is sent.
  defp client_assertion_options(opts, client_id, request_opts) do
    if ClientAuthOptions.valid?(opts, :assertion) do
      {:ok,
       opts
       |> Keyword.put_new_lazy(:audience, fn -> Keyword.get(request_opts, :issuer) end)
       |> Keyword.put(:client_id, client_id)}
    else
      {:error, :invalid_client_assertion_options}
    end
  end

  defp drop_client_auth_jti(opts) do
    case Keyword.get(opts, :client_auth) do
      {:private_key_jwt, jwk, assertion_opts} when is_list(assertion_opts) ->
        Keyword.put(
          opts,
          :client_auth,
          {:private_key_jwt, jwk, Keyword.delete(assertion_opts, :jti)}
        )

      {:client_attestation, attestation, key, ca_opts} when is_list(ca_opts) ->
        Keyword.put(
          opts,
          :client_auth,
          {:client_attestation, attestation, key, Keyword.delete(ca_opts, :jti)}
        )

      _other ->
        opts
    end
  end

  defp put_attestation_challenge(opts, nil), do: opts

  defp put_attestation_challenge(opts, challenge) do
    case Keyword.get(opts, :client_auth) do
      {:client_attestation, attestation, key, ca_opts} when is_list(ca_opts) ->
        Keyword.put(
          opts,
          :client_auth,
          {:client_attestation, attestation, key, Keyword.put(ca_opts, :challenge, challenge)}
        )

      _other ->
        opts
    end
  end

  defp req_options(opts), do: Keyword.get(opts, :req_options, [])
end
