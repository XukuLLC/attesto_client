defmodule AttestoClient.Wallet.CredentialEncryption do
  @moduledoc false

  alias AttestoClient.OAuthHTTP
  alias AttestoClient.Wallet.CredentialJSON

  @encs ~w(A256GCM A128GCM)
  @max_bytes 2_000_000
  @private_fields ~w(d p q dp dq qi oth k)

  @spec prepare(keyword()) :: {:ok, map()} | {:error, term()}
  def prepare(opts) do
    metadata = Keyword.get(opts, :credential_issuer_metadata, %{})

    with true <- is_map(metadata),
         {:ok, mode} <- mode(opts),
         {:ok, request} <- metadata_section(metadata, "credential_request_encryption"),
         {:ok, response} <- metadata_section(metadata, "credential_response_encryption"),
         :ok <- allowed_mode(mode, request, response),
         {:ok, response_context} <- response_context(mode, response, opts),
         {:ok, request_context} <- request_context(mode, request, response_context) do
      {:ok, %{request: request_context, response: response_context}}
    else
      false -> {:error, :invalid_credential_issuer_metadata}
      {:error, _reason} = error -> error
    end
  end

  @spec post(String.t(), map(), String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def post(endpoint, body, access_token, context, opts) do
    with {:ok, payload} <- encode(body, context),
         {:ok, response} <- OAuthHTTP.post_credential(endpoint, payload, access_token, opts),
         {:ok, decoded} <- decode(response, context),
         :ok <- response_status(response.status, decoded) do
      {:ok, decoded}
    end
  end

  defp mode(opts) do
    case Keyword.get(opts, :credential_encryption, :auto) do
      mode when mode in [:auto, :required, :disabled] -> {:ok, mode}
      _invalid -> {:error, :invalid_credential_encryption}
    end
  end

  defp metadata_section(metadata, name) do
    case Map.fetch(metadata, name) do
      :error ->
        {:ok, nil}

      {:ok, %{"encryption_required" => required} = section} when is_boolean(required) ->
        {:ok, section}

      _invalid ->
        {:error, :invalid_credential_encryption_metadata}
    end
  end

  defp allowed_mode(:disabled, request, response) do
    if required?(request) or required?(response),
      do: {:error, :credential_encryption_required},
      else: :ok
  end

  defp allowed_mode(_mode, _request, _response), do: :ok

  defp required?(%{"encryption_required" => true}), do: true
  defp required?(_section), do: false

  defp response_context(:disabled, _section, _opts), do: {:ok, nil}

  defp response_context(:required, nil, _opts),
    do: {:error, :missing_response_encryption_metadata}

  defp response_context(_mode, nil, _opts), do: {:ok, nil}

  defp response_context(_mode, section, opts) do
    with :ok <- supported_alg(section),
         {:ok, enc} <- select_enc(section),
         {:ok, private, public} <- response_key(opts) do
      {:ok, %{private: private, public: public, enc: enc}}
    end
  end

  defp supported_alg(%{"alg_values_supported" => algorithms}) when is_list(algorithms) do
    if "ECDH-ES" in algorithms,
      do: :ok,
      else: {:error, :unsupported_credential_encryption_algorithm}
  end

  defp supported_alg(_section), do: {:error, :invalid_credential_encryption_metadata}

  defp select_enc(%{"enc_values_supported" => algorithms}) when is_list(algorithms) do
    case Enum.find(@encs, &(&1 in algorithms)) do
      nil -> {:error, :unsupported_credential_encryption_method}
      enc -> {:ok, enc}
    end
  end

  defp select_enc(_section), do: {:error, :invalid_credential_encryption_metadata}

  defp response_key(opts) do
    key = Keyword.get_lazy(opts, :credential_response_encryption_key, &generate_key/0)

    with {:ok, private} <- AttestoClient.Builder.normalize_key(key),
         {_type, private_map} <- JOSE.JWK.to_map(private),
         true <- valid_private_key?(private_map) do
      {_type, public} = JOSE.JWK.to_public_map(private)
      public = Map.merge(public, %{"alg" => "ECDH-ES", "use" => "enc"})
      {:ok, private, public}
    else
      _invalid -> {:error, :invalid_response_encryption_key}
    end
  rescue
    _error -> {:error, :invalid_response_encryption_key}
  end

  defp generate_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp valid_private_key?(%{"kty" => "EC", "crv" => "P-256", "d" => d} = key),
    do:
      is_binary(d) and d != "" and allowed_key_use?(key) and
        Map.get(key, "alg") in [nil, "ECDH-ES"]

  defp valid_private_key?(_key), do: false

  defp request_context(:disabled, _section, _response), do: {:ok, nil}

  defp request_context(_mode, nil, response) when not is_nil(response),
    do: {:error, :missing_request_encryption_metadata}

  defp request_context(_mode, nil, nil), do: {:ok, nil}

  defp request_context(_mode, section, _response) do
    with {:ok, public} <- select_recipient(section),
         {:ok, enc} <- select_enc(section) do
      {:ok, %{public: public, enc: enc}}
    end
  end

  defp select_recipient(%{"jwks" => %{"keys" => keys}}) when is_list(keys) do
    with :ok <- unambiguous_keys(keys) do
      case Enum.find(keys, &valid_recipient?/1) do
        nil -> {:error, :unsupported_request_encryption_key}
        public -> {:ok, public}
      end
    end
  end

  defp select_recipient(_section), do: {:error, :invalid_credential_encryption_metadata}

  defp unambiguous_keys(keys) do
    if keys != [] and length(keys) <= 128 and Enum.all?(keys, &valid_kid?/1) and
         length(Enum.uniq_by(keys, & &1["kid"])) == length(keys),
       do: :ok,
       else: {:error, :invalid_credential_encryption_metadata}
  end

  defp valid_recipient?(%{"kty" => "EC", "crv" => "P-256", "alg" => "ECDH-ES"} = key) do
    Enum.all?(~w(x y), &(is_binary(key[&1]) and key[&1] != "")) and
      not Enum.any?(@private_fields, &Map.has_key?(key, &1)) and allowed_key_use?(key) and
      valid_kid?(key)
  end

  defp valid_recipient?(_key), do: false

  defp valid_kid?(%{"kid" => kid}), do: is_binary(kid) and byte_size(kid) in 1..256
  defp valid_kid?(_key), do: false

  defp allowed_key_use?(key),
    do: Map.get(key, "use", "enc") == "enc" and valid_key_ops?(Map.get(key, "key_ops"))

  defp valid_key_ops?(nil), do: true

  defp valid_key_ops?(operations) when is_list(operations) and operations != [],
    do: Enum.all?(operations, &(&1 in ~w(deriveKey deriveBits)))

  defp valid_key_ops?(_operations), do: false

  defp encode(body, %{request: nil}), do: {:ok, {:json, body}}

  defp encode(body, %{request: request, response: response}) do
    body = add_response_encryption(body, response)
    header = encryption_header(request.public, request.enc)

    with {:ok, compact} <-
           AttestoClient.CryptoJWE.encrypt(request.public, JSON.encode!(body), header) do
      {:ok, {:jwt, compact}}
    end
  end

  defp add_response_encryption(body, nil), do: body

  defp add_response_encryption(body, response),
    do:
      Map.put(body, "credential_response_encryption", %{
        "jwk" => response.public,
        "enc" => response.enc
      })

  defp encryption_header(public, enc) do
    %{"alg" => "ECDH-ES", "enc" => enc, "cty" => "json"}
    |> maybe_kid(public)
  end

  defp maybe_kid(header, %{"kid" => kid}), do: Map.put(header, "kid", kid)
  defp maybe_kid(header, _key), do: header

  defp decode(%{body: body} = response, %{response: nil}) when is_map(body) do
    if media_type(response.headers) == "application/json",
      do: {:ok, body},
      else: {:error, :invalid_credential_response_content_type}
  end

  defp decode(%{body: body} = response, %{response: context})
       when is_binary(body) and not is_nil(context) do
    with true <- media_type(response.headers) == "application/jwt",
         {:ok, plaintext, header} <-
           AttestoClient.CryptoJWE.decrypt(context.private, body,
             accepted_algs: ["ECDH-ES"],
             accepted_encs: [context.enc],
             max_compact_bytes: @max_bytes,
             max_plaintext_bytes: @max_bytes
           ),
         :ok <- check_response_header(header, context.public),
         {:ok, decoded} <- CredentialJSON.decode(plaintext) do
      {:ok, decoded}
    else
      false -> {:error, :invalid_credential_response_content_type}
      {:error, _reason} = error -> error
    end
  end

  defp decode(_response, %{response: context}) when not is_nil(context),
    do: {:error, :unencrypted_credential_response}

  defp decode(_response, _context), do: {:error, :invalid_credential_response}

  defp check_response_header(header, public) do
    if Map.get(header, "kid") == Map.get(public, "kid"),
      do: :ok,
      else: {:error, :response_encryption_key_mismatch}
  end

  defp media_type(headers) do
    case Map.get(headers, "content-type", []) do
      [type] when is_binary(type) ->
        type |> String.split(";") |> hd() |> String.trim() |> String.downcase()

      _invalid ->
        nil
    end
  end

  defp response_status(status, body) when status in [200, 202] do
    cond do
      Map.has_key?(body, "credentials") and Map.has_key?(body, "transaction_id") ->
        {:error, :invalid_credential_response}

      status == 202 and not Map.has_key?(body, "transaction_id") ->
        {:error, :invalid_deferred_credential_response}

      status == 200 and Map.has_key?(body, "transaction_id") ->
        {:error, :invalid_deferred_credential_response}

      status == 202 ->
        validate_deferred_interval(body)

      true ->
        :ok
    end
  end

  defp response_status(status, body),
    do: {:error, {:oauth_error, status, Map.take(body, ["error", "error_description"])}}

  defp validate_deferred_interval(%{"interval" => interval})
       when is_integer(interval) and interval > 0,
       do: :ok

  defp validate_deferred_interval(_body), do: {:error, :invalid_deferred_interval}
end
