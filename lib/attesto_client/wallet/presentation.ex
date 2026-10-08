defmodule AttestoClient.Wallet.Presentation do
  @moduledoc """
  OID4VP 1.0 wallet presentations for SD-JWT VC and ISO mdoc.

  `present/3` selects credentials satisfying a verified request, builds holder
  proofs, and submits the response. `direct_post.jwt` encrypts the complete
  response to a public key from authenticated client metadata. The encryption
  key also binds the mdoc session transcript. `direct_post` remains supported.

  Requested nested claims, claim alternatives, and credential sets are evaluated
  before disclosure. An explicit `:selection` remains subject to those constraints.
  Omitted claim queries disclose no selectively disclosable claims; otherwise
  only requested disclosures and their necessary parents are included. Public
  issuer claims remain visible because they cannot be removed from the signed credential.
  Aggregate VP-token data and the encoded response are bounded to 1 MiB,
  including caller-built responses, before encryption or HTTP submission.
  Both response modes use nonempty presentation arrays. The verifier must
  advertise the selected format in `vp_formats_supported`; any advertised
  issuer/holder algorithm lists also constrain generation and submission.
  `build_response/3` checks those advertisements and the response envelope;
  it does not replace credential signature verification during issuance.

  The host owns consent, credential storage, issuer trust and browser navigation.
  A successful response may contain `redirect_uri`; the host must open it in the
  user's browser, rather than fetch it as a back-channel HTTP request.
  """

  alias Attesto.{JWS, Thumbprint}
  alias AttestoClient.{Builder, OAuthHTTP}
  alias AttestoClient.Wallet.Presentation.{DCQL, Disclosures, Encryption, Formats, Mdoc}
  alias AttestoClient.Wallet.PresentationRequest

  @max_response_bytes 1_048_576

  @type opt ::
          {:selection, map()}
          | {:holder_keys, map()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, integer()}
          | {:req_options, keyword()}
          | {:timeout, pos_integer()}

  @doc "Select held credentials satisfying a DCQL query."
  def select(query, held), do: DCQL.select(query, held)

  @doc "Select, build and submit presentations. The host must obtain user consent first."
  def present(%PresentationRequest{} = request, held, opts \\ [])
      when is_list(held) and is_list(opts) do
    with :ok <- Formats.validate(request.client_metadata),
         {:ok, selection} <- selection(request, held, opts),
         {:ok, vp_token} <- build_vp_token(selection, request, opts) do
      submit(request, vp_token, opts)
    end
  end

  defp selection(request, held, opts) do
    case Keyword.get(opts, :selection) do
      nil -> select(request.dcql_query, held)
      %{} = selected -> {:ok, selected}
      _ -> {:error, :invalid_selection}
    end
  end

  @doc "Build presentations without sending them. Entries are nonempty arrays in both response modes."
  def build_vp_token(selection, %PresentationRequest{} = request, opts \\ [])
      when is_map(selection) and is_list(opts) do
    with :ok <- PresentationRequest.validate_bindings(request),
         {:ok, encryption} <- Encryption.context(request),
         :ok <- Formats.validate(request.client_metadata),
         :ok <- DCQL.validate_selection(request.dcql_query, selection) do
      Enum.reduce_while(selection, {:ok, %{}}, &accumulate(&1, &2, request, encryption, opts))
    end
  end

  defp accumulate({id, held}, {:ok, acc}, request, encryption, opts) do
    case build_one(id, held, request, encryption, opts) do
      {:ok, value} ->
        updated = Map.put(acc, id, [value])

        if bounded_entries?(updated),
          do: {:cont, {:ok, updated}},
          else: {:halt, {:error, :response_too_large}}

      {:error, reason} ->
        {:halt, {:error, {id, reason}}}
    end
  end

  @doc "Submit an already-built response. Encrypted mode never sends credentials or state in plaintext."
  def submit(%PresentationRequest{} = request, vp_token, opts \\ [])
      when is_map(vp_token) and is_list(opts) do
    with {:ok, form} <- build_response(request, vp_token, opts) do
      OAuthHTTP.post_form_open(request.response_uri, form, opts)
    end
  end

  @doc "Build the form body without network access, including an encrypted response when requested."
  def build_response(%PresentationRequest{} = request, vp_token, opts \\ [])
      when is_map(vp_token) and is_list(opts) do
    with :ok <- PresentationRequest.validate_bindings(request),
         {:ok, encryption} <- Encryption.context(request),
         :ok <- Formats.validate(request.client_metadata),
         :ok <- DCQL.validate(request.dcql_query),
         :ok <- valid_response(vp_token, request),
         :ok <- DCQL.validate_response_ids(request.dcql_query, Map.keys(vp_token)),
         :ok <- Formats.check_response(request.client_metadata, request.dcql_query, vp_token) do
      response_form(request, vp_token, encryption)
    end
  end

  defp response_form(request, vp_token, nil) do
    with {:ok, encoded} <- encode_response(vp_token, byte_size(request.state || "")),
         do: {:ok, %{"vp_token" => encoded} |> put_optional("state", request.state)}
  end

  defp response_form(request, vp_token, encryption) do
    payload = %{"vp_token" => vp_token} |> put_optional("state", request.state)

    with {:ok, encoded} <- encode_response(payload),
         {:ok, compact} <- Encryption.encrypt(encryption, encoded),
         do: {:ok, %{"response" => compact}}
  end

  defp encode_response(payload, additional_bytes \\ 0) do
    encoded = JSON.encode!(payload)

    if byte_size(encoded) + additional_bytes <= @max_response_bytes,
      do: {:ok, encoded},
      else: {:error, :response_too_large}
  end

  defp valid_response(vp_token, request) do
    queries = Map.new(request.dcql_query["credentials"], &{&1["id"], &1})

    valid =
      map_size(vp_token) > 0 and
        Enum.all?(vp_token, fn {id, value} ->
          Map.has_key?(queries, id) and valid_entry?(value, request.response_mode, queries[id])
        end)

    cond do
      not valid -> {:error, :invalid_vp_token}
      not bounded_entries?(vp_token) -> {:error, :response_too_large}
      true -> :ok
    end
  end

  defp bounded_entries?(vp_token) do
    Enum.reduce_while(vp_token, 0, fn {id, value}, total ->
      bytes = byte_size(id) + entry_bytes(value)
      updated = total + bytes
      if updated <= @max_response_bytes, do: {:cont, updated}, else: {:halt, :too_large}
    end) != :too_large
  end

  defp entry_bytes(value) when is_binary(value), do: byte_size(value)

  defp entry_bytes(values) when is_list(values) do
    Enum.reduce_while(values, 0, fn value, total ->
      updated = total + byte_size(value)

      if updated <= @max_response_bytes,
        do: {:cont, updated},
        else: {:halt, @max_response_bytes + 1}
    end)
  end

  defp valid_entry?(values, mode, query)
       when mode in ["direct_post", "direct_post.jwt"] and is_list(values) and values != [],
       do:
         (length(values) == 1 or query["multiple"] == true) and
           Enum.all?(values, &valid_presentation?/1)

  defp valid_entry?(_value, _mode, _query), do: false

  defp valid_presentation?(value),
    do: is_binary(value) and byte_size(value) in 1..1_048_576 and String.valid?(value)

  defp build_one(id, held, request, encryption, opts) do
    with {:ok, key} <- holder_key(id, opts),
         :ok <- check_holder_key(key, held),
         :ok <- Formats.check_credential(request.client_metadata, held, key, opts) do
      query = Enum.find(request.dcql_query["credentials"], &(&1["id"] == id))
      paths = DCQL.paths(query, held)
      build_credential(held, request, key, paths, encryption, opts)
    end
  end

  defp holder_key(id, opts) do
    case Keyword.get(opts, :holder_keys) do
      keys when is_map(keys) ->
        case Map.fetch(keys, id) do
          {:ok, key} -> {:ok, key}
          :error -> {:error, :missing_holder_key}
        end

      _ ->
        {:error, :missing_holder_keys}
    end
  end

  defp check_holder_key(key, held) do
    with {:ok, jwk} <- Builder.normalize_key(key),
         {:ok, bound} <- binding_key(held),
         {:ok, actual} <- jwk |> Builder.public_jwk() |> Thumbprint.of_jwk(),
         {:ok, expected} <- Thumbprint.of_jwk(bound) do
      if actual == expected, do: :ok, else: {:error, :holder_key_mismatch}
    end
  end

  defp binding_key(%{holder_binding: %{"jwk" => key}}) when is_map(key), do: {:ok, key}
  defp binding_key(%{format: "mso_mdoc", holder_binding: key}) when is_map(key), do: {:ok, key}
  defp binding_key(_held), do: {:error, :missing_holder_binding}

  defp build_credential(%{format: format} = held, request, key, paths, _encryption, opts)
       when format in ["dc+sd-jwt", "vc+sd-jwt"] do
    with {:ok, filtered, hash_alg} <- Disclosures.filter(held.credential, paths),
         {:ok, jwk} <- Builder.normalize_key(key),
         {:ok, alg} <- Builder.resolve_alg(jwk, opts) do
      claims = %{
        "nonce" => request.nonce,
        "aud" => request.client_id,
        "iat" => Builder.now(opts),
        "sd_hash" => :crypto.hash(hash_alg, filtered) |> JWS.encode64()
      }

      header = %{"alg" => alg, "typ" => "kb+jwt"} |> Builder.put_kid(jwk, opts)
      with {:ok, jwt} <- Builder.sign(jwk, header, claims), do: {:ok, filtered <> jwt}
    end
  end

  defp build_credential(%{format: "mso_mdoc"} = held, request, key, paths, encryption, opts) do
    opts = Keyword.put(opts, :claim_paths, paths)

    opts =
      if encryption, do: Keyword.put(opts, :response_encryption_jwk, encryption.key), else: opts

    Mdoc.build_device_response(held, request, key, opts)
  end

  defp build_credential(_held, _request, _key, _paths, _encryption, _opts),
    do: {:error, :unsupported_format}

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)
end
