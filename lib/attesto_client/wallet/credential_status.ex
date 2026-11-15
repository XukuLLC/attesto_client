defmodule AttestoClient.Wallet.CredentialStatus do
  @moduledoc false

  alias Attesto.{JWS, Mdoc, SdJwtVc, StatusList}

  # Detect references in the signed credential itself. A persisted held map
  # may predate status support or omit the derived claims/status fields.
  # Verification precedes every fetch, including when a host supplies a resolver.
  def check(held, opts) do
    with {:ok, status} <- reference(held) do
      if is_nil(status), do: :ok, else: verify(held, opts)
    end
  rescue
    _ -> {:error, :invalid_status_reference}
  catch
    _, _ -> {:error, :status_list_fetch_failed}
  end

  defp reference(%{format: "dc+sd-jwt", credential: credential}) do
    with {:ok, claims} <- JWS.peek_json(hd(:binary.split(credential, "~")), :payload) do
      case Map.fetch(claims, "status") do
        :error -> {:ok, nil}
        {:ok, status} when is_map(status) -> {:ok, status}
        _ -> {:error, :invalid_status_reference}
      end
    end
  end

  defp reference(%{format: "mso_mdoc", credential: credential}), do: Mdoc.peek_status(credential)
  defp reference(_held), do: {:ok, nil}

  defp verify(held, opts) do
    trust = Map.get(held, :issuer_key) || Keyword.get(opts, :trusted)

    verify_opts =
      opts
      |> Keyword.take([:now, :accepted_algs, :trusted_certificates, :haip, :certificate_trust])
      |> Keyword.put(:resolve_status, resolver(opts))
      |> status_trust(held)

    if is_nil(trust) and not Keyword.has_key?(verify_opts, :trusted_certificates) do
      {:error, :missing_status_trust}
    else
      result =
        case held.format do
          "dc+sd-jwt" -> SdJwtVc.verify(held.credential, trust, verify_opts)
          "mso_mdoc" -> Mdoc.verify(held.credential, trust, verify_opts)
        end

      case result do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  defp status_trust(opts, %{issuer_trusted_certificates: anchors}) do
    opts
    |> Keyword.put(:status_trusted_certificates, anchors)
    |> Keyword.put(:issuer_identity, :certificate)
  end

  defp status_trust(opts, _held), do: opts

  def resolver(opts) do
    case Keyword.fetch(opts, :resolve_status) do
      :error -> &StatusList.fetch/2
      {:ok, fun} when is_function(fun, 1) or is_function(fun, 2) -> fun
      _ -> fn _, _ -> {:error, :invalid_status_resolver} end
    end
  end
end
