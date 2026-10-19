defmodule AttestoClient.OAuthHTTP.Challenge do
  @moduledoc false

  alias AttestoClient.Wallet.CredentialJSON
  alias AttestoClient.WWWAuthenticate

  @spec attestation_error?(Req.Response.t()) :: boolean()
  def attestation_error?(%Req.Response{
        status: 400,
        body: %{"error" => "use_attestation_challenge"}
      }),
      do: true

  def attestation_error?(_response), do: false

  @spec attestation(Req.Response.t()) :: String.t() | nil
  def attestation(response) do
    case Req.Response.get_header(response, "oauth-client-attestation-challenge") do
      [challenge] when is_binary(challenge) and byte_size(challenge) in 1..1024 -> challenge
      _other -> nil
    end
  end

  @spec dpop_nonce_challenge?(Req.Response.t()) :: boolean()
  def dpop_nonce_challenge?(%Req.Response{status: status} = response) when status in [400, 401] do
    dpop_error(response) == "use_dpop_nonce" and dpop_nonce(response) != nil
  end

  def dpop_nonce_challenge?(_response), do: false

  @spec dpop_nonce(Req.Response.t()) :: String.t() | nil
  def dpop_nonce(%Req.Response{} = response) do
    case Req.Response.get_header(response, "dpop-nonce") do
      [nonce | _] when is_binary(nonce) and nonce != "" -> nonce
      _ -> nil
    end
  end

  defp dpop_error(%Req.Response{body: %{"error" => error}}) when is_binary(error), do: error

  defp dpop_error(%Req.Response{body: body} = response) when is_binary(body) do
    case CredentialJSON.decode(body) do
      {:ok, %{"error" => error}} when is_binary(error) -> error
      _other -> dpop_authenticate_error(response)
    end
  end

  defp dpop_error(%Req.Response{} = response), do: dpop_authenticate_error(response)

  # RFC 9449 §8: the nonce demand arrives as a DPoP challenge carrying
  # error="use_dpop_nonce". Only a DPoP-scheme challenge counts; a Bearer
  # challenge, or the same text inside another parameter's value, does not.
  defp dpop_authenticate_error(response) do
    nonce_required? =
      response
      |> Req.Response.get_header("www-authenticate")
      |> WWWAuthenticate.parse()
      |> Enum.any?(&(&1.scheme == "dpop" and &1.params["error"] == "use_dpop_nonce"))

    if nonce_required?, do: "use_dpop_nonce"
  end
end
