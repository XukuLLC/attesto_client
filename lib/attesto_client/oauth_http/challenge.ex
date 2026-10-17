defmodule AttestoClient.OAuthHTTP.Challenge do
  @moduledoc false

  alias AttestoClient.Wallet.CredentialJSON

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

  defp dpop_authenticate_error(response) do
    response
    |> Req.Response.get_header("www-authenticate")
    |> Enum.find_value(fn header -> if dpop_nonce_error?(header), do: "use_dpop_nonce" end)
  end

  defp dpop_nonce_error?(header) when is_binary(header) do
    header
    |> auth_header_parts()
    |> Enum.reduce_while(nil, &reduce_auth_header_part/2)
    |> Kernel.==(true)
  end

  defp dpop_nonce_error?(_invalid), do: false

  defp reduce_auth_header_part(part, scheme) do
    case auth_header_part(part) do
      {:challenge, next_scheme, params} -> auth_header_result(next_scheme, params)
      {:params, params} -> auth_header_result(scheme, params)
    end
  end

  defp auth_header_result(scheme, params) do
    if dpop_scheme?(scheme) and dpop_nonce_error_param?(params),
      do: {:halt, true},
      else: {:cont, scheme}
  end

  defp auth_header_parts(header), do: split_auth_header(header, false, false, [], [])

  defp split_auth_header(<<>>, _quoted?, _escaped?, current, parts) do
    [current |> Enum.reverse() |> IO.iodata_to_binary() | parts]
    |> Enum.reverse()
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp split_auth_header(<<?,, rest::binary>>, false, _escaped?, current, parts) do
    part = current |> Enum.reverse() |> IO.iodata_to_binary()
    split_auth_header(rest, false, false, [], [part | parts])
  end

  defp split_auth_header(<<?", rest::binary>>, quoted?, false, current, parts),
    do: split_auth_header(rest, not quoted?, false, [?" | current], parts)

  defp split_auth_header(<<?\\, rest::binary>>, true, false, current, parts),
    do: split_auth_header(rest, true, true, [?\\ | current], parts)

  defp split_auth_header(<<char, rest::binary>>, quoted?, _escaped?, current, parts),
    do: split_auth_header(rest, quoted?, false, [char | current], parts)

  defp auth_header_part(part) do
    case Regex.run(~r/^([!#$%&'*+\-.^_`|~0-9A-Za-z]+)(.*)$/s, part, capture: :all_but_first) do
      [token, rest] ->
        rest = String.trim_leading(rest)
        if String.starts_with?(rest, "="), do: {:params, part}, else: {:challenge, token, rest}

      _invalid ->
        {:params, part}
    end
  end

  defp dpop_scheme?(scheme) when is_binary(scheme), do: String.downcase(scheme) == "dpop"
  defp dpop_scheme?(_other), do: false

  defp dpop_nonce_error_param?(params) do
    Regex.match?(~r/^\s*(?i:error)\s*=\s*(?:"use_dpop_nonce"|use_dpop_nonce)\s*$/, params)
  end
end
