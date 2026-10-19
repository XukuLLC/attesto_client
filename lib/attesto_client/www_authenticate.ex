defmodule AttestoClient.WWWAuthenticate do
  @moduledoc """
  Read `WWW-Authenticate` challenges (RFC 9110 §11.6.1).

  A resource server refuses a request with one or more challenges: an
  authentication scheme followed by auth-params, or by a single token68 value.
  A client reads them to learn which scheme the resource accepts, why a
  credential was refused (RFC 6750 §3), whether a DPoP nonce must be fetched
  (RFC 9449 §8), or where the resource publishes its metadata (RFC 9728 §5.1,
  the `resource_metadata` parameter).

  `parse/1` takes one header value, or the list `Plug.Conn.get_resp_header/2`
  and `Req.Response.get_header/2` return, and reads every challenge in it.
  Scheme and parameter names are case-insensitive, so they are returned
  lowercased; quoted parameter values are returned unquoted. A malformed list
  member is skipped rather than failing the header, and a value over 8 KiB is
  read as no challenges at all.
  """

  @max_header_bytes 8_192
  @token ~r/^([!#$%&'*+\-.^_`|~0-9A-Za-z]+)(.*)$/s
  @bare_token ~r/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/
  @token68 ~r/^[A-Za-z0-9\-._~+\/]+=*$/

  @typedoc """
  One challenge: its scheme, its auth-params, and the token68 value it carries
  when it has one instead of parameters.
  """
  @type challenge :: %{
          scheme: String.t(),
          params: %{optional(String.t()) => String.t()},
          token68: String.t() | nil
        }

  @doc """
  Parse one `WWW-Authenticate` value, or a list of them, into challenges.

      iex> AttestoClient.WWWAuthenticate.parse(~s(Bearer realm="api", error="invalid_token", DPoP algs="ES256"))
      [
        %{scheme: "bearer", params: %{"realm" => "api", "error" => "invalid_token"}, token68: nil},
        %{scheme: "dpop", params: %{"algs" => "ES256"}, token68: nil}
      ]

  A parameter repeated within one challenge keeps its first value. A parameter
  that precedes any scheme belongs to no challenge and is dropped.
  """
  @spec parse(String.t() | [String.t()] | term()) :: [challenge()]
  def parse(values) when is_list(values), do: Enum.flat_map(values, &parse/1)

  def parse(header) when is_binary(header) and byte_size(header) <= @max_header_bytes do
    if String.valid?(header) do
      header
      |> split_members()
      |> Enum.reduce([], &add_member/2)
      |> Enum.reverse()
      |> Enum.map(&finish/1)
    else
      []
    end
  end

  def parse(_other), do: []

  @doc """
  The RFC 9728 §5.1 `resource_metadata` URL advertised by the first challenge
  that carries a valid one, read from a header value, a list of values, or
  challenges already parsed.

  Only an absolute `https` URL without userinfo or fragment is returned, since
  the client will fetch it; a challenge advertising anything else is skipped.

      iex> AttestoClient.WWWAuthenticate.resource_metadata(
      ...>   ~s(Bearer resource_metadata="https://rs.example/.well-known/oauth-protected-resource/mcp")
      ...> )
      {:ok, "https://rs.example/.well-known/oauth-protected-resource/mcp"}
  """
  @spec resource_metadata(String.t() | [String.t()] | [challenge()]) :: {:ok, String.t()} | :error
  def resource_metadata(values) do
    values
    |> challenges()
    |> Enum.find_value(:error, &metadata_pointer/1)
  end

  defp metadata_pointer(%{params: %{"resource_metadata" => url}}) do
    if Attesto.URI.https_identifier?(url), do: {:ok, url}
  end

  defp metadata_pointer(_challenge), do: nil

  defp challenges([%{scheme: _scheme} | _rest] = parsed), do: parsed
  defp challenges(values), do: parse(values)

  # Split the field on the commas outside quoted strings. A backslash inside a
  # quoted string escapes the next character (RFC 9110 §5.6.4), so an escaped
  # quote neither closes the string nor lets a comma inside it split the member.
  defp split_members(header), do: split_members(header, false, [], [])

  defp split_members(<<>>, _quoted?, current, members),
    do: Enum.reverse([member(current) | members])

  defp split_members(<<?,, rest::binary>>, false, current, members),
    do: split_members(rest, false, [], [member(current) | members])

  defp split_members(<<?\\, char, rest::binary>>, true, current, members),
    do: split_members(rest, true, [char, ?\\ | current], members)

  defp split_members(<<?", rest::binary>>, quoted?, current, members),
    do: split_members(rest, not quoted?, [?" | current], members)

  defp split_members(<<char, rest::binary>>, quoted?, current, members),
    do: split_members(rest, quoted?, [char | current], members)

  defp member(chars), do: chars |> Enum.reverse() |> IO.iodata_to_binary() |> String.trim()

  defp add_member("", acc), do: acc

  defp add_member(member, acc) do
    case classify(member) do
      {:param, name, value} -> put_param(acc, name, value)
      {:scheme, scheme, ""} -> [new(scheme) | acc]
      {:scheme, scheme, payload} -> [scheme_payload(new(scheme), payload) | acc]
      :invalid -> acc
    end
  end

  defp new(scheme), do: %{scheme: scheme, params: [], token68: nil}

  defp put_param([current | rest], name, value),
    do: [%{current | params: [{name, value} | current.params]} | rest]

  defp put_param([], _name, _value), do: []

  # What follows a scheme on the same member is either its token68 value or
  # its first auth-param. A token68 value may end in `=` padding, which is why
  # it is recognized before the `name=value` reading.
  defp scheme_payload(challenge, payload) do
    if Regex.match?(@token68, payload) do
      %{challenge | token68: payload}
    else
      case classify(payload) do
        {:param, name, value} -> %{challenge | params: [{name, value}]}
        _other -> challenge
      end
    end
  end

  defp classify(member) do
    case Regex.run(@token, member, capture: :all_but_first) do
      [name, ""] ->
        {:scheme, String.downcase(name), ""}

      [name, rest] ->
        trimmed = String.trim_leading(rest)

        cond do
          String.starts_with?(trimmed, "=") ->
            param(
              name,
              trimmed |> binary_part(1, byte_size(trimmed) - 1) |> String.trim_leading()
            )

          # Whitespace separated a scheme from what follows it.
          trimmed != rest ->
            {:scheme, String.downcase(name), trimmed}

          true ->
            :invalid
        end

      nil ->
        :invalid
    end
  end

  defp param(name, <<?", rest::binary>>),
    do: {:param, String.downcase(name), unquote_string(rest, [])}

  defp param(name, raw) do
    if Regex.match?(@bare_token, raw), do: {:param, String.downcase(name), raw}, else: :invalid
  end

  # The closing quote ends the value; anything after it is ignored. An unclosed
  # string runs to the end of the member.
  defp unquote_string(<<>>, acc), do: finish_value(acc)
  defp unquote_string(<<?", _rest::binary>>, acc), do: finish_value(acc)
  defp unquote_string(<<?\\, char, rest::binary>>, acc), do: unquote_string(rest, [char | acc])
  defp unquote_string(<<char, rest::binary>>, acc), do: unquote_string(rest, [char | acc])

  defp finish_value(acc), do: acc |> Enum.reverse() |> IO.iodata_to_binary()

  defp finish(%{params: params} = challenge) do
    params =
      params
      |> Enum.reverse()
      |> Enum.reduce(%{}, fn {name, value}, acc -> Map.put_new(acc, name, value) end)

    %{challenge | params: params}
  end
end
