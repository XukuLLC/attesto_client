defmodule AttestoClient.PinnedRequest do
  @moduledoc false

  @destination_options [
    :adapter,
    :url,
    :method,
    :body,
    :base_url,
    :params,
    :path_params,
    :path_params_style,
    :form,
    :form_multipart,
    :json,
    :compress_body,
    :compressed,
    :range,
    :checksum,
    :aws_sigv4,
    :plugins,
    :finch_request,
    :into,
    :raw,
    :decode_body,
    :decode_json,
    :decoders,
    :http_errors,
    :output,
    :follow_redirects,
    :cache,
    :cache_dir
  ]
  @protected_transport_options [
    :cb_info,
    :server_name_indication,
    :verify_fun,
    :customize_hostname_check,
    :partial_chain
  ]
  @transport_headers ~w(
    accept-encoding
    connection
    content-encoding
    content-length
    host
    keep-alive
    proxy-authenticate
    proxy-authorization
    te
    trailer
    transfer-encoding
    upgrade
  )

  @type target :: %{
          required(:url) => String.t(),
          required(:host) => String.t(),
          required(:authority) => String.t()
        }

  @spec prepare(target(), keyword(), [String.t()], [atom()]) ::
          {:ok, keyword()} | {:error, :unsafe_transport_options}
  def prepare(target, req_options, reserved_headers \\ [], reserved_options \\ [])

  def prepare(
        %{url: url, host: host, authority: authority} = target,
        req_options,
        reserved_headers,
        reserved_options
      )
      when is_binary(url) and is_binary(host) and is_binary(authority) and
             is_list(req_options) and is_list(reserved_headers) and is_list(reserved_options) do
    with true <- unique_keyword?(req_options),
         {:ok, connect_options} <- connect_options(req_options),
         :ok <- safe_destination_options(target, req_options, connect_options) do
      headers =
        req_options
        |> Keyword.get(:headers, [])
        |> sanitize_headers(@transport_headers ++ reserved_headers)
        |> List.insert_at(0, {"host", authority})

      options =
        req_options
        |> Keyword.drop(@destination_options ++ reserved_options ++ [:unix_socket])
        |> Keyword.put(:headers, headers)

      {:ok, put_connect_options(options, target, connect_options)}
    else
      _unsafe -> {:error, :unsafe_transport_options}
    end
  end

  def prepare(_target, _req_options, _reserved_headers, _reserved_options),
    do: {:error, :unsafe_transport_options}

  # Build from Req's bare pipeline rather than Req.new/1. The latter merges
  # application-wide defaults, which could reintroduce a proxy, custom Finch,
  # AWS signer, authentication value, or URL mutation after screening.
  @spec new(keyword()) :: Req.Request.t()
  def new(options) when is_list(options) do
    Req.Request.new()
    |> Req.Steps.attach()
    |> Req.merge(options)
  end

  defp safe_destination_options(_target, req_options, connect_options) do
    in_process? = active?(Keyword.get(req_options, :plug))

    cond do
      active?(Keyword.get(req_options, :unix_socket)) ->
        {:error, :unix_socket}

      not in_process? and active?(Keyword.get(connect_options, :proxy)) ->
        {:error, :proxy}

      not in_process? and active?(Keyword.get(req_options, :finch)) ->
        {:error, :custom_finch}

      not in_process? and active?(Keyword.get(req_options, :adapter)) ->
        {:error, :custom_adapter}

      true ->
        :ok
    end
  end

  defp connect_options(req_options) do
    case Keyword.get(req_options, :connect_options, []) do
      options when is_list(options) ->
        if unique_keyword?(options),
          do: secure_transport_options(options),
          else: {:error, :connect_options}

      _other ->
        {:error, :connect_options}
    end
  end

  # Preserve legitimate trust-store and client-certificate configuration, but
  # do not let request options disable peer verification or replace the host
  # identity used by TLS. Mint derives SNI and hostname verification from the
  # protected `connect_options[:hostname]` installed below.
  defp secure_transport_options(options) do
    case Keyword.fetch(options, :transport_opts) do
      :error ->
        {:ok, options}

      {:ok, transport_opts} when is_list(transport_opts) ->
        if unique_keyword?(transport_opts) do
          transport_opts =
            transport_opts
            |> Keyword.drop(@protected_transport_options)
            |> Keyword.put(:verify, :verify_peer)

          {:ok, Keyword.put(options, :transport_opts, transport_opts)}
        else
          {:error, :transport_opts}
        end

      _other ->
        {:error, :transport_opts}
    end
  end

  # A rewritten URL dials the screened IP. Mint still needs the external host
  # for SNI and certificate verification. A caller-owned Finch pool cannot be
  # combined with per-request connection options, so it is rejected above.
  defp put_connect_options(options, target, connect_options) do
    cond do
      rewritten?(target) ->
        options
        |> Keyword.delete(:finch)
        |> Keyword.put(:connect_options, Keyword.put(connect_options, :hostname, target.host))

      connect_options != [] and not active?(Keyword.get(options, :finch)) ->
        Keyword.put(
          options,
          :connect_options,
          Keyword.put(connect_options, :hostname, target.host)
        )

      true ->
        options
    end
  end

  defp rewritten?(%{url: url, host: host}) do
    case URI.new(url) do
      {:ok, %URI{host: request_host}} -> request_host != host
      _error -> true
    end
  end

  defp sanitize_headers(headers, reserved) when is_list(headers) or is_map(headers) do
    reserved = MapSet.new(reserved, &String.downcase/1)

    Enum.reject(headers, fn
      {name, _value} -> MapSet.member?(reserved, normalize_header_name(name))
      _malformed -> false
    end)
  end

  defp sanitize_headers(_headers, _reserved), do: []

  defp normalize_header_name(name) when is_atom(name) do
    name
    |> Atom.to_string()
    |> String.replace("_", "-")
    |> String.downcase()
  end

  defp normalize_header_name(name) do
    name
    |> to_string()
    |> String.replace("_", "-")
    |> String.downcase()
  end

  defp unique_keyword?(options) do
    Keyword.keyword?(options) and
      options |> Keyword.keys() |> Enum.uniq() |> length() == length(options)
  end

  defp active?(value), do: value not in [nil, false]
end
