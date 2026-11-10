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
  # Req's default `:receive_timeout`, which its Finch adapter applies per read.
  @receive_timeout 15_000
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
    with :ok <- validate_options(req_options),
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

  @doc false
  @spec validate_options(term()) :: :ok | {:error, :unsafe_transport_options}
  def validate_options(options) when is_list(options) do
    connect = Keyword.get(options, :connect_options, [])
    transport = if is_list(connect), do: Keyword.get(connect, :transport_opts, []), else: nil

    if unique_keyword?(options) and unique_keyword?(connect) and unique_keyword?(transport),
      do: :ok,
      else: {:error, :unsafe_transport_options}
  end

  def validate_options(_options), do: {:error, :unsafe_transport_options}

  @doc false
  @spec bounded_response_into(pos_integer()) :: function()
  def bounded_response_into(max_bytes) when is_integer(max_bytes) and max_bytes > 0 do
    fn {:data, data}, {request, response} ->
      body = if is_binary(response.body), do: response.body, else: ""

      if byte_size(body) + byte_size(data) > max_bytes do
        response = %{
          response
          | body: "",
            private: Map.put(response.private, :attesto_client_response_too_large, true)
        }

        {:halt, {request, response}}
      else
        {:cont, {request, %{response | body: body <> data}}}
      end
    end
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
        secure_transport_options(options)

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
        transport_opts =
          transport_opts
          |> Keyword.drop(@protected_transport_options)
          |> Keyword.put(:verify, :verify_peer)

        {:ok, Keyword.put(options, :transport_opts, transport_opts)}

      _other ->
        {:error, :transport_opts}
    end
  end

  # The URL dials the screened IP. Mint still needs the external host for SNI
  # and certificate verification. A caller-owned Finch pool cannot be combined
  # with per-request connection options, so it is rejected above. An
  # in-process `:plug` replaces the adapter set here.
  defp put_connect_options(options, target, connect_options) do
    options
    |> Keyword.delete(:finch)
    |> Keyword.put(:connect_options, Keyword.put(connect_options, :hostname, target.host))
    |> Keyword.put(:adapter, adapter())
  end

  # Req 0.7 calls `run/1` on an adapter module and deprecates an adapter
  # function; Req 0.6 runs the adapter as a request step function.
  defp adapter do
    case Application.spec(:req, :vsn) do
      [?0, ?., ?6, ?. | _patch] -> &__MODULE__.run/1
      _later -> __MODULE__
    end
  end

  # The Req adapter for every screened request: one Mint connection to the
  # pinned address, closed when the response is complete. Req's Finch adapter
  # starts a Finch instance, with its own registered processes and atoms, for
  # each distinct set of `connect_options`, which here includes the hostname,
  # and never stops it. Hostnames reach this module from untrusted documents,
  # so that state would grow without bound.
  @doc false
  @spec run(Req.Request.t()) :: {Req.Request.t(), Req.Response.t() | Exception.t()}
  def run(%Req.Request{} = request) do
    connect_options = Map.get(request.options, :connect_options, [])
    timeout = Map.get(request.options, :receive_timeout, @receive_timeout)

    with {:ok, conn} <- connect(request.url, connect_options),
         {:ok, conn, ref} <- send_request(conn, request) do
      receive_response(conn, ref, timeout, {:head, request, nil, []})
    else
      {:error, conn, error} ->
        _closed = Mint.HTTP.close(conn)
        {request, normalize_error(error)}

      {:error, error} ->
        {request, normalize_error(error)}
    end
  end

  # Mirrors how Req's Finch adapter turns `connect_options` into Mint options.
  defp connect(%URI{host: address, port: port} = url, connect_options) do
    transport_opts =
      connect_options
      |> Keyword.take([:timeout])
      |> Keyword.merge(Keyword.get(connect_options, :transport_opts, []))

    # URI.parse drops the brackets of an IPv6 literal; Mint needs the family.
    transport_opts =
      if String.contains?(address, ":"),
        do: Keyword.put(transport_opts, :inet6, true),
        else: transport_opts

    protocols =
      Keyword.get_lazy(connect_options, :protocols, fn ->
        connect_options |> Keyword.get(:protocol, :http1) |> List.wrap()
      end)

    mint_options =
      connect_options
      |> Keyword.take([:client_settings])
      |> Keyword.merge(
        hostname: Keyword.fetch!(connect_options, :hostname),
        mode: :passive,
        protocols: protocols,
        transport_opts: transport_opts
      )

    Mint.HTTP.connect(scheme(url), address, port, mint_options)
  end

  defp scheme(%URI{scheme: "https"}), do: :https
  defp scheme(%URI{scheme: "http"}), do: :http

  defp send_request(conn, request) do
    headers = for {name, values} <- request.headers, value <- values, do: {name, value}
    method = request.method |> to_string() |> String.upcase()

    Mint.HTTP.request(conn, method, request_target(request.url), headers, request.body)
  end

  defp request_target(%URI{path: path, query: query}) do
    path = if path in [nil, ""], do: "/", else: path
    if query in [nil, ""], do: path, else: path <> "?" <> query
  end

  defp receive_response(conn, ref, timeout, state) do
    case Mint.HTTP.recv(conn, 0, timeout) do
      {:ok, conn, responses} ->
        case handle_responses(responses, ref, state) do
          {:cont, state} ->
            receive_response(conn, ref, timeout, state)

          {:done, result} ->
            _closed = Mint.HTTP.close(conn)
            result
        end

      {:error, conn, error, _responses} ->
        _closed = Mint.HTTP.close(conn)
        {request_of(state), normalize_error(error)}
    end
  end

  defp handle_responses([], _ref, state), do: {:cont, state}

  defp handle_responses([response | rest], ref, state) do
    case handle_response(response, ref, state) do
      {:cont, state} -> handle_responses(rest, ref, state)
      {:done, _result} = done -> done
    end
  end

  # The state is `{:head, request, status, headers}` until body data arrives,
  # then `{:body, {request, response}}`, the accumulator Req's `:into` takes.
  # A new status line (after a 1xx informational response) starts a new head.
  # Headers arriving after body data are trailers, which no caller reads.
  defp handle_response({:status, ref, status}, ref, {:head, request, _status, _headers}),
    do: {:cont, {:head, request, status, []}}

  defp handle_response({:headers, ref, headers}, ref, {:head, request, status, acc}),
    do: {:cont, {:head, request, status, acc ++ headers}}

  defp handle_response({:data, ref, _data} = data, ref, {:head, request, status, headers}),
    do: handle_response(data, ref, {:body, head(request, status, headers)})

  defp handle_response({:data, ref, data}, ref, {:body, {request, _response} = acc}),
    do: collect(request.into, data, acc)

  defp handle_response({:headers, ref, _trailers}, ref, {:body, _acc} = state),
    do: {:cont, state}

  defp handle_response({:done, ref}, ref, {:head, request, status, headers}),
    do: {:done, head(request, status, headers)}

  defp handle_response({:done, ref}, ref, {:body, acc}), do: {:done, acc}

  defp handle_response({:error, ref, error}, ref, state),
    do: {:done, {request_of(state), normalize_error(error)}}

  # An HTTP/2 server push opens another stream; it is not this response.
  defp handle_response({:push_promise, ref, _promised_ref, _headers}, ref, state),
    do: {:cont, state}

  defp handle_response(response, ref, state) when elem(response, 1) != ref,
    do: {:cont, state}

  defp collect(nil, data, {request, response}),
    do: {:cont, {:body, {request, %{response | body: response.body <> data}}}}

  defp collect(into, data, acc) when is_function(into, 2) do
    case into.({:data, data}, acc) do
      {:cont, acc} -> {:cont, {:body, acc}}
      {:halt, acc} -> {:done, acc}
    end
  end

  defp head(request, status, headers),
    do: {request, Req.Response.new(status: status, headers: headers)}

  defp request_of({:head, request, _status, _headers}), do: request
  defp request_of({:body, {request, _response}}), do: request

  defp normalize_error(%Mint.TransportError{reason: reason}),
    do: %Req.TransportError{reason: reason}

  defp normalize_error(%Mint.HTTPError{module: Mint.HTTP2, reason: reason}),
    do: %Req.HTTPError{protocol: :http2, reason: reason}

  defp normalize_error(%Mint.HTTPError{reason: reason}),
    do: %Req.HTTPError{protocol: :http1, reason: reason}

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

  @doc false
  @spec unique_keyword?(term()) :: boolean()
  def unique_keyword?(options) when is_list(options) do
    Keyword.keyword?(options) and
      options |> Keyword.keys() |> Enum.uniq() |> length() == length(options)
  end

  def unique_keyword?(_options), do: false

  defp active?(value), do: value not in [nil, false]
end
