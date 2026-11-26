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
          required(:addresses) => [:inet.ip_address()],
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
    |> Req.Request.register_options([:attesto_target, :attesto_body_limit, :attesto_context])
    |> Req.Steps.attach()
    |> Req.merge(options)
  end

  @doc false
  @spec extract_options(keyword()) :: {:ok, keyword()} | {:error, :unsafe_transport_options}
  def extract_options(opts) when is_list(opts) do
    case Keyword.get(opts, :req_options, []) do
      request_opts when is_list(request_opts) ->
        with :ok <- validate_options(request_opts), do: {:ok, request_opts}

      _invalid ->
        {:error, :unsafe_transport_options}
    end
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

  # The adapter carries every screened IP. Mint still needs the external host for SNI
  # and certificate verification. A caller-owned Finch pool cannot be combined
  # with per-request connection options, so it is rejected above. An
  # in-process `:plug` replaces the adapter set here.
  defp put_connect_options(options, target, connect_options) do
    connect_options = protocol_connect_options(target, connect_options)

    options
    |> Keyword.delete(:finch)
    |> Keyword.put(:connect_options, Keyword.put(connect_options, :hostname, target.host))
    |> Keyword.put(:attesto_target, target)
    |> Keyword.put(:adapter, adapter())
  end

  # TLS trust options are meaningful only to the SSL transport. Passing them
  # to a loopback HTTP connection makes Mint hand `:verify` to `:gen_tcp`,
  # which rejects the socket options before a byte can be written. HTTP is
  # permitted only by the separately enforced loopback policy; remove the TLS
  # sub-options while retaining connection timeouts and the pinned hostname.
  defp protocol_connect_options(%{url: url}, connect_options) do
    case URI.new(url) do
      {:ok, %URI{scheme: "http"}} -> Keyword.delete(connect_options, :transport_opts)
      _https_or_invalid -> connect_options
    end
  end

  # Req 0.7 calls `run/1` on an adapter module and deprecates an adapter
  # function; Req 0.6 runs the adapter as a request step function.
  defp adapter do
    case Application.spec(:req, :vsn) do
      [?0, ?., ?6, ?. | _patch] -> &__MODULE__.run/1
      _later -> __MODULE__
    end
  end

  # The Req adapter for every screened request. Connections are delegated to `Attesto.PinnedHTTP.passive_request/2`
  # so a connection is closed as soon as the response completes. Req's Finch
  # adapter starts a Finch instance, with its own registered processes and
  # atoms, for each distinct set of `connect_options`, which here includes the
  # hostname, and never stops it. Hostnames reach this module from untrusted
  # documents, so that state would grow without bound.
  @doc false
  @spec run(Req.Request.t()) :: {Req.Request.t(), Req.Response.t() | Exception.t()}
  def run(%Req.Request{} = request) do
    connect_options = Map.get(request.options, :connect_options, [])
    timeout = Map.get(request.options, :receive_timeout, @receive_timeout)

    context =
      Map.get(request.options, :attesto_context) ||
        AttestoClient.Deadline.context(if(timeout == :infinity, do: 15_000, else: timeout))

    deadline = context.deadline
    headers = for {name, values} <- request.headers, value <- values, do: {name, value}

    on_head = fn status, resp_headers ->
      {request, Req.Response.new(status: status, headers: resp_headers)}
    end

    on_data = fn data, {req, _response} = acc ->
      collect(req.into, data, acc)
    end

    AttestoClient.Deadline.connecting(context)

    case Attesto.PinnedHTTP.passive_request(
           Map.fetch!(request.options, :attesto_target),
           method: request.method,
           headers: headers,
           body: request.body,
           deadline: deadline,
           receive_timeout: timeout,
           connect_timeout: Keyword.get(connect_options, :timeout, 3_000),
           connect_options: connect_options,
           body_limit: Map.get(request.options, :attesto_body_limit, 2_000_000),
           on_request: fn -> AttestoClient.Deadline.sending(context, request.method) end,
           on_head: on_head,
           on_data: on_data
         ) do
      {:ok, result} -> result
      {:error, reason} -> {request, normalize_error(reason, context)}
    end
  end

  defp collect(nil, data, {request, response}),
    do: {:cont, {request, %{response | body: response.body <> data}}}

  defp collect(into, data, acc) when is_function(into, 2),
    do: into.({:data, data}, acc)

  defp normalize_error({:not_sent, cause}, context) do
    reason =
      case AttestoClient.Deadline.not_sent(context, cause) do
        :not_sent -> {:not_sent, cause}
        :timeout -> :request_timeout
        :transport_error -> :transport_error
      end

    %Req.TransportError{reason: reason}
  end

  defp normalize_error({:maybe_sent, :deadline_exceeded}, _context),
    do: %Req.TransportError{reason: :request_timeout}

  defp normalize_error({:maybe_sent, {:transport, reason}}, _context),
    do: %Req.TransportError{reason: reason}

  defp normalize_error({:maybe_sent, {:http, protocol, reason}}, _context),
    do: %Req.HTTPError{protocol: protocol, reason: reason}

  defp normalize_error({:maybe_sent, cause}, _context),
    do: %Req.TransportError{reason: cause}

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
