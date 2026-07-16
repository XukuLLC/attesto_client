defmodule AttestoClient.OAuthHTTP do
  @moduledoc false

  alias AttestoClient.ClientAssertion
  alias AttestoClient.Deadline

  @default_timeout_ms 10_000

  @spec post_form(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def post_form(endpoint, form, opts) when is_map(form) and is_list(opts) do
    with :ok <- AttestoClient.Discovery.validate_endpoint(endpoint),
         {:ok, form, req_options} <- authenticate(form, endpoint, opts),
         {:ok, timeout_ms} <- timeout(opts) do
      Deadline.run(
        fn -> request(endpoint, form, req_options, timeout_ms, :json) end,
        timeout_ms
      )
    end
  end

  @spec post_form_unit(String.t(), map(), keyword()) :: :ok | {:error, term()}
  def post_form_unit(endpoint, form, opts) when is_map(form) and is_list(opts) do
    with :ok <- AttestoClient.Discovery.validate_endpoint(endpoint),
         {:ok, form, req_options} <- authenticate(form, endpoint, opts),
         {:ok, timeout_ms} <- timeout(opts) do
      Deadline.run(
        fn -> request(endpoint, form, req_options, timeout_ms, :unit) end,
        timeout_ms
      )
    end
  end

  defp authenticate(form, endpoint, opts) do
    client_id = Keyword.get(opts, :client_id)
    authenticate_as(Keyword.get(opts, :client_auth, :none), client_id, form, endpoint, opts)
  end

  defp authenticate_as(:none, client_id, form, _endpoint, opts)
       when is_binary(client_id) and client_id != "" do
    {:ok, Map.put(form, "client_id", client_id), req_options(opts)}
  end

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

  defp authenticate_as({:private_key_jwt, jwk, assertion_opts}, client_id, form, endpoint, opts)
       when is_binary(client_id) and client_id != "" and is_list(assertion_opts) do
    with {:ok, build_opts} <- client_assertion_options(assertion_opts, client_id, endpoint) do
      case ClientAssertion.build(jwk, build_opts) do
        {:ok, assertion} ->
          {:ok,
           Map.merge(form, %{
             "client_id" => client_id,
             "client_assertion_type" => ClientAssertion.assertion_type(),
             "client_assertion" => assertion
           }), req_options(opts)}

        {:error, reason} ->
          {:error, {:client_assertion, reason}}
      end
    end
  end

  defp authenticate_as(_invalid, _client_id, _form, _endpoint, _opts),
    do: {:error, :invalid_client_auth}

  defp client_assertion_options(opts, client_id, endpoint) do
    allowed = [:audience, :alg, :kid, :lifetime, :now, :jti]
    keys = if Keyword.keyword?(opts), do: Keyword.keys(opts), else: []

    if keys != [] or opts == [] do
      if Enum.all?(keys, &(&1 in allowed)) and length(keys) == length(Enum.uniq(keys)) do
        build_opts =
          opts
          |> Keyword.put_new(:audience, endpoint)
          |> Keyword.put(:client_id, client_id)

        {:ok, build_opts}
      else
        {:error, :invalid_client_assertion_options}
      end
    else
      {:error, :invalid_client_assertion_options}
    end
  end

  defp request(endpoint, form, req_options, timeout_ms, response_mode) do
    options =
      req_options ++
        [
          url: endpoint,
          method: :post,
          form: form,
          redirect: false,
          retry: false,
          receive_timeout: timeout_ms
        ]

    case Req.request(Req.new(options)) do
      {:ok, %Req.Response{status: status}} when status in 200..299 and response_mode == :unit ->
        :ok

      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 and is_map(body) ->
        {:ok, body}

      {:ok, %Req.Response{status: status, body: %{} = body}} ->
        {:error, {:oauth_error, status, Map.take(body, ["error", "error_description"])}}

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, _reason} ->
        {:error, :transport_error}
    end
  rescue
    _error -> {:error, :transport_error}
  end

  defp req_options(opts), do: Keyword.get(opts, :req_options, [])

  defp timeout(opts) do
    case Keyword.get(opts, :timeout, @default_timeout_ms) do
      timeout when is_integer(timeout) and timeout > 0 -> {:ok, timeout}
      _invalid -> {:error, :invalid_timeout}
    end
  end
end
