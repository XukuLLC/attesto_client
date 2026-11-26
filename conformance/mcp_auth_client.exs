defmodule AttestoClient.Conformance.MCPAuthClient do
  @moduledoc false

  alias AttestoClient.MCPAuthorization

  @redirect_uri "http://127.0.0.1:3000/callback"
  @browser_binding "attesto-mcp-conformance"
  @cimd_client_id "https://conformance-test.local/client-metadata.json"
  @outbound [allow_loopback_http: true]
  @stateless_version "2026-07-28"
  @expected_rejections %{
    "auth/resource-mismatch" => [:resource_mismatch],
    "auth/metadata-issuer-mismatch" => [:issuer_mismatch],
    "auth/iss-supported-missing" => [:missing_response_issuer],
    "auth/iss-wrong-issuer" => [:issuer_mismatch],
    "auth/iss-unexpected" => [:issuer_mismatch],
    "auth/iss-normalized" => [:issuer_mismatch],
    "auth/scope-retry-limit" => [:scope_retry_limit]
  }

  def run(server_url) do
    scenario = System.fetch_env!("MCP_CONFORMANCE_SCENARIO")
    version = System.get_env("MCP_CONFORMANCE_PROTOCOL_VERSION", "2025-11-25")

    state = %{
      server_url: server_url,
      scenario: scenario,
      version: version,
      conformance_context: conformance_context(),
      authorization: nil,
      registration: nil,
      tokens: nil,
      next_id: 1
    }

    try do
      state
      |> run_lifecycle()
      |> ensure_expected_rejection_did_not_succeed!()

      IO.puts("MCP authorization conformance flow completed")
    catch
      {:expected_rejection, reason} ->
        IO.puts("MCP authorization correctly refused the scenario: #{reason}")
    end
  end

  defp run_lifecycle(%{version: @stateless_version} = state), do: exercise_tools(state)

  defp run_lifecycle(state) do
    initialize_params = %{
      "protocolVersion" => state.version,
      "capabilities" => %{},
      "clientInfo" => %{"name" => "attesto-client-conformance", "version" => "1.0.0"}
    }

    {state, _result} = rpc(state, "initialize", initialize_params)
    state = notify(state, "notifications/initialized", %{})
    exercise_tools(state)
  end

  defp exercise_tools(state) do
    {state, _tools} = rpc(state, "tools/list", %{})
    {state, _result} = rpc(state, "tools/call", %{"name" => "test-tool", "arguments" => %{}})
    state
  end

  defp rpc(state, method, params) do
    {id, state} = next_id(state)

    payload = %{
      "jsonrpc" => "2.0",
      "id" => id,
      "method" => method,
      "params" => request_params(state, params)
    }

    {state, response} = request(state, payload, 0)
    body = response_body!(response)

    case body do
      %{"result" => result} -> {state, result}
      %{"error" => %{"code" => code}} -> fail({:json_rpc_error, code})
      _invalid -> fail(:invalid_json_rpc_response)
    end
  end

  defp notify(state, method, params) do
    payload = %{
      "jsonrpc" => "2.0",
      "method" => method,
      "params" => request_params(state, params)
    }

    {state, _response} = request(state, payload, 0)
    state
  end

  defp request(_state, _payload, attempts) when attempts > 5,
    do: fail(:authorization_retry_limit)

  defp request(state, payload, attempts) do
    headers = request_headers(state)

    case Req.request(
           method: :post,
           url: state.server_url,
           json: payload,
           headers: headers,
           redirect: false,
           retry: false,
           receive_timeout: 10_000
         ) do
      {:ok, %Req.Response{status: status} = response} when status in 200..299 ->
        {state, response}

      {:ok, %Req.Response{status: 401} = response} ->
        state = authorize(state, challenge_headers(response))
        request(state, payload, attempts + 1)

      {:ok, %Req.Response{status: 403} = response} ->
        state = step_up(state, challenge_headers(response))
        request(state, payload, attempts + 1)

      {:ok, %Req.Response{status: status}} ->
        fail({:http_status, status})

      {:error, reason} ->
        fail({:transport, reason})
    end
  end

  defp authorize(state, challenges) do
    with {:ok, authorization} <-
           MCPAuthorization.discover(state.server_url,
             www_authenticate: challenges,
             offline_access: true,
             outbound: @outbound
           ),
         {:ok, registration} <- select_registration(state, authorization),
         {:ok, tokens} <- authorize_code(authorization, registration) do
      %{
        state
        | authorization: authorization,
          registration: registration,
          tokens: tokens
      }
    else
      {:error, reason} -> reject_or_fail(state, reason)
    end
  end

  defp step_up(%{authorization: nil} = state, challenges), do: authorize(state, challenges)

  defp step_up(state, challenges) do
    with {:ok, authorization} <-
           MCPAuthorization.step_up(state.authorization, challenges, max_scope_retries: 2),
         {:ok, tokens} <- authorize_code(authorization, state.registration) do
      %{state | authorization: authorization, tokens: tokens}
    else
      {:error, reason} -> reject_or_fail(state, reason)
    end
  end

  defp select_registration(state, authorization) do
    MCPAuthorization.select_registration(authorization,
      registration: state.registration,
      pre_registered: pre_registered(state.conformance_context),
      client_id_metadata: client_id_metadata(),
      dynamic_registration: [
        client_name: "Attesto MCP Conformance Client",
        redirect_uris: [@redirect_uri],
        application_type: :native
      ],
      outbound: @outbound
    )
  end

  defp authorize_code(authorization, registration) do
    with {:ok, started} <-
           MCPAuthorization.start(authorization, registration, :return,
             redirect_uri: @redirect_uri,
             browser_binding: @browser_binding,
             outbound: @outbound
           ),
         {:ok, callback_params} <- authorization_redirect(started.url),
         {:ok, result} <-
           MCPAuthorization.callback(
             authorization,
             registration,
             :return,
             callback_params,
             transaction: started.transaction,
             browser_binding: @browser_binding,
             outbound: @outbound
           ) do
      {:ok, result.tokens}
    end
  end

  defp authorization_redirect(url) do
    case Req.get(url: url, redirect: false, retry: false, receive_timeout: 10_000) do
      {:ok, %Req.Response{status: status} = response} when status in 300..399 ->
        case Req.Response.get_header(response, "location") do
          [location] -> callback_params(url, location)
          _missing -> {:error, :missing_authorization_redirect}
        end

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, {:transport, reason}}
    end
  end

  defp callback_params(base, location) do
    uri = base |> URI.new!() |> URI.merge(location)

    case uri.query do
      query when is_binary(query) -> {:ok, URI.decode_query(query)}
      _missing -> {:error, :missing_callback_query}
    end
  end

  defp request_headers(state) do
    base = [
      {"accept", "application/json, text/event-stream"},
      {"mcp-protocol-version", state.version}
    ]

    case {state.authorization, state.tokens} do
      {%MCPAuthorization{} = authorization, %AttestoClient.TokenSet{} = tokens} ->
        case MCPAuthorization.authorization_header(authorization, tokens) do
          {:ok, header} -> [header | base]
          {:error, reason} -> fail(reason)
        end

      _unauthorized ->
        base
    end
  end

  defp request_params(%{version: @stateless_version} = state, params) do
    metadata = %{
      "io.modelcontextprotocol/protocolVersion" => state.version,
      "io.modelcontextprotocol/clientCapabilities" => %{"tools" => %{}},
      "io.modelcontextprotocol/clientInfo" => %{
        "name" => "attesto-client-conformance",
        "version" => "1.0.0"
      }
    }

    Map.update(params, "_meta", metadata, &Map.merge(metadata, &1))
  end

  defp request_params(_state, params), do: params

  defp response_body!(%Req.Response{body: %{} = body}), do: body

  defp response_body!(%Req.Response{body: body}) when is_binary(body) do
    body
    |> String.split("\n")
    |> Enum.find_value(fn
      "data:" <> data -> decode_json(String.trim(data))
      _line -> nil
    end)
    |> case do
      nil -> decode_json(body) || fail(:invalid_json_rpc_response)
      decoded -> decoded
    end
  end

  defp response_body!(_response), do: fail(:invalid_json_rpc_response)

  defp decode_json(value) do
    case JSON.decode(value) do
      {:ok, %{} = decoded} -> decoded
      _invalid -> nil
    end
  end

  defp challenge_headers(response), do: Req.Response.get_header(response, "www-authenticate")

  defp next_id(state), do: {state.next_id, %{state | next_id: state.next_id + 1}}

  defp client_id_metadata do
    %{
      client_id: @cimd_client_id,
      document: %{
        "client_id" => @cimd_client_id,
        "client_name" => "Attesto MCP Conformance Client",
        "redirect_uris" => [@redirect_uri],
        "grant_types" => ["authorization_code", "refresh_token"],
        "response_types" => ["code"],
        "token_endpoint_auth_method" => "none"
      },
      client_auth: :none
    }
  end

  defp pre_registered(%{
         "client_id" => client_id,
         "client_secret" => secret,
         "issuer" => issuer
       })
       when is_binary(client_id) and is_binary(secret) and is_binary(issuer) do
    %{
      issuer => %{
        client_id: client_id,
        client_auth: {:client_secret_basic, secret}
      }
    }
  end

  defp pre_registered(_context), do: %{}

  defp conformance_context do
    case System.get_env("MCP_CONFORMANCE_CONTEXT") do
      nil -> %{}
      encoded -> decode_json(encoded) || %{}
    end
  end

  defp reject_or_fail(state, reason) do
    if reason in Map.get(@expected_rejections, state.scenario, []) do
      throw({:expected_rejection, reason})
    else
      fail(reason)
    end
  end

  defp ensure_expected_rejection_did_not_succeed!(state) do
    if Map.has_key?(@expected_rejections, state.scenario),
      do: fail(:expected_rejection_did_not_occur),
      else: state
  end

  defp fail(reason) do
    projected = AttestoClient.Error.project(reason)
    raise "MCP authorization conformance client failed: #{inspect(projected)}"
  end
end

case List.last(System.argv()) do
  nil -> raise "usage: mix run conformance/mcp_auth_client.exs -- SERVER_URL"
  server_url -> AttestoClient.Conformance.MCPAuthClient.run(server_url)
end
