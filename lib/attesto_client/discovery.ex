defmodule AttestoClient.Discovery do
  @moduledoc """
  Fetch and read OAuth 2.0 / OpenID Connect authorization-server metadata
  (RFC 8414 / OpenID Connect Discovery 1.0).

  A thin lookup: it fetches the discovery document (and, separately, the JWKS)
  and returns the parsed JSON. It runs no flow and holds no state - the host
  reads the endpoint URLs and capabilities it needs (and, for verifying JARM
  responses, passes the fetched JWKS to `AttestoClient.JARM.verify/3`).

  ## URL construction

  By default the OpenID Connect Discovery document is fetched by appending
  `/.well-known/openid-configuration` to the issuer (OpenID Connect Discovery
  1.0 §4). Pass `well_known: :oauth_authorization_server` for the RFC 8414
  document, which is constructed differently: the well-known segment is inserted
  **before** the issuer's path component (RFC 8414 §3.1), so it is correct for
  path-based (multi-tenant) issuers.

  ## Issuer / transport validation

    * The issuer MUST be an `https` URL with no query or fragment (RFC 8414 §2).
    * The document's own `issuer` member MUST be **identical** to the issuer it
      was fetched for (RFC 8414 §3.3 / OpenID Connect Discovery 1.0 §4.3),
      defending against a metadata mix-up. The comparison is exact - no
      trailing-slash normalisation - so a path-based issuer that ends in `/`
      (e.g. a multi-tenant issuer) must be supplied exactly as the server
      publishes it. A trailing slash is removed only when constructing the
      well-known request URL, as both specs require.
    * A JWKS is fetched only over `https`, since it is the trust root for
      verifying the authorization server's signatures.

  ## HTTP

  Requests go through [`Req`](https://hex.pm/packages/req). Pass `:req_options`
  to configure it - notably `plug:` for `Req.Test` in tests.
  """

  @oidc_segment "/.well-known/openid-configuration"
  @oauth_segment "/.well-known/oauth-authorization-server"
  @default_max_response_bytes 512 * 1024

  @type well_known :: :openid_configuration | :oauth_authorization_server
  @type opt ::
          {:well_known, well_known()}
          | {:req_options, keyword()}
          | {:max_response_bytes, pos_integer()}
          | {:resolver,
             (charlist(), :inet | :inet6 -> {:ok, [:inet.ip_address()]} | {:error, term()})}

  @type error ::
          :invalid_issuer
          | :invalid_well_known
          | :invalid_jwks_uri
          | :issuer_mismatch
          | :invalid_metadata
          | :response_too_large
          | :blocked_host
          | {:http_status, pos_integer()}
          | {:transport, term()}

  @doc """
  Fetch the authorization server's metadata for `issuer`, returning
  `{:ok, metadata}` (a string-keyed map) or `{:error, reason}`.

  `issuer` must be an `https` URL with no query or fragment. Options:
  `:well_known` (`:openid_configuration` (default) or
  `:oauth_authorization_server`) and `:req_options` (forwarded to `Req`).
  """
  @spec fetch(String.t(), [opt()]) :: {:ok, map()} | {:error, error()}
  def fetch(issuer, opts \\ []) when is_list(opts) do
    with {:ok, uri, canonical} <- validate_issuer(issuer),
         {:ok, well_known} <- well_known(opts),
         {:ok, body} <- get_json(metadata_url(uri, well_known), opts) do
      check_issuer(body, canonical)
    end
  end

  @doc """
  Fetch a JWKS document from `jwks_uri` (typically the metadata's `jwks_uri`),
  returning `{:ok, jwks}` - a map with a `"keys"` list - or `{:error, reason}`.
  The URI must be `https`.
  """
  @spec fetch_jwks(String.t(), [opt()]) :: {:ok, map()} | {:error, error()}
  def fetch_jwks(jwks_uri, opts \\ []) when is_list(opts) do
    with {:ok, url} <- validate_https(jwks_uri, :invalid_jwks_uri),
         {:ok, body} <- get_json(url, opts) do
      validate_jwks(body)
    end
  end

  @doc """
  Validate an authorization-server endpoint before making a server-side
  request. The endpoint must use HTTPS, must not contain userinfo or a fragment,
  and must not resolve to a private, loopback, or link-local address.

  Applications normally use this indirectly through the authorization-code,
  refresh, and revocation APIs.
  """
  @spec validate_endpoint(term(), keyword()) ::
          :ok | {:error, :invalid_endpoint | :blocked_host}
  def validate_endpoint(endpoint, opts \\ [])

  def validate_endpoint(endpoint, opts) when is_binary(endpoint) and is_list(opts) do
    case URI.parse(endpoint) do
      %URI{scheme: "https", host: host, userinfo: nil, fragment: nil}
      when is_binary(host) and host != "" ->
        guard_host(endpoint, opts)

      _invalid ->
        {:error, :invalid_endpoint}
    end
  end

  def validate_endpoint(_endpoint, _opts), do: {:error, :invalid_endpoint}

  @doc false
  @spec validate_browser_endpoint(term()) :: :ok | {:error, :invalid_endpoint}
  def validate_browser_endpoint(endpoint) when is_binary(endpoint) do
    case URI.parse(endpoint) do
      %URI{scheme: "https", host: host, userinfo: nil, fragment: nil}
      when is_binary(host) and host != "" ->
        :ok

      _invalid ->
        {:error, :invalid_endpoint}
    end
  end

  def validate_browser_endpoint(_endpoint), do: {:error, :invalid_endpoint}

  @doc false
  @spec validate_issuer_identifier(term()) :: :ok | {:error, :invalid_issuer}
  def validate_issuer_identifier(issuer) do
    case validate_issuer(issuer) do
      {:ok, _uri, _canonical} -> :ok
      {:error, :invalid_issuer} = error -> error
    end
  end

  # RFC 8414 §2: the issuer is an https URL with no query or fragment. Returns
  # the parsed URI and the issuer exactly as supplied, which is what the §3.3
  # document match compares against.
  defp validate_issuer(issuer) when is_binary(issuer) do
    case URI.parse(issuer) do
      %URI{scheme: "https", host: host, userinfo: nil, query: nil, fragment: nil} = uri
      when is_binary(host) and host != "" ->
        {:ok, uri, issuer}

      _other ->
        {:error, :invalid_issuer}
    end
  end

  defp validate_issuer(_other), do: {:error, :invalid_issuer}

  defp validate_https(url, error) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: "https", host: host, userinfo: nil, fragment: nil}
      when is_binary(host) and host != "" ->
        {:ok, url}

      _other ->
        {:error, error}
    end
  end

  defp validate_https(_url, error), do: {:error, error}

  # Fail fast on an unknown :well_known rather than silently fetching the wrong
  # document (a typo would otherwise return {:ok, _} for the wrong metadata).
  defp well_known(opts) do
    case Keyword.get(opts, :well_known, :openid_configuration) do
      :openid_configuration -> {:ok, :openid_configuration}
      :oauth_authorization_server -> {:ok, :oauth_authorization_server}
      _other -> {:error, :invalid_well_known}
    end
  end

  # OpenID Connect Discovery §4: append the segment to the issuer path.
  defp metadata_url(uri, :openid_configuration) do
    %{uri | path: issuer_path(uri) <> @oidc_segment} |> URI.to_string()
  end

  # RFC 8414 §3.1: insert the segment before the issuer's path component.
  defp metadata_url(uri, :oauth_authorization_server) do
    %{uri | path: @oauth_segment <> issuer_path(uri)} |> URI.to_string()
  end

  defp issuer_path(%URI{path: path}) do
    (path || "") |> String.trim_trailing("/")
  end

  # RFC 8414 §3.3 / OIDC Discovery §4.3: the `issuer` in the document MUST be
  # identical to the issuer it was retrieved for. Exact string comparison - a
  # slash-normalising match would accept a subtly different identifier, and
  # would reject legitimate slash-terminated path issuers (the value in the
  # document is what ID Token `iss` claims are later matched against).
  defp check_issuer(metadata, supplied) when is_map(metadata) do
    if Map.get(metadata, "issuer") == supplied,
      do: {:ok, metadata},
      else: {:error, :issuer_mismatch}
  end

  defp validate_jwks(%{"keys" => keys} = jwks) when is_list(keys), do: {:ok, jwks}
  defp validate_jwks(_other), do: {:error, :invalid_metadata}

  defp get_json(url, opts) do
    with {:ok, target} <- screen_endpoint(url, opts) do
      # SSRF hardening: redirects are NOT followed (`redirect: false` wins over
      # any caller `:req_options`). Otherwise the https/host validation, which
      # only covers the INITIAL URL, would be bypassed by a 3xx `Location` to an
      # internal address (e.g. the cloud metadata service). A 3xx therefore
      # surfaces as `{:http_status, 3xx}` rather than being chased.
      req_options =
        opts
        |> Keyword.get(:req_options, [])
        |> Keyword.put_new(:receive_timeout, 10_000)

      max_bytes = max_response_bytes(opts)
      req = request(target, req_options, max_bytes)

      case Req.request(req) do
        {:ok, %Req.Response{private: %{attesto_client_response_too_large: true}}} ->
          {:error, :response_too_large}

        {:ok, %Req.Response{status: 200, body: body}} when is_binary(body) ->
          decode_json(body)

        # Req test plugs may hand back an already-decoded body even with the
        # network-only raw/streaming options below. No socket was opened in that
        # case, so accepting the map preserves the in-process test seam.
        {:ok, %Req.Response{status: 200, body: body}} when is_map(body) ->
          {:ok, body}

        {:ok, %Req.Response{status: 200}} ->
          {:error, :invalid_metadata}

        {:ok, %Req.Response{status: status}} ->
          {:error, {:http_status, status}}

        {:error, reason} ->
          {:error, {:transport, reason}}
      end
    end
  rescue
    error -> {:error, {:transport, Exception.message(error)}}
  end

  defp request(target, req_options, max_bytes) do
    headers =
      req_options
      |> Keyword.get(:headers, [])
      |> Enum.reject(fn {name, _value} -> String.downcase(to_string(name)) == "host" end)
      |> List.insert_at(0, {"host", target.authority})

    connect_options =
      req_options
      |> Keyword.get(:connect_options, [])
      |> Keyword.put(:hostname, target.host)

    req_options
    |> Keyword.merge(
      url: target.url,
      headers: headers,
      connect_options: connect_options,
      redirect: false,
      retry: false,
      compressed: false,
      raw: true,
      into: bounded_response_into(max_bytes)
    )
    |> Req.new()
  end

  defp bounded_response_into(max_bytes) do
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

  defp decode_json(body) do
    case JSON.decode(body) do
      {:ok, %{} = decoded} -> {:ok, decoded}
      _other -> {:error, :invalid_metadata}
    end
  end

  defp max_response_bytes(opts) do
    case Keyword.get(opts, :max_response_bytes, @default_max_response_bytes) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> @default_max_response_bytes
    end
  end

  # SSRF guard: resolve every A/AAAA answer, reject the whole set if any target
  # is special-use, then rewrite the URL to one checked address. Mint's
  # `connect_options[:hostname]` keeps TLS SNI and certificate verification on
  # the original host while the socket dials that IP. This closes the DNS-
  # rebinding window between validation and connect.
  defp guard_host(url, opts) do
    case screen_endpoint(url, opts) do
      {:ok, _target} -> :ok
      {:error, :blocked_host} = error -> error
    end
  end

  @doc false
  @spec screen_endpoint(String.t(), keyword()) ::
          {:ok, %{url: String.t(), host: String.t(), authority: String.t()}}
          | {:error, :blocked_host}
  def screen_endpoint(url, opts \\ [])

  def screen_endpoint(url, opts) when is_binary(url) and is_list(opts) do
    case URI.new(url) do
      {:ok, %URI{scheme: "https", host: host, userinfo: nil, fragment: nil} = uri}
      when is_binary(host) and host != "" ->
        screen_uri(uri, opts)

      _other ->
        {:error, :blocked_host}
    end
  end

  def screen_endpoint(_url, _opts), do: {:error, :blocked_host}

  defp screen_uri(%URI{host: host} = uri, opts) do
    if req_test_transport?(opts), do: {:ok, target(uri, host)}, else: screen_resolved(uri, opts)
  end

  defp screen_resolved(%URI{host: host} = uri, opts) do
    with {:ok, addresses} <- resolve_addrs(host, opts),
         false <- Enum.any?(addresses, &blocked_ip?/1) do
      {:ok, target(uri, hd(addresses))}
    else
      _other -> {:error, :blocked_host}
    end
  end

  # An active Req plug handles the request in-process and cannot connect to the
  # URL's resolved address. Skipping DNS in that case keeps tests deterministic
  # without weakening any real network transport. Req treats nil and false as
  # inactive, so those values must retain the network guard.
  defp req_test_transport?(opts) do
    plug =
      opts
      |> Keyword.get(:req_options, [])
      |> Map.new()
      |> Map.get(:plug)

    plug not in [nil, false]
  end

  defp resolve_addrs(host, opts) do
    charlist = String.to_charlist(host)
    resolver = Keyword.get(opts, :resolver, &:inet.getaddrs/2)
    v4 = lookup(resolver, charlist, :inet)
    v6 = lookup(resolver, charlist, :inet6)

    case v4 ++ v6 do
      [] -> {:error, :unresolvable}
      addrs -> {:ok, addrs}
    end
  end

  defp lookup(resolver, host, family) do
    case resolver.(host, family) do
      {:ok, addresses} when is_list(addresses) -> addresses
      _other -> []
    end
  end

  defp target(uri, host) when is_binary(host) do
    %{url: URI.to_string(uri), host: host, authority: authority(uri)}
  end

  defp target(uri, ip) do
    host = ip |> :inet.ntoa() |> List.to_string()
    %{url: URI.to_string(%{uri | host: host}), host: uri.host, authority: authority(uri)}
  end

  defp authority(%URI{host: host, port: port, scheme: scheme}) do
    host = if String.contains?(host, ":"), do: "[" <> host <> "]", else: host

    if default_port?(scheme, port), do: host, else: host <> ":" <> Integer.to_string(port)
  end

  defp default_port?("https", 443), do: true
  defp default_port?("http", 80), do: true
  defp default_port?(_scheme, _port), do: false

  # IPv4 ranges that must never be the target of a server-side fetch. The
  # globally reachable anycast exceptions inside 192.0.0.0/24 remain usable.
  defp blocked_ip?({127, _, _, _}), do: true
  defp blocked_ip?({10, _, _, _}), do: true
  defp blocked_ip?({192, 168, _, _}), do: true
  defp blocked_ip?({172, b, _, _}) when b in 16..31, do: true
  defp blocked_ip?({169, 254, _, _}), do: true
  defp blocked_ip?({100, b, _, _}) when b in 64..127, do: true
  defp blocked_ip?({0, _, _, _}), do: true
  defp blocked_ip?({192, 0, 0, d}) when d in [9, 10], do: false
  defp blocked_ip?({192, 0, 0, _}), do: true
  defp blocked_ip?({192, 0, 2, _}), do: true
  defp blocked_ip?({192, 88, 99, _}), do: true
  defp blocked_ip?({198, b, _, _}) when b in 18..19, do: true
  defp blocked_ip?({198, 51, 100, _}), do: true
  defp blocked_ip?({203, 0, 113, _}), do: true
  defp blocked_ip?({a, _, _, _}) when a in 224..255, do: true

  # IPv6 unspecified and loopback addresses.
  defp blocked_ip?({0, 0, 0, 0, 0, 0, 0, 0}), do: true
  defp blocked_ip?({0, 0, 0, 0, 0, 0, 0, 1}), do: true

  # Deprecated IPv4-compatible IPv6 (::a.b.c.d) — unwrap and re-check the
  # embedded v4 address so compatible private/loopback targets cannot bypass
  # the IPv4 policy.
  defp blocked_ip?({0, 0, 0, 0, 0, 0, g, h}),
    do: blocked_ip?({div(g, 256), rem(g, 256), div(h, 256), rem(h, 256)})

  # IPv4-mapped IPv6 (::ffff:a.b.c.d) — unwrap and re-check the embedded v4.
  defp blocked_ip?({0, 0, 0, 0, 0, 0xFFFF, g, h}),
    do: blocked_ip?({div(g, 256), rem(g, 256), div(h, 256), rem(h, 256)})

  # The globally reachable RFC 6052 NAT64 prefix may carry a public IPv4
  # destination, so unwrap it and apply the IPv4 policy rather than blocking
  # the entire prefix.
  defp blocked_ip?({0x64, 0xFF9B, 0, 0, 0, 0, g, h}),
    do: blocked_ip?({div(g, 256), rem(g, 256), div(h, 256), rem(h, 256)})

  # RFC 8215's local-use NAT64 prefix is not globally reachable.
  defp blocked_ip?({0x64, 0xFF9B, 1, _, _, _, _, _}), do: true

  # 6to4 embeds an IPv4 destination in words 2-3.
  defp blocked_ip?({0x2002, g, h, _, _, _, _, _}),
    do: blocked_ip?({div(g, 256), rem(g, 256), div(h, 256), rem(h, 256)})

  # IANA IPv6 special-purpose ranges: discard-only, Teredo, benchmarking,
  # ORCHIDv2, documentation, SRv6 SIDs, and multicast.
  defp blocked_ip?({0x0100, 0, 0, 0, _, _, _, _}), do: true
  defp blocked_ip?({0x2001, 0, _, _, _, _, _, _}), do: true
  defp blocked_ip?({0x2001, 0x0002, 0, _, _, _, _, _}), do: true
  defp blocked_ip?({0x2001, word, _, _, _, _, _, _}) when word in 0x0020..0x002F, do: true
  defp blocked_ip?({0x3FFF, _, _, _, _, _, _, _}), do: true
  defp blocked_ip?({0x5F00, _, _, _, _, _, _, _}), do: true
  defp blocked_ip?({first, _, _, _, _, _, _, _}) when first in 0xFF00..0xFFFF, do: true

  # Other IPv6: fe80::/10 link-local, fec0::/10 deprecated site-local, or
  # fc00::/7 unique-local (bit math in the body — band/2 is not guard-safe as a
  # qualified call).
  defp blocked_ip?({a, _, _, _, _, _, _, _}) when is_integer(a),
    do:
      Bitwise.band(a, 0xFFC0) == 0xFE80 or
        Bitwise.band(a, 0xFFC0) == 0xFEC0 or
        Bitwise.band(a, 0xFE00) == 0xFC00

  defp blocked_ip?(_addr), do: false
end
