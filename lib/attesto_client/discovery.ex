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
    * The document's own `issuer` member MUST equal the issuer it was fetched
      from (RFC 8414 §3.3), defending against a metadata mix-up. A trailing slash
      on the supplied issuer is normalised away for both the request and this
      comparison.
    * A JWKS is fetched only over `https`, since it is the trust root for
      verifying the authorization server's signatures.

  ## HTTP

  Requests go through [`Req`](https://hex.pm/packages/req). Pass `:req_options`
  to configure it - notably `plug:` for `Req.Test` in tests.
  """

  @oidc_segment "/.well-known/openid-configuration"
  @oauth_segment "/.well-known/oauth-authorization-server"

  @type well_known :: :openid_configuration | :oauth_authorization_server
  @type opt :: {:well_known, well_known()} | {:req_options, keyword()}

  @type error ::
          :invalid_issuer
          | :invalid_jwks_uri
          | :issuer_mismatch
          | :invalid_metadata
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
         {:ok, body} <- get_json(metadata_url(uri, well_known(opts)), opts) do
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

  # RFC 8414 §2: the issuer is an https URL with no query or fragment. Returns
  # the parsed URI and the canonical issuer (trailing slash removed) used for the
  # §3.3 match.
  defp validate_issuer(issuer) when is_binary(issuer) do
    case URI.parse(issuer) do
      %URI{scheme: "https", host: host, query: nil, fragment: nil} = uri
      when is_binary(host) and host != "" ->
        {:ok, uri, String.trim_trailing(issuer, "/")}

      _other ->
        {:error, :invalid_issuer}
    end
  end

  defp validate_issuer(_other), do: {:error, :invalid_issuer}

  defp validate_https(url, error) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: "https", host: host} when is_binary(host) and host != "" -> {:ok, url}
      _other -> {:error, error}
    end
  end

  defp validate_https(_url, error), do: {:error, error}

  defp well_known(opts) do
    case Keyword.get(opts, :well_known, :openid_configuration) do
      :oauth_authorization_server -> :oauth_authorization_server
      _ -> :openid_configuration
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

  # RFC 8414 §3.3: the `issuer` in the document MUST equal the issuer it was
  # retrieved for (compared against the canonical, slash-normalised value).
  defp check_issuer(metadata, canonical) when is_map(metadata) do
    if Map.get(metadata, "issuer") == canonical,
      do: {:ok, metadata},
      else: {:error, :issuer_mismatch}
  end

  defp validate_jwks(%{"keys" => keys} = jwks) when is_list(keys), do: {:ok, jwks}
  defp validate_jwks(_other), do: {:error, :invalid_metadata}

  defp get_json(url, opts) do
    req = Req.new([url: url] ++ Keyword.get(opts, :req_options, []))

    case Req.request(req) do
      {:ok, %Req.Response{status: 200, body: body}} when is_map(body) -> {:ok, body}
      {:ok, %Req.Response{status: 200}} -> {:error, :invalid_metadata}
      {:ok, %Req.Response{status: status}} -> {:error, {:http_status, status}}
      {:error, reason} -> {:error, {:transport, reason}}
    end
  rescue
    error -> {:error, {:transport, Exception.message(error)}}
  end
end
