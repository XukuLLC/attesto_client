defmodule AttestoClient.Discovery do
  @moduledoc """
  Fetch and read OAuth 2.0 / OpenID Connect authorization-server metadata
  (RFC 8414 / OpenID Connect Discovery 1.0).

  A thin lookup: it fetches the discovery document (and, separately, the JWKS)
  and returns the parsed JSON. It runs no flow and holds no state - the host
  reads the endpoint URLs and capabilities it needs (and, for verifying JARM
  responses, passes the fetched JWKS to `AttestoClient.JARM.verify/3`).

  ## Issuer validation (RFC 8414 §3.3)

  `fetch/2` requires an `https` issuer and rejects a document whose own `issuer`
  member does not exactly match the issuer it was fetched from, defending against
  a metadata mix-up.

  ## HTTP

  Requests go through [`Req`](https://hex.pm/packages/req). Pass `:req_options`
  to configure it - notably `plug:` for `Req.Test` in tests, or `connect_options`
  / `retry` in production.
  """

  # OpenID Connect Discovery 1.0 §4: the well-known document, appended to the
  # issuer. (RFC 8414 also defines /.well-known/oauth-authorization-server;
  # override the tail with :well_known_path when targeting that.)
  @openid_configuration "/.well-known/openid-configuration"

  @type opt :: {:well_known_path, String.t()} | {:req_options, keyword()}

  @type error ::
          :invalid_issuer
          | :issuer_mismatch
          | :invalid_metadata
          | {:http_status, pos_integer()}
          | {:transport, term()}

  @doc """
  Fetch the authorization server's metadata for `issuer`, returning
  `{:ok, metadata}` (a string-keyed map) or `{:error, reason}`.

  `issuer` must be an `https` URL. Options: `:well_known_path` (defaults to
  `#{@openid_configuration}`) and `:req_options` (forwarded to `Req`).
  """
  @spec fetch(String.t(), [opt()]) :: {:ok, map()} | {:error, error()}
  def fetch(issuer, opts \\ []) when is_binary(issuer) and is_list(opts) do
    with {:ok, base} <- validate_issuer(issuer),
         {:ok, body} <- get_json(base <> well_known_path(opts), opts) do
      check_issuer(body, issuer)
    end
  end

  @doc """
  Fetch a JWKS document from `jwks_uri` (typically the metadata's `jwks_uri`),
  returning `{:ok, jwks}` - a map with a `"keys"` list - or `{:error, reason}`.
  """
  @spec fetch_jwks(String.t(), [opt()]) :: {:ok, map()} | {:error, error()}
  def fetch_jwks(jwks_uri, opts \\ []) when is_binary(jwks_uri) and is_list(opts) do
    case get_json(jwks_uri, opts) do
      {:ok, %{"keys" => keys} = jwks} when is_list(keys) -> {:ok, jwks}
      {:ok, _other} -> {:error, :invalid_metadata}
      {:error, _reason} = error -> error
    end
  end

  # RFC 8414 §2 / OpenID Connect Discovery: the issuer is an https URL. Return it
  # without a trailing slash so the well-known path joins cleanly.
  defp validate_issuer(issuer) do
    case URI.parse(issuer) do
      %URI{scheme: "https", host: host} when is_binary(host) and host != "" ->
        {:ok, String.trim_trailing(issuer, "/")}

      _other ->
        {:error, :invalid_issuer}
    end
  end

  defp well_known_path(opts) do
    case Keyword.get(opts, :well_known_path) do
      path when is_binary(path) and path != "" -> path
      _ -> @openid_configuration
    end
  end

  # RFC 8414 §3.3: the `issuer` in the document MUST be identical to the issuer
  # it was retrieved for.
  defp check_issuer(metadata, issuer) when is_map(metadata) do
    if Map.get(metadata, "issuer") == issuer,
      do: {:ok, metadata},
      else: {:error, :issuer_mismatch}
  end

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
