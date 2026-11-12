defmodule AttestoClient.Outbound do
  @moduledoc """
  The `:outbound` option: deliberate exceptions to the rules this library
  applies to every address it connects to.

  By default an issuer, and every endpoint its metadata names, must be an
  `https` URL whose host resolves only to public addresses. Requests are sent
  to the address that was checked, and redirects are never followed, so there
  is no second hop to screen. Two exceptions can be named, and both are exact:

      outbound: [allowed_cidrs: ["10.20.0.0/16"]]
      outbound: [allow_loopback_http: true]

  `AttestoClient.AuthorizationCode.start/2`, `callback/3` and `exchange/2`,
  `AttestoClient.IDToken.verify/2`, `AttestoClient.Token.refresh/4`,
  `AttestoClient.Logout.url/1`, the `AttestoClient.Discovery` functions and
  `AttestoClient.Issuer` (and so `AttestoClient.ResourceServer`) take the
  option, and so do the other calls that talk to an issuer or to an endpoint
  the caller chose from its metadata: `AttestoClient.UserInfo.verify/2`,
  `AttestoClient.SignedIntrospection.verify/2`,
  `AttestoClient.Token.exchange_pre_authorized_code/2` and `revoke/2`,
  `AttestoClient.WalletAttestation.fetch_challenge/2` and
  `AttestoClient.Wallet.request_credential/3`.

  Three calls refuse it with `{:error, :outbound_not_supported}`:
  `AttestoClient.Wallet.CredentialOffer.fetch/2`,
  `AttestoClient.Wallet.PresentationRequest.fetch/3` and `from_uri/3`, and
  `AttestoClient.Wallet.Presentation.submit/3` and `present/3`. The address each of them
  connects to is written by another party (a credential offer link, a
  verifier's request), not chosen by the operator, so an allowance there
  would let whoever wrote the link direct a request into the listed networks.

  It is never stored in an authorization transaction or a token set:
  each call applies only what that call was given, so nothing a transaction
  carries can widen what `callback/3` connects to. Pass the same value to every
  call that talks to the issuer.

  ## `:allowed_cidrs`

  A list of CIDR blocks naming the non-public networks the issuer's hosts may
  resolve into, for an identity provider reachable only at a private address
  (a cluster-internal name, split-horizon DNS). Every address a host resolves
  to must be public or inside one of the blocks; anything else is refused with
  `:blocked_host`, as before. `https` is still required.

  This is an SSRF exception the operator takes on deliberately. With it, a
  metadata document served by the issuer can direct this library's requests,
  including the token request with its client credentials, at any host in the
  listed networks. List the smallest blocks that contain the issuer. There is
  no host-name form: allowing a name would trust DNS, and whoever controls the
  name's answer could point it at any private address. The rule itself is
  `Attesto.OutboundTarget`'s; a block with host bits set, a malformed block and
  a zero-length prefix are refused.

  ## `:allow_loopback_http`

  For development against an identity provider on the local machine. With
  `true`, `http` is accepted for the issuer and for the endpoints in its
  metadata when the host is `localhost` or a literal loopback address
  (`127.0.0.0/8`, `::1`), and such a host may be connected to. Every other host
  still needs `https` and a public (or listed) address.

  The option is refused, with `{:error, :invalid_outbound}`, when the issuer
  itself is not a loopback host: it has no use against a deployed issuer, and
  leaving it on there would let that issuer's metadata name a service on the
  machine running this library. Do not set it outside development.
  """

  @keys [:allowed_cidrs, :allow_loopback_http]

  @type t :: [{:allowed_cidrs, [String.t()]} | {:allow_loopback_http, boolean()}]

  @doc """
  Check the `:outbound` value in `opts`.

  Returns `:ok` when it is absent, `nil`, or a keyword list holding only
  `:allowed_cidrs` (a list of CIDR strings core accepts) and
  `:allow_loopback_http` (a boolean), each at most once. Anything else is
  `{:error, :invalid_outbound}`.
  """
  @spec validate(keyword()) :: :ok | {:error, :invalid_outbound}
  def validate(opts) when is_list(opts) do
    case Keyword.get(opts, :outbound) do
      nil -> :ok
      outbound -> if valid?(outbound), do: :ok, else: {:error, :invalid_outbound}
    end
  end

  @doc false
  # For a call whose target address is supplied by another party. Such a call
  # takes no exception, so a caller who passes one is told, not ignored.
  @spec refuse(keyword()) :: :ok | {:error, :outbound_not_supported}
  def refuse(opts) when is_list(opts) do
    if is_nil(Keyword.get(opts, :outbound)), do: :ok, else: {:error, :outbound_not_supported}
  end

  @doc false
  # Raising form for process start-up options.
  @spec validate!(keyword(), String.t()) :: t()
  def validate!(opts, label) when is_list(opts) and is_binary(label) do
    case validate(opts) do
      :ok ->
        Keyword.get(opts, :outbound) || []

      {:error, :invalid_outbound} ->
        raise ArgumentError,
              "#{label} :outbound must be a keyword list of :allowed_cidrs (CIDR strings) " <>
                "and :allow_loopback_http (a boolean)"
    end
  end

  @doc false
  # The issuer rule for `:allow_loopback_http`: on, the issuer must itself be a
  # loopback host. Call after `validate/1`.
  @spec check_issuer(term(), keyword()) :: :ok | {:error, :invalid_outbound}
  def check_issuer(issuer, opts) do
    if allow_loopback_http?(opts) and not loopback_url?(issuer),
      do: {:error, :invalid_outbound},
      else: :ok
  end

  @doc false
  # `Attesto.URI.https_identifier?/2` under this call's exceptions.
  @spec https_identifier?(term(), keyword()) :: boolean()
  def https_identifier?(value, opts) when is_list(opts) do
    Attesto.URI.https_identifier?(value, allow_loopback_http: allow_loopback_http?(opts))
  end

  @doc false
  # The exceptions `Attesto.OutboundTarget.screen/2` is given for `url`. The
  # loopback exception is passed only for a hop that is itself `http` to a
  # loopback host, so it cannot open any other request of the same call.
  @spec screen_options(String.t(), keyword()) :: keyword()
  def screen_options(url, opts) when is_binary(url) and is_list(opts) do
    outbound = Keyword.get(opts, :outbound) || []

    [allowed_cidrs: Keyword.get(outbound, :allowed_cidrs, [])]
    |> put_loopback(url, allow_loopback_http?(opts))
  end

  defp put_loopback(screen_opts, url, true) do
    if loopback_http_url?(url),
      do: Keyword.put(screen_opts, :allow_loopback, true),
      else: screen_opts
  end

  defp put_loopback(screen_opts, _url, false), do: screen_opts

  defp allow_loopback_http?(opts) do
    case Keyword.get(opts, :outbound) do
      outbound when is_list(outbound) ->
        Keyword.get(outbound, :allow_loopback_http, false) == true

      _absent ->
        false
    end
  end

  defp loopback_url?(url) when is_binary(url) do
    case URI.new(url) do
      {:ok, %URI{host: host}} -> Attesto.URI.loopback_host?(host)
      {:error, _part} -> false
    end
  end

  defp loopback_url?(_other), do: false

  defp loopback_http_url?(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: "http", host: host}} -> Attesto.URI.loopback_host?(host)
      _other -> false
    end
  end

  defp valid?(outbound) do
    Keyword.keyword?(outbound) and
      Keyword.keys(outbound) -- @keys == [] and
      Keyword.keys(outbound) == Enum.uniq(Keyword.keys(outbound)) and
      is_boolean(Keyword.get(outbound, :allow_loopback_http, false)) and
      valid_cidrs?(Keyword.get(outbound, :allowed_cidrs, []))
  end

  defp valid_cidrs?(cidrs) do
    _parsed = Attesto.IPAddress.parse_cidrs!(cidrs)
    true
  rescue
    ArgumentError -> false
  end
end
