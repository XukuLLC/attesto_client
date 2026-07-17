defmodule AttestoClient.MixProject do
  @moduledoc false
  use Mix.Project

  @version "2.1.1"
  @url "https://github.com/XukuLLC/attesto_client"
  @maintainers ["Neil Berkman"]

  def project do
    [
      name: "AttestoClient",
      app: :attesto_client,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      description:
        "Secure OpenID Connect code + PKCE, refresh, revocation, logout, and " <>
          "OAuth 2.0 / FAPI client artifacts and verification.",
      package: package(),
      source_url: @url,
      homepage_url: @url,
      maintainers: @maintainers,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: docs(),
      aliases: aliases()
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test]]
  end

  def application do
    [extra_applications: [:crypto, :logger]]
  end

  defp elixirc_paths(:test), do: ["lib", "test_support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      # The shared OAuth/OIDC/FAPI wire formats and verification primitives. A
      # runtime dependency: the client reuses attesto's signing-algorithm
      # resolution and (for the response side) its verification, the mirror of
      # what attesto's server side issues.
      attesto_dep(),
      {:jose, "~> 1.11.9"},
      # Discovery-metadata / JWKS fetching over HTTP (the family's HTTP client,
      # as in req_dpop).
      {:req, ">= 0.6.1 and < 1.0.0"},

      # Optional Plug integration for inbound resource-server verification.
      {:plug, "~> 1.16.6 or ~> 1.17.4 or ~> 1.18.5 or ~> 1.19.5 or >= 1.20.3 and < 2.0.0",
       optional: true},

      # dev / quality
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:quokka, "~> 2.12", only: [:dev, :test], runtime: false}
    ]
  end

  # Co-develop against the sibling attesto checkout only when explicitly opted in
  # via ATTESTO_PATH=1 (and the checkout exists). NOT keyed on Mix.env, since
  # `mix hex.publish` runs in :dev and a path dep cannot be packaged; the default
  # - including every publish - resolves the published version constraint.
  defp attesto_dep do
    if System.get_env("ATTESTO_PATH") in ~w(1 true) and File.dir?("../attesto") do
      {:attesto, path: "../attesto"}
    else
      {:attesto, "~> 1.0"}
    end
  end

  defp aliases do
    [
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        "test"
      ]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @url,
      extras: [
        "README.md",
        "guides/authorization-code.md",
        "guides/resource-server.md",
        "CHANGELOG.md",
        "LICENSE"
      ],
      groups_for_extras: [
        Guides: ~r/guides\//,
        Changelog: ~r/CHANGELOG\.md/,
        License: ~r/LICENSE/
      ]
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{
        "Changelog" => "https://hexdocs.pm/attesto_client/changelog.html",
        "GitHub" => @url
      },
      files: ~w(lib guides LICENSE mix.exs README.md CHANGELOG.md)
    ]
  end
end
