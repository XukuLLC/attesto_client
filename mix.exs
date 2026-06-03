defmodule AttestoClient.MixProject do
  @moduledoc false
  use Mix.Project

  @version "0.1.0"
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
        "Client-side OAuth 2.0 / OpenID Connect / FAPI 2.0 artifacts and verification: " <>
          "private_key_jwt assertions, signed request objects (JAR), and JARM verification.",
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
      {:jose, "~> 1.11"},

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
      {:attesto, "~> 0.6"}
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
      extras: ["README.md", "CHANGELOG.md", "LICENSE"],
      groups_for_extras: [
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
      files: ~w(lib LICENSE mix.exs README.md CHANGELOG.md)
    ]
  end
end
