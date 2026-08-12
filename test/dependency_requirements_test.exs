defmodule AttestoClient.DependencyRequirementsTest do
  use ExUnit.Case, async: true

  test "Attesto retains the complete current security floor" do
    case dependency!(:attesto) do
      {:attesto, requirement} when is_binary(requirement) ->
        assert Version.match?("1.12.2", requirement)
        assert Version.match?("1.99.0", requirement)
        refute Version.match?("1.12.1", requirement)
        refute Version.match?("2.0.0", requirement)

      {:attesto, opts} when is_list(opts) ->
        assert opts[:path], "expected the explicit ATTESTO_PATH development dependency"
    end
  end

  defp dependency!(app) do
    AttestoClient.MixProject.project()
    |> Keyword.fetch!(:deps)
    |> Enum.find(&(elem(&1, 0) == app))
  end
end
