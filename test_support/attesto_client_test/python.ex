defmodule AttestoClient.Test.Python do
  @moduledoc false

  @spec available(String.t()) :: {:ok, String.t()} | {:skip, String.t()}
  def available(script) when is_binary(script) do
    python = System.get_env("ATTESTO_CLIENT_PYTHON") || System.find_executable("python3")

    cond do
      is_nil(python) -> {:skip, "python3 not found"}
      not File.exists?(script_path(script)) -> {:skip, "python helper not found"}
      true -> ensure_pyjwt(python)
    end
  end

  @spec run(String.t(), String.t(), map()) :: {:ok, map()} | {:error, String.t()}
  def run(python, script, payload)
      when is_binary(python) and is_binary(script) and is_map(payload) do
    path =
      Path.join(
        System.tmp_dir!(),
        "attesto_client_python_#{System.unique_integer([:positive])}.json"
      )

    File.write!(path, JSON.encode!(payload))

    try do
      case System.cmd(python, [script_path(script), path], stderr_to_stdout: true) do
        {output, 0} -> {:ok, output |> last_json_line!() |> JSON.decode!()}
        {output, _status} -> {:error, String.trim(output)}
      end
    after
      File.rm(path)
    end
  end

  defp ensure_pyjwt(python) do
    case System.cmd(python, ["-c", "import jwt"], stderr_to_stdout: true) do
      {_output, 0} -> {:ok, python}
      {output, _status} -> {:skip, "PyJWT unavailable: #{String.trim(output)}"}
    end
  end

  defp script_path(script), do: Path.expand("../python/#{script}", __DIR__)

  defp last_json_line!(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.reverse()
    |> Enum.find(&String.starts_with?(&1, "{"))
    |> case do
      nil -> raise "python parity helper emitted no JSON: #{output}"
      line -> line
    end
  end
end
