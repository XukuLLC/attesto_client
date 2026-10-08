# Encryption is an optional capability of the supported core dependency range.
# The coordinated candidate runs every test; older-core compatibility runs
# explicitly exclude only tests that require that capability.
jwe_available? =
  Code.ensure_loaded?(Attesto.JWE) and function_exported?(Attesto.JWE, :encrypt, 4) and
    function_exported?(Attesto.JWE, :decrypt, 3)

ExUnit.start(exclude: if(jwe_available?, do: [], else: [requires_core_jwe: true]))
