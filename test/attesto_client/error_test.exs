defmodule AttestoClient.ErrorTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Error

  test "walks every documented error union and projects its fixed reason atoms" do
    paths = Path.wildcard("lib/**/*.ex")

    for path <- paths,
        [_, union] <-
          Regex.scan(
            ~r/@type\s+(?:error|refresh_error)\s*::(.*?)(?=\n\s*@|\n\s*def|\z)/s,
            File.read!(path)
          ),
        [_, name] <- Regex.scan(~r/(?<!:):([a-zA-Z_][a-zA-Z_0-9?!]*)/, union) do
      reason = String.to_existing_atom(name)
      assert Error.project(reason) == %{code: reason, http_status: nil}, "#{path}: #{name}"
    end
  end

  test "strips provider text, credentials, exceptions and callback identifiers" do
    secret = %{
      "error" => "invented_provider_code",
      "error_description" => "secret",
      "access_token" => "credential"
    }

    assert Error.project({:oauth_error, 401, secret}) == %{code: :oauth_error, http_status: 401}

    assert Error.project({:authorization_error, secret, secret}) == %{
             code: :authorization_error,
             http_status: nil
           }

    assert Error.project({:jwks_refresh_failed, {:http_status, 503}}) == %{
             code: :jwks_refresh_failed,
             http_status: 503
           }

    assert Error.project({"credential-id", {:http_status, 502}}) == %{
             code: :presentation_error,
             http_status: 502
           }

    for tag <- [
          :coordinator_exit,
          :dpop,
          :client_assertion,
          :client_attestation,
          :transport,
          :select_authorization_server,
          :signing_failed,
          :credential_endpoint_mismatch,
          :invalid_credential_endpoint_metadata,
          :key_attestation,
          :invalid_state,
          :duplicate_callback_parameter,
          :transaction_store,
          :deferred_sleep,
          :refresh_task_exit,
          :invalid_fetch_result,
          :no_match,
          :not_sent
        ] do
      assert Error.project({tag, secret}) == %{code: tag, http_status: nil}
    end

    for unknown <- [
          secret,
          "secret",
          :unrecognized_provider_reason,
          {:unknown, secret},
          %RuntimeError{message: "secret"}
        ] do
      assert Error.project(unknown) == %{code: :unknown_error, http_status: nil}
    end
  end

  test "only valid HTTP statuses are kept, including through the error envelope" do
    for status <- [99, 600, "401", nil, %{"secret" => true}] do
      assert Error.project({:oauth_error, status, "secret"}) == %{
               code: :oauth_error,
               http_status: nil
             }
    end

    for tag <- [:http_status, :unexpected_http_status], status <- [100, 400, 599] do
      assert Error.project({:error, {tag, status}}) == %{code: tag, http_status: status}
    end
  end
end
