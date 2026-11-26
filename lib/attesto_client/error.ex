defmodule AttestoClient.Error do
  @moduledoc """
  Project client failures to a fixed code and an optional HTTP status.

  Use `project/1` before logging or rendering an error. Provider descriptions,
  response bodies, credentials, callback parameter names, key bytes, and
  exception text are never included. Codes are a closed vocabulary; unknown
  reasons become `:unknown_error`. This function does not choose response text
  or a local response status for a host.

  Bare documented reason atoms retain their names. Payload-bearing tuples
  retain only their fixed tag. `{:authorization_error, error, description}`
  becomes `:authorization_error`, regardless of either provider string.
  `{:oauth_error, status, body}`, `{:http_status, status}`, and
  `{:unexpected_http_status, status}` retain a status only when it is an
  integer from 100 through 599. An issuer refresh wrapper retains a nested
  HTTP status. `{:invalid_state, reason}` becomes `:invalid_state` and never
  returns store details. A presentation's `{query_id, reason}` becomes
  `:presentation_error`, discarding the identifier and retaining only a
  recognized nested HTTP status. All other terms become `:unknown_error`.
  """

  @codes ~w(
    access_denied
    already_exists
    ambiguous_credential_configuration_id
    ambiguous_credential_offer
    ambiguous_key
    auth_time_required
    authorization_error
    authorization_transaction_expired
    blocked_host
    browser_binding_mismatch
    client_assertion
    client_attestation
    client_auth_mismatch
    client_not_allowed
    conflicting_profiles
    connect_options
    coordinator_exit
    credential_configuration_format_mismatch
    credential_configuration_not_advertised
    credential_configuration_type_mismatch
    credential_count_mismatch
    credential_encryption_required
    credential_endpoint_mismatch
    credential_issuer_metadata_mismatch
    credential_issuer_mismatch
    custom_adapter
    custom_finch
    deferred_attempts_exhausted
    deferred_sleep
    deferred_timeout
    deferred_transaction_mismatch
    dpop
    dpop_binding_mismatch
    dpop_key_mismatch
    dpop_proof_required
    dpop_proof_unexpected
    duplicate_callback_parameter
    duplicate_holder_key
    expired
    holder_binding_mismatch
    holder_key_mismatch
    http_status
    id_token_alg_mismatch
    incompatible_verifier_format
    insufficient_scope
    invalid
    invalid_access_token
    invalid_algorithm_policy
    invalid_at_hash
    invalid_attested_keys
    invalid_audience
    invalid_auth_time
    invalid_auth_time_allowance_seconds
    invalid_authorization_code_grant
    invalid_authorization_params
    invalid_azp
    invalid_c_hash
    invalid_callback
    invalid_certificate
    invalid_certification
    invalid_challenge
    invalid_challenge_response
    invalid_claims
    invalid_client_assertion_options
    invalid_client_auth
    invalid_client_id
    invalid_clock_skew_seconds
    invalid_context
    invalid_credential
    invalid_credential_configuration_id
    invalid_credential_configuration_ids
    invalid_credential_configuration_metadata
    invalid_credential_encryption
    invalid_credential_encryption_metadata
    invalid_credential_endpoint_metadata
    invalid_credential_issuer
    invalid_credential_issuer_metadata
    invalid_credential_offer
    invalid_credential_request
    invalid_credential_response
    invalid_credential_response_content_type
    invalid_dcql_query
    invalid_deferred_clock
    invalid_deferred_credential_response
    invalid_deferred_interval
    invalid_deferred_options
    invalid_deferred_sleep
    invalid_dpop_key
    invalid_dpop_nonce
    invalid_encryption_metadata
    invalid_endpoint
    invalid_endpoint_query
    invalid_expected_status
    invalid_expiry_leeway_seconds
    invalid_fapi
    invalid_fetch_result
    invalid_grants
    invalid_haip
    invalid_haip_options
    invalid_htm
    invalid_htu
    invalid_iat
    invalid_instance_key
    invalid_issuer
    invalid_issuer_aliases
    invalid_json
    invalid_jti
    invalid_jwe
    invalid_jwks
    invalid_jwks_uri
    invalid_key
    invalid_key_attestation
    invalid_key_storage
    invalid_kid
    invalid_lifetime
    invalid_max_age
    invalid_max_entries
    invalid_max_token_age_seconds
    invalid_metadata
    invalid_metadata_url
    invalid_nbf
    invalid_nonce
    invalid_nonce_endpoint
    invalid_nonce_response
    invalid_offer
    invalid_options
    invalid_outbound
    invalid_par_option
    invalid_par_response
    invalid_params
    invalid_policy
    invalid_pre_authorized_code
    invalid_pre_authorized_code_grant
    invalid_profile
    invalid_profile_client_auth
    invalid_profile_dpop_key
    invalid_protocol
    invalid_redirect_uri
    invalid_request
    invalid_request_object
    invalid_request_uri_method
    invalid_require_auth_time
    invalid_require_kid
    invalid_require_response_issuer
    invalid_require_typ
    invalid_resolver
    invalid_resource
    invalid_response_content_type
    invalid_response_encryption_key
    invalid_response_mode
    invalid_response_type
    invalid_response_uri
    invalid_s_hash
    invalid_scope
    invalid_scopes
    invalid_selection
    invalid_signature
    invalid_state
    invalid_status_reference
    invalid_status_resolver
    invalid_store
    invalid_subject
    invalid_target
    invalid_text_response
    invalid_time
    invalid_timeout
    invalid_token
    invalid_token_response
    invalid_token_set
    invalid_token_type
    invalid_token_type_hint
    invalid_transaction
    invalid_transaction_data
    invalid_transaction_id
    invalid_transaction_ttl_ms
    invalid_trusted_audiences
    invalid_tx_code
    invalid_typ
    invalid_user_authentication
    invalid_verifier
    invalid_verifier_metadata
    invalid_vp_token
    invalid_wallet_nonce
    invalid_well_known
    invalid_x5c
    issuer_mismatch
    jwks_refresh_failed
    key_attestation
    max_age_exceeded
    metadata_unavailable
    missing_at_hash
    missing_audience
    missing_azp
    missing_browser_binding
    missing_c_hash
    missing_client_id
    missing_code
    missing_code_verifier
    missing_credential_endpoint
    missing_credential_offer
    missing_deferred_endpoint
    missing_dpop_key
    missing_end_session_endpoint
    missing_exp
    missing_format
    missing_holder_binding
    missing_holder_key
    missing_holder_keys
    missing_id_token
    missing_issuer
    missing_kid
    missing_par_endpoint
    missing_pre_authorized_code_grant
    missing_redirect_uri
    missing_refresh_token
    missing_request_encryption_metadata
    missing_response_encryption_metadata
    missing_response_issuer
    missing_revocation_endpoint
    missing_s_hash
    missing_state
    missing_status_trust
    missing_subject
    missing_token_endpoint
    missing_transaction
    missing_trusted
    missing_trusted_certificates
    missing_tx_code
    mixed_authorization_response
    mtls_binding_mismatch
    mtls_cert_required
    mtls_certificate_mismatch
    mtls_certificate_required
    no_authorization_server
    no_match
    nonce_mismatch
    nonce_required
    not_found
    not_sent
    not_yet_valid
    oauth_error
    operation_failed
    outbound_not_supported
    par_required
    profile_client_auth_required
    profile_dpop_required
    profile_mismatch
    profile_scope_required
    profile_token_set_required
    proxy
    refresh_request_mismatch
    refresh_task_exit
    refresh_timeout
    reserved_claim_conflict
    resource_mismatch
    response_encryption_key_mismatch
    response_issuer_not_supported
    response_too_large
    select_authorization_server
    signing_failed
    state_collision
    status_list_fetch_failed
    store_unavailable
    sub_mismatch
    subject_mismatch
    subject_not_allowed
    timeout
    token_lifetime_exceeded
    token_too_old
    transaction_store
    transport
    transport_error
    transport_opts
    unadvertised_authorization_server
    unencrypted_credential_response
    unexpected_http_status
    unexpected_typ
    unix_socket
    unsafe_transport_options
    unsupported_alg
    unsupported_client_id_prefix
    unsupported_confirmation
    unsupported_credential_encryption_algorithm
    unsupported_credential_encryption_method
    unsupported_critical_header
    unsupported_encryption
    unsupported_format
    unsupported_haip_format
    unsupported_key
    unsupported_mdoc
    unsupported_profile_client_auth
    unsupported_request_encryption_key
    unsupported_response_mode
    unsupported_sd_alg
    untrusted_audience
    weak_key
  )a

  @type projection :: %{code: atom(), http_status: 100..599 | nil}

  @doc """
  Return `%{code: code, http_status: status_or_nil}` for a reason.

  Accepts either the reason itself or `{:error, reason}`. The returned code
  comes only from the fixed library vocabulary, never from provider text.
  """
  @spec project(term()) :: projection()
  def project({:error, reason}), do: project(reason)
  def project(reason) when reason in @codes, do: result(reason)

  def project({:authorization_error, _error, _description}), do: result(:authorization_error)
  def project({:oauth_error, status, _body}), do: result(:oauth_error, status)
  def project({:http_status, status}), do: result(:http_status, status)
  def project({:unexpected_http_status, status}), do: result(:unexpected_http_status, status)

  def project({:jwks_refresh_failed, reason}),
    do: result(:jwks_refresh_failed, project(reason).http_status)

  def project({:coordinator_exit, _details}), do: result(:coordinator_exit)
  def project({:dpop, _details}), do: result(:dpop)
  def project({:client_assertion, _details}), do: result(:client_assertion)
  def project({:refresh_task_exit, _details}), do: result(:refresh_task_exit)
  def project({:invalid_fetch_result, _details}), do: result(:invalid_fetch_result)
  def project({:transport, _details}), do: result(:transport)
  def project({:select_authorization_server, _details}), do: result(:select_authorization_server)
  def project({:signing_failed, _details}), do: result(:signing_failed)
  def project({:not_sent, _details}), do: result(:not_sent)

  def project({:credential_endpoint_mismatch, _details}),
    do: result(:credential_endpoint_mismatch)

  def project({:invalid_credential_endpoint_metadata, _details}),
    do: result(:invalid_credential_endpoint_metadata)

  def project({:key_attestation, _details}), do: result(:key_attestation)
  def project({:invalid_state, _details}), do: result(:invalid_state)

  def project({:duplicate_callback_parameter, _details}),
    do: result(:duplicate_callback_parameter)

  def project({:transaction_store, _details}), do: result(:transaction_store)
  def project({:deferred_sleep, _details}), do: result(:deferred_sleep)
  def project({:client_attestation, _details}), do: result(:client_attestation)
  def project({:no_match, _details}), do: result(:no_match)

  def project({query_id, reason}) when is_binary(query_id),
    do: result(:presentation_error, project(reason).http_status)

  def project(_unknown), do: result(:unknown_error)

  defp result(code, status \\ nil)

  defp result(code, status) when is_integer(status) and status in 100..599,
    do: %{code: code, http_status: status}

  defp result(code, _status), do: %{code: code, http_status: nil}
end
