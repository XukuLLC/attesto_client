defmodule AttestoClient.Wallet.Presentation.CertificateTrust do
  @moduledoc """
  Bounded X.509 trust validation for wallet presentation requests and issuer provenance.

  This public compatibility module delegates validation to `Attesto.X509`.
  Existing function names, options, return values, and errors are preserved.

  `verify/2` accepts a leaf-first DER certificate chain and explicit DER trust
  anchors in `:trusted_certificates`. It validates the complete path with OTP's
  PKIX implementation, then applies an optional `:certificate_trust` callback
  for additional host policy. The callback cannot replace path validation.
  Returns the verified leaf public JWK and authority key identifiers from the
  validated chain. Hosts still own ecosystem policy and revocation checking.

  `:purpose` defaults to `:generic`. The `:mdoc_issuer` purpose recognizes a
  critical mdoc document-signer extended key usage on the leaf certificate.
  It does not accept that extension on a CA or bypass any path-validation error.

  PSS-specific SubjectPublicKeyInfo keys are rejected throughout the selected
  path, including its trust anchor, until complete PSS parameter propagation
  is supported. `rsaEncryption` parameters must be NULL; absent parameters are
  accepted for interoperability. Other parameter values fail closed.
  """

  @doc "Validate a leaf-first DER chain using `Attesto.X509.verify/2`."
  @spec verify([binary()], [Attesto.X509.option()]) ::
          {:ok, Attesto.X509.verified()} | {:error, Attesto.X509.verify_error()}
  defdelegate verify(chain, opts), to: Attesto.X509

  @doc "Decode a bounded JOSE certificate chain using `Attesto.X509.decode_x5c/1`."
  @spec decode_x5c(term()) :: {:ok, [binary()]} | {:error, :invalid_certificate}
  defdelegate decode_x5c(chain), to: Attesto.X509
end
