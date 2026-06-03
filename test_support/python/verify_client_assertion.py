"""Independent reference verifier for a private_key_jwt client assertion.

Reads a JSON file: {"assertion", "public_jwk", "audience"} and verifies the
assertion with PyJWT (an independent, non-Elixir JWT implementation), enforcing
the signature, expiry, and audience. Prints {"claims": {...}} as the last JSON
line on success, or {"error": "..."} and a non-zero exit on failure.

This is the external "Leg A" parity check: an artifact AttestoClient builds must
be accepted by a reference verifier, not only by attesto's own verifier.
"""

import json
import sys

import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm, OKPAlgorithm


def load_key(public_jwk):
    kty = public_jwk["kty"]
    raw = json.dumps(public_jwk)
    if kty == "EC":
        return ECAlgorithm.from_jwk(raw)
    if kty == "RSA":
        return RSAAlgorithm.from_jwk(raw)
    if kty == "OKP":
        return OKPAlgorithm.from_jwk(raw)
    raise ValueError("unsupported kty: %s" % kty)


def main():
    data = json.load(open(sys.argv[1]))
    assertion = data["assertion"]
    public_jwk = data["public_jwk"]
    audience = data["audience"]
    alg = public_jwk.get("alg") or data.get("alg")

    key = load_key(public_jwk)
    claims = jwt.decode(
        assertion,
        key,
        algorithms=[alg],
        audience=audience,
        options={"require": ["exp", "iat"]},
    )
    print(json.dumps({"claims": claims}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - surface any failure to the caller
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)
