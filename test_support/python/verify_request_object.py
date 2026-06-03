"""Independent reference verifier for a JAR request object (RFC 9101).

Reads {"request_object", "public_jwk", "audience"} and verifies the request
object with PyJWT (independent of Elixir/attesto), enforcing signature, audience,
and the presence of exp/nbf/iat. Prints {"header": {...}, "claims": {...}} as the
last JSON line on success; {"error": "..."} and a non-zero exit on failure.

External "Leg A" parity: an artifact AttestoClient builds must be accepted by a
reference verifier, not only by attesto's own.
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
    token = data["request_object"]
    public_jwk = data["public_jwk"]
    audience = data["audience"]
    alg = public_jwk.get("alg") or data.get("alg")

    key = load_key(public_jwk)
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(
        token,
        key,
        algorithms=[alg],
        audience=audience,
        options={"require": ["exp", "nbf", "iat"]},
    )
    print(json.dumps({"header": header, "claims": claims}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - surface any failure to the caller
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)
