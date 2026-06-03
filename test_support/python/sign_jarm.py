"""Independent reference SIGNER for a JARM authorization response (the flipped
parity direction).

Reads {"private_jwk", "alg", "claims"} and signs the claims into a JWT with
PyJWT (an independent, non-Elixir implementation). Prints {"jwt": "..."} as the
last JSON line. AttestoClient.JARM.verify/3 must then accept this token - proving
the Elixir verifier reads what an independent implementation writes.
"""

import json
import sys

import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm, OKPAlgorithm


def load_private(private_jwk):
    kty = private_jwk["kty"]
    raw = json.dumps(private_jwk)
    if kty == "EC":
        return ECAlgorithm.from_jwk(raw)
    if kty == "RSA":
        return RSAAlgorithm.from_jwk(raw)
    if kty == "OKP":
        return OKPAlgorithm.from_jwk(raw)
    raise ValueError("unsupported kty: %s" % kty)


def main():
    data = json.load(open(sys.argv[1]))
    key = load_private(data["private_jwk"])
    headers = {"kid": data["private_jwk"]["kid"]} if "kid" in data["private_jwk"] else None
    token = jwt.encode(data["claims"], key, algorithm=data["alg"], headers=headers)
    print(json.dumps({"jwt": token}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - surface any failure to the caller
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)
