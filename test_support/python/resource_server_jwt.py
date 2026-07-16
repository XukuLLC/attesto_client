"""Independent PyJWT parity helper for RFC 9068 access tokens.

The ``sign`` operation creates an access token that the Elixir resource-server
verifier must accept. The ``verify`` operation validates an Elixir-generated
token with an independent JWT implementation. Input and output are JSON files
and JSON lines so ExUnit can use the helper without Python package bindings.
"""

import json
import sys

import jwt
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm


def load_key(jwk):
    raw = json.dumps(jwk)
    if jwk["kty"] == "RSA":
        return RSAAlgorithm.from_jwk(raw)
    if jwk["kty"] == "EC":
        return ECAlgorithm.from_jwk(raw)
    if jwk["kty"] == "OKP":
        return OKPAlgorithm.from_jwk(raw)
    raise ValueError("unsupported kty: %s" % jwk["kty"])


def sign(data):
    token = jwt.encode(
        data["claims"],
        load_key(data["private_jwk"]),
        algorithm=data["alg"],
        headers=data["headers"],
    )
    return {"token": token}


def verify(data):
    header = jwt.get_unverified_header(data["token"])
    if header.get("typ", "").lower() not in ("at+jwt", "application/at+jwt"):
        raise ValueError("unexpected typ")

    claims = jwt.decode(
        data["token"],
        load_key(data["public_jwk"]),
        algorithms=[data["alg"]],
        audience=data["audience"],
        issuer=data["issuer"],
        options={
            "require": [
                "iss",
                "aud",
                "sub",
                "client_id",
                "exp",
                "iat",
                "jti",
            ]
        },
    )
    return {"header": header, "claims": claims}


def main():
    with open(sys.argv[1], encoding="utf-8") as handle:
        data = json.load(handle)

    if data["operation"] == "sign":
        result = sign(data)
    elif data["operation"] == "verify":
        result = verify(data)
    else:
        raise ValueError("unknown operation")

    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - report the reference failure
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)
