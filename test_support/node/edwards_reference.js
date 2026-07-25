const crypto = require("crypto");
const fs = require("fs");

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function oidcHash(value, alg, curve) {
  let hash;

  if (["EdDSA", "Ed25519"].includes(alg) && curve === "Ed25519") {
    hash = crypto.createHash("sha512");
  } else if (["EdDSA", "Ed448"].includes(alg) && curve === "Ed448") {
    hash = crypto.createHash("shake256", { outputLength: 114 });
  } else {
    throw new TypeError(
      `incompatible Edwards algorithm and curve: ${alg}/${curve}`,
    );
  }

  const digest = hash.update(value, "utf8").digest();
  return digest.subarray(0, digest.length / 2).toString("base64url");
}

function sign(input) {
  const header = { alg: input.alg, kid: input.kid, typ: input.typ || "JWT" };
  const claims = { ...input.claims };

  for (const [claim, value] of Object.entries(input.detached_hashes || {})) {
    claims[claim] = oidcHash(value, input.alg, input.curve);
  }

  const encodedHeader = base64urlJson(header);
  const encodedClaims = base64urlJson(claims);
  const signingInput = Buffer.from(
    `${encodedHeader}.${encodedClaims}`,
    "ascii",
  );
  const key = crypto.createPrivateKey({
    key: input.private_jwk,
    format: "jwk",
  });
  const signature = crypto.sign(null, signingInput, key).toString("base64url");

  return {
    token: `${encodedHeader}.${encodedClaims}.${signature}`,
    header,
    claims,
  };
}

function verify(input) {
  const parts = input.token.split(".");
  if (parts.length !== 3)
    throw new TypeError("compact JWT must have three segments");

  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  const signingInput = Buffer.from(
    `${encodedHeader}.${encodedClaims}`,
    "ascii",
  );
  const signature = Buffer.from(encodedSignature, "base64url");
  const key = crypto.createPublicKey({ key: input.public_jwk, format: "jwk" });

  if (!crypto.verify(null, signingInput, key, signature)) {
    throw new Error("Edwards signature verification failed");
  }

  return {
    header: JSON.parse(
      Buffer.from(encodedHeader, "base64url").toString("utf8"),
    ),
    claims: JSON.parse(
      Buffer.from(encodedClaims, "base64url").toString("utf8"),
    ),
  };
}

const input = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const result = input.operation === "sign" ? sign(input) : verify(input);
process.stdout.write(`${JSON.stringify(result)}\n`);
