"use strict";

const crypto = require("crypto");

/**
 * HMAC signing / verification for the `x-agent-games-signature` header.
 *
 * The platform signs the RAW request body and expects the same over the raw
 * response body. The public docs do not pin the digest encoding, so:
 *  - outbound: HMAC-SHA256, secret as UTF-8 string, lowercase hex digest
 *    (the convention a live preflight-passing agent uses);
 *  - inbound: accept the identical MAC bytes encoded as hex or base64
 *    (optional "sha256=" prefix), compared in constant time. Accepting two
 *    encodings of the same MAC is representation tolerance, not a weakening:
 *    a caller still has to know the secret.
 */

function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function macBytes(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest();
}

function decodeCandidate(headerValue) {
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice("sha256=".length).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  } catch {
    /* fall through */
  }
  return null;
}

function verifyBodySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const candidate = decodeCandidate(headerValue);
  if (!candidate) return false;
  const expected = macBytes(secret, rawBody);
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

/** BN128 (alt_bn128) scalar field prime. */
const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Deterministic per-task salt for the circuit's private `salt` input:
 * HMAC(secret, "gatekeeper-salt:" + task_id) reduced mod p. Deterministic so
 * a redelivered task reproduces identical proof inputs; bound to the secret
 * so third parties cannot predict it.
 */
function deriveSalt(secret, taskId) {
  const digest = crypto
    .createHmac("sha256", secret || "gatekeeper-local-dev")
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

module.exports = { signBody, verifyBodySignature, deriveSalt, BN128_PRIME };
