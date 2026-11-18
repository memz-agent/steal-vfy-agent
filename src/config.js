"use strict";

const fs = require("fs");
const path = require("path");

/**
 * Runtime config from environment. Secrets are NEVER hardcoded:
 *  - AGENT_GAMES_HMAC_SECRET: platform-issued, shown once via the
 *    dashboard "Rotate Secret" for THIS agent. Required at runtime.
 * Strategy (not secret-critical, but keep params/salt/commitment in sync —
 * recompute with `npm run commitment` after any change):
 *  - STEAL_VFY_PARAMS: 8 comma-separated integers (default 10,0,0,0,0,0,0,0)
 *  - STEAL_VFY_SALT:   decimal field element blinding the commitment
 *  - STEAL_VFY_COMMITMENT: decimal Poseidon(params, salt); if unset it is
 *    recomputed from params+salt at startup.
 * KURIER_API_KEY is intentionally NOT used: for Steal the VFY the arena
 * re-verifies the Groth16 proof embedded in the turn response against its
 * own VK (build guide: policyProof.proof is REQUIRED and "The platform
 * re-verifies this offline against its own VK"); proofReference is an
 * optional audit pointer only, so no Kurier submission is needed.
 */

const DEFAULT_PARAMS = ["10", "0", "0", "0", "0", "0", "0", "0"];

function loadDotEnv() {
  const envPath = path.join(__dirname, "..", ".env");
  try {
    for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
      if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
    }
  } catch {
    /* no .env file — fine */
  }
}

function loadConfig() {
  loadDotEnv();
  const rawParams = process.env.STEAL_VFY_PARAMS || DEFAULT_PARAMS.join(",");
  const params = rawParams.split(",").map((x) => x.trim());
  if (params.length !== 8 || params.some((x) => !/^\d+$/.test(x))) {
    throw new Error(`STEAL_VFY_PARAMS must be 8 non-negative integers, got: ${rawParams}`);
  }
  return {
    port: Number(process.env.PORT || 8080),
    hmacSecret: process.env.AGENT_GAMES_HMAC_SECRET || "",
    circuitsDir: path.join(__dirname, "..", "circuits"),
    strategyParams: params,
    strategySalt: process.env.STEAL_VFY_SALT || "",
    strategyCommitment: process.env.STEAL_VFY_COMMITMENT || "",
    seenStorePath: process.env.SEEN_STORE_PATH || "",
  };
}

module.exports = { loadConfig, DEFAULT_PARAMS };
