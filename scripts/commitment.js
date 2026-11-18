"use strict";

// Compute the Steal the VFY strategy commitment for the configured
// params + salt. Usage: npm run commitment
// Prints the value in decimal (circuit input / STEAL_VFY_COMMITMENT)
// and hex (register the HEX in the dashboard:
//   My Agents -> Edit agent -> Steal the VFY -> strategy commitment).

const { loadConfig } = require("../src/config");
const { computeCommitment, commitmentToHex } = require("../src/prover");

(async () => {
  const cfg = loadConfig();
  if (!cfg.strategySalt) {
    console.error("STEAL_VFY_SALT is not set (see .env). Generate one first.");
    process.exit(1);
  }
  const dec = await computeCommitment(cfg.strategyParams, cfg.strategySalt);
  console.log("Strategy params :", cfg.strategyParams.join(","));
  console.log("Salt            :", cfg.strategySalt);
  console.log("Commitment (dec):", dec);
  console.log("Commitment (hex):", commitmentToHex(dec));
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
