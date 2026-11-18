"use strict";

// Export circuits/verification_key.json from the OFFICIAL
// vfy-policy_final.zkey (needed for local proof verification in tests
// and in the handler). Usage: npm run export-vk

const { execFileSync } = require("child_process");
const path = require("path");

const dir = path.join(__dirname, "..", "circuits");
execFileSync(
  process.platform === "win32" ? "npx.cmd" : "npx",
  ["snarkjs", "zkey", "export", "verificationkey",
   path.join(dir, "vfy-policy_final.zkey"),
   path.join(dir, "verification_key.json")],
  { stdio: "inherit" }
);
console.log("Wrote circuits/verification_key.json");
