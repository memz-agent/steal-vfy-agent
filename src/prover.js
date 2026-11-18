"use strict";

const path = require("path");
const fs = require("fs");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { ethers } = require("ethers");
const { matchIdToBigInt } = require("./strategy");

/**
 * Groth16 proving for the official vfy-policy circuit (bn128).
 *
 * Circuit interface (17 inputs; verified against the official artifacts):
 *   public:  commitment, matchId, turnNumber, selfBalance,
 *            opponentBalance, action, amount, circuitVersion
 *   private: salt, strategyParams[0..7]
 * Public signals (9, output-then-public order):
 *   [0] circuit output (a circuit-computed hash of the public inputs —
 *       semantics unpublished; do not assert its value)
 *   [1] commitment  [2] matchId  [3] turnNumber  [4] selfBalance
 *   [5] opponentBalance  [6] action  [7] amount  [8] circuitVersion
 *
 * commitment = Poseidon(strategyParams[0..7], salt) (circomlib Poseidon,
 * 9 inputs). The dashboard registration takes the same value as
 * 0x-prefixed 64-hex.
 */

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

async function computeCommitment(strategyParams, salt) {
  const poseidon = await getPoseidon();
  const preimage = [...strategyParams.map((v) => BigInt(v)), BigInt(salt)];
  const hash = poseidon.F.toObject(poseidon(preimage));
  return hash.toString();
}

function commitmentToHex(commitmentDec) {
  return "0x" + BigInt(commitmentDec).toString(16).padStart(64, "0");
}

/**
 * The OPTIONAL policyProof.publicInputsHash audit pointer, computed
 * exactly as the official build guide specifies: keccak256 of the
 * ABI-packed (32-byte big-endian each) fields
 * [commitment, matchId (uuid hex), turn, selfBalance, opponentBalance,
 *  actionCode, amount, circuitVersion=1].
 * The platform verifies the actual proof + public_signals; this hash is
 * an audit pointer only — but we compute it correctly anyway.
 */
function computePublicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, actionCode, amount }) {
  const word = (v) => ethers.zeroPadValue(ethers.toBeHex(BigInt(v)), 32);
  const matchWord = word(matchIdToBigInt(matchId));
  const packed = ethers.concat([
    word(commitment),
    matchWord,
    word(turn),
    word(selfBalance),
    word(opponentBalance),
    word(actionCode),
    word(amount),
    word(1),
  ]);
  return ethers.keccak256(packed);
}

class Prover {
  constructor(circuitsDir) {
    this.wasmPath = path.join(circuitsDir, "vfy-policy.wasm");
    this.zkeyPath = path.join(circuitsDir, "vfy-policy_final.zkey");
    this.vkPath = path.join(circuitsDir, "verification_key.json");
    this._vk = null;
  }

  vk() {
    if (!this._vk) this._vk = JSON.parse(fs.readFileSync(this.vkPath, "utf8"));
    return this._vk;
  }

  buildInput({ commitment, matchId, turn, selfBalance, opponentBalance, actionCode, amount, salt, strategyParams }) {
    return {
      commitment: String(commitment),
      matchId: matchIdToBigInt(matchId).toString(),
      turnNumber: String(turn),
      selfBalance: String(selfBalance),
      opponentBalance: String(opponentBalance),
      action: String(actionCode),
      amount: String(amount),
      circuitVersion: "1",
      salt: String(salt),
      strategyParams: strategyParams.map(String),
    };
  }

  async prove(input) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, this.wasmPath, this.zkeyPath);
    return { proof, publicSignals };
  }

  async verify(publicSignals, proof) {
    return snarkjs.groth16.verify(this.vk(), publicSignals, proof);
  }
}

module.exports = { Prover, computeCommitment, commitmentToHex, computePublicInputsHash };
