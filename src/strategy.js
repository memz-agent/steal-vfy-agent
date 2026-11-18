"use strict";

/**
 * Steal the VFY strategy — MUST mirror the vfy-policy circuit exactly.
 *
 * The circuit (official vfy-policy.wasm / vfy-policy_final.zkey, vk_hash
 * 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047)
 * enforces ONE parametric threshold policy over the game state. A move
 * that does not follow the policy cannot produce a valid witness — the
 * prover throws — so the "strategy" is exactly the choice of the 8
 * private strategyParams + salt, committed as
 *   commitment = Poseidon(strategyParams[0..7], salt)   (circomlib Poseidon)
 *
 * Circuit decision tree (cross-verified against the official artifacts by
 * local proving tests, see test/run-tests.js):
 *   1. selfBalance < params[1]                    -> FORTIFY
 *   2. params[3] == 0 AND opponentBalance > params[2] -> EXTRACT params[0]
 *   3. otherwise                                  -> HOLD
 *   amount must be 0 for HOLD/FORTIFY and exactly params[0] for EXTRACT.
 * All comparisons are strict. The circuit's policy check does NOT look at
 * the turn number or the fortification timers, so richer policies
 * ("fortify when ahead late", "extract only if opponent unfortified")
 * are NOT expressible — any such move would fail to prove.
 *
 * Chosen params: [10, 0, 0, 0, 0, 0, 0, 0] — always EXTRACT 10.
 * EXTRACT 10 is strictly dominant in the documented payoff matrix
 * (per-turn balance-difference swing, self action vs opponent action):
 *              opp HOLD   opp FORTIFY   opp EXTRACT
 *   EXTRACT      +20         +10            0
 *   FORTIFY       -4          0           -10
 *   HOLD         -20         -10          -20
 * (FORTIFY costs 2 and blocks 6; EXTRACT is free and takes up to 10.)
 * EXTRACT is >= every alternative against every opponent action, so the
 * thresholds are set to never trigger: params[1]=0 (balance is never < 0,
 * so never FORTIFY) and params[2]=0 (EXTRACT whenever opponentBalance > 0;
 * at opponentBalance == 0 the circuit forces HOLD, which loses nothing —
 * an extraction would take 0 anyway).
 */

const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

function decideMove(state, params) {
  if (!state || typeof state !== "object") {
    throw new Error("missing game state");
  }
  const selfBalance = BigInt(state.selfBalance ?? 0);
  const opponentBalance = BigInt(state.opponentBalance ?? 0);
  const p = params.map((x) => BigInt(x));

  if (selfBalance < p[1]) {
    return { type: "FORTIFY", amountNum: 0, actionCode: ACTION_CODE.FORTIFY };
  }
  if (p[3] === 0n && opponentBalance > p[2]) {
    const amount = Number(p[0]);
    if (!Number.isInteger(amount) || amount < 1 || amount > 10) {
      throw new Error(`invalid extract amount param: ${params[0]}`);
    }
    return { type: "EXTRACT", amountNum: amount, actionCode: ACTION_CODE.EXTRACT };
  }
  return { type: "HOLD", amountNum: 0, actionCode: ACTION_CODE.HOLD };
}

/** UUID (dashes) -> field integer, exactly as the official docs' formula. */
function matchIdToBigInt(matchId) {
  const hex = String(matchId).replace(/^0x/i, "").replace(/-/g, "");
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`invalid matchId: ${matchId}`);
  }
  return BigInt("0x" + hex);
}

module.exports = { ACTION_CODE, decideMove, matchIdToBigInt };
