"use strict";

/**
 * Local test suite for the Steal the VFY agent. No network, no platform.
 *
 * Covers:
 *  1. Preflight handshake over real HTTP (platform-style HMAC signing).
 *  2. Signature rejection.
 *  3. Turn -> EXTRACT 10: response schema, REAL Groth16 proof verified
 *     against the OFFICIAL verification key (exported from the official
 *     zkey), public_signals order/content, and the docs-formula
 *     publicInputsHash recomputed independently byte-by-byte.
 *  4. Turn with opponentBalance = 0 -> HOLD, `amount` field ABSENT,
 *     proof verifies.
 *  5. Circuit-enforcement negatives: a move that violates the committed
 *     policy (HOLD when EXTRACT is mandated; EXTRACT amount != params[0])
 *     makes fullProve throw — proving the strategy must mirror the
 *     circuit, and ours does.
 *  6. FORTIFY branch with alternate params [10,30,0,0,...]: selfBalance
 *     25 -> FORTIFY proves; EXTRACT at selfBalance 25 throws.
 *  7. Commitment stability/format.
 *  8. Full 20-turn match simulations through the handler against
 *     HOLD-bot (expect win), EXTRACT-bot (expect draw), FORTIFY-bot
 *     (expect win), using the documented resolver rules.
 */

const assert = require("assert");
const crypto = require("crypto");
const http = require("http");
const { ethers } = require("ethers");

process.env.AGENT_GAMES_HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "local-test-secret-steal-vfy";
const { loadConfig } = require("../src/config");
const { StealHandler } = require("../src/handler");
const { SeenStore } = require("../src/store");
const { Prover, computeCommitment, commitmentToHex } = require("../src/prover");
const { decideMove, matchIdToBigInt } = require("../src/strategy");
const { signBody, verifyBodySignature } = require("../src/hmac");
const { createAgentServer } = require("../server");

const cfg = loadConfig();
const SECRET = cfg.hmacSecret;
const MATCH_ID = "9f4e1b2a-3c5d-4e6f-8a9b-1c2d3e4f5a6b";

let passed = 0;
function ok(name) {
  passed += 1;
  console.log(`  PASS ${name}`);
}

function turnEnvelope(matchId, turn, selfBalance, opponentBalance, commitmentHex) {
  return {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "competition",
    matchId,
    turn,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    state: {
      selfBalance: String(selfBalance),
      opponentBalance: String(opponentBalance),
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
    },
    strategyCommitment: { hash: commitmentHex },
    resolverVersion: "v1",
    nonce: crypto.randomBytes(4).toString("hex"),
  };
}

async function postSigned(handler, obj) {
  const raw = Buffer.from(JSON.stringify(obj), "utf8");
  return handler.handlePost(raw, signBody(SECRET, raw));
}

/** Independent byte-level recomputation of the docs' publicInputsHash. */
function expectedPublicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, actionCode, amount }) {
  const word = (v) => {
    const hex = BigInt(v).toString(16).padStart(64, "0");
    assert.strictEqual(hex.length, 64);
    return Buffer.from(hex, "hex");
  };
  const packed = Buffer.concat([
    word(commitment),
    word(matchIdToBigInt(matchId)),
    word(turn),
    word(selfBalance),
    word(opponentBalance),
    word(actionCode),
    word(amount),
    word(1),
  ]);
  assert.strictEqual(packed.length, 256);
  return ethers.keccak256(ethers.hexlify(packed));
}

/** Documented resolver: simultaneous actions on prior balances. */
function resolveTurn(self, opp) {
  // self/opp: { balance, move: {type, amountNum} }
  const gainOf = (attacker, defender) => {
    if (attacker.move.type !== "EXTRACT") return 0;
    let gain = Math.min(attacker.move.amountNum, defender.balance);
    if (defender.move.type === "FORTIFY") gain = Math.max(0, gain - 6);
    return gain;
  };
  const sGain = gainOf(self, opp);
  const oGain = gainOf(opp, self);
  let sBal = self.balance + sGain - oGain;
  let oBal = opp.balance + oGain - sGain;
  if (self.move.type === "FORTIFY") sBal -= Math.min(2, Math.max(0, sBal));
  if (opp.move.type === "FORTIFY") oBal -= Math.min(2, Math.max(0, oBal));
  return { sBal: Math.max(0, sBal), oBal: Math.max(0, oBal) };
}

(async () => {
  console.log("== setup");
  const commitment = await computeCommitment(cfg.strategyParams, cfg.strategySalt);
  const commitmentHex = commitmentToHex(commitment);
  console.log(`  params=${cfg.strategyParams.join(",")} commitment=${commitmentHex}`);
  assert.strictEqual(commitment, await computeCommitment(cfg.strategyParams, cfg.strategySalt), "commitment must be deterministic");
  assert.match(commitmentHex, /^0x[0-9a-f]{64}$/);
  ok("commitment deterministic, 0x + 64 hex");

  const store = new SeenStore("");
  const handler = new StealHandler(cfg, store);
  const prover = new Prover(cfg.circuitsDir);

  console.log("== 1. preflight over HTTP");
  const server = createAgentServer();
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;
  const preflight = { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: "", nonce: "abc123" };
  const rawPre = JSON.stringify(preflight);
  const resPre = await new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, path: "/agent", method: "POST", headers: { "content-type": "application/json", "x-agent-games-signature": signBody(SECRET, Buffer.from(rawPre)) } },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
      }
    );
    req.on("error", reject);
    req.end(rawPre);
  });
  assert.strictEqual(resPre.status, 200);
  assert.deepStrictEqual(JSON.parse(resPre.body), { ok: true, protocolVersion: "v1" });
  assert.ok(verifyBodySignature(SECRET, Buffer.from(resPre.body), resPre.headers["x-agent-games-signature"]), "preflight response must be validly signed");
  server.close();
  ok("preflight -> signed { ok: true, protocolVersion: 'v1' }");

  console.log("== 2. bad signature rejected");
  const rawBad = Buffer.from(JSON.stringify(preflight));
  const resBad = await handler.handlePost(rawBad, "0".repeat(64));
  assert.strictEqual(resBad.status, 401);
  ok("invalid HMAC -> 401");

  console.log("== 3. turn: EXTRACT 10 with real proof");
  const env3 = turnEnvelope(MATCH_ID, 3, 95, 105, commitmentHex);
  const res3 = await postSigned(handler, env3);
  assert.strictEqual(res3.status, 200);
  const body3 = JSON.parse(res3.body);
  assert.strictEqual(body3.matchId, MATCH_ID);
  assert.strictEqual(body3.turn, 3);
  assert.deepStrictEqual(body3.action, { type: "EXTRACT", amount: 10 });
  assert.ok(body3.policyProof, "policyProof must be present");
  assert.strictEqual(body3.policyProof.circuitVersion, "v1");
  assert.ok(body3.policyProof.proof && body3.policyProof.proof.pi_a, "groth16 proof present");
  const ps = body3.policyProof.public_signals;
  assert.strictEqual(ps.length, 9, "9 public signals");
  assert.strictEqual(ps[1], commitment, "signals[1] = commitment");
  assert.strictEqual(ps[2], matchIdToBigInt(MATCH_ID).toString(), "signals[2] = matchId");
  assert.strictEqual(ps[3], "3", "signals[3] = turn");
  assert.strictEqual(ps[4], "95", "signals[4] = selfBalance");
  assert.strictEqual(ps[5], "105", "signals[5] = opponentBalance");
  assert.strictEqual(ps[6], "2", "signals[6] = action EXTRACT");
  assert.strictEqual(ps[7], "10", "signals[7] = amount");
  assert.strictEqual(ps[8], "1", "signals[8] = circuitVersion");
  assert.strictEqual(await prover.verify(ps, body3.policyProof.proof), true, "proof must verify against OFFICIAL vk");
  const expectedHash = expectedPublicInputsHash({ commitment, matchId: MATCH_ID, turn: 3, selfBalance: 95, opponentBalance: 105, actionCode: 2, amount: 10 });
  assert.strictEqual(body3.policyProof.publicInputsHash, expectedHash, "publicInputsHash must match docs keccak formula");
  assert.ok(verifyBodySignature(SECRET, Buffer.from(res3.body), res3.signature), "turn response signed");
  ok("EXTRACT turn: schema + proof verifies vs official VK + signals order + publicInputsHash formula");

  console.log("== 3b. redelivery replays identical body");
  const res3b = await postSigned(handler, env3);
  assert.strictEqual(res3b.body, res3.body);
  ok("idempotent replay");

  console.log("== 4. turn: opponent broke -> HOLD, amount absent, proof verifies");
  const env4 = turnEnvelope(MATCH_ID, 4, 190, 0, commitmentHex);
  const res4 = await postSigned(handler, env4);
  const body4 = JSON.parse(res4.body);
  assert.deepStrictEqual(body4.action, { type: "HOLD" });
  assert.ok(!("amount" in body4.action), "amount must be omitted for HOLD");
  assert.strictEqual(body4.policyProof.public_signals[6], "0");
  assert.strictEqual(await prover.verify(body4.policyProof.public_signals, body4.policyProof.proof), true);
  ok("HOLD turn: no amount field, proof verifies");

  console.log("== 5. circuit enforcement negatives");
  const baseInput = {
    commitment, matchId: MATCH_ID, turn: 5, selfBalance: 95, opponentBalance: 105,
    salt: cfg.strategySalt, strategyParams: cfg.strategyParams,
  };
  await assert.rejects(
    prover.prove(prover.buildInput({ ...baseInput, actionCode: 0, amount: 0 })),
    "HOLD while policy mandates EXTRACT must fail to prove"
  );
  await assert.rejects(
    prover.prove(prover.buildInput({ ...baseInput, actionCode: 2, amount: 5 })),
    "EXTRACT amount != params[0] must fail to prove"
  );
  await assert.rejects(
    prover.prove(prover.buildInput({ ...baseInput, actionCode: 1, amount: 0 })),
    "FORTIFY while policy mandates EXTRACT must fail to prove"
  );
  ok("non-conformant moves cannot prove (witness assertion)");

  console.log("== 6. FORTIFY branch with params [10,30,0,0,0,0,0,0]");
  const altParams = ["10", "30", "0", "0", "0", "0", "0", "0"];
  const altCommitment = await computeCommitment(altParams, cfg.strategySalt);
  const mv = decideMove({ selfBalance: "25", opponentBalance: "100" }, altParams);
  assert.strictEqual(mv.type, "FORTIFY");
  const altInput = prover.buildInput({
    commitment: altCommitment, matchId: MATCH_ID, turn: 1, selfBalance: 25, opponentBalance: 100,
    actionCode: 1, amount: 0, salt: cfg.strategySalt, strategyParams: altParams,
  });
  const altProof = await prover.prove(altInput);
  assert.strictEqual(await prover.verify(altProof.publicSignals, altProof.proof), true);
  await assert.rejects(
    prover.prove(prover.buildInput({
      commitment: altCommitment, matchId: MATCH_ID, turn: 1, selfBalance: 25, opponentBalance: 100,
      actionCode: 2, amount: 10, salt: cfg.strategySalt, strategyParams: altParams,
    })),
    "EXTRACT below the fortify threshold must fail to prove"
  );
  ok("params[1] fortify threshold enforced by the circuit");

  console.log("== 7. full-match simulations (20 turns each, every turn proven)");
  const bots = {
    "HOLD-bot": () => ({ type: "HOLD", amountNum: 0 }),
    "EXTRACT-bot": () => ({ type: "EXTRACT", amountNum: 10 }),
    "FORTIFY-bot": () => ({ type: "FORTIFY", amountNum: 0 }),
  };
  const outcomes = {};
  for (const [name, botFn] of Object.entries(bots)) {
    const matchId = crypto.randomUUID();
    let sBal = 100, oBal = 100;
    for (let turn = 1; turn <= 20; turn++) {
      const env = turnEnvelope(matchId, turn, sBal, oBal, commitmentHex);
      const res = await postSigned(handler, env);
      const body = JSON.parse(res.body);
      assert.ok(body.policyProof, `turn ${turn} vs ${name}: proof required`);
      const myMove = { type: body.action.type, amountNum: body.action.amount || 0 };
      const r = resolveTurn({ balance: sBal, move: myMove }, { balance: oBal, move: botFn() });
      sBal = r.sBal; oBal = r.oBal;
    }
    outcomes[name] = { sBal, oBal };
    console.log(`    vs ${name}: final ${sBal} - ${oBal}`);
  }
  assert.ok(outcomes["HOLD-bot"].sBal > outcomes["HOLD-bot"].oBal, "must beat HOLD-bot");
  assert.strictEqual(outcomes["EXTRACT-bot"].sBal, outcomes["EXTRACT-bot"].oBal, "must draw EXTRACT-bot");
  assert.ok(outcomes["FORTIFY-bot"].sBal > outcomes["FORTIFY-bot"].oBal, "must beat FORTIFY-bot");
  ok("simulations: W vs HOLD-bot, D vs EXTRACT-bot, W vs FORTIFY-bot");

  console.log(`\nALL ${passed} TEST GROUPS PASSED`);
})().catch((e) => {
  console.error("\nTEST FAILURE:", e);
  process.exit(1);
});
