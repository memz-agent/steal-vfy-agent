"use strict";

const crypto = require("crypto");
const { signBody, verifyBodySignature } = require("./hmac");
const { decideMove } = require("./strategy");
const { Prover, computeCommitment, computePublicInputsHash } = require("./prover");

const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const EVENT_ID = "steal-the-vfy";
const PROTOCOL_VERSION = "v1";
const CIRCUIT_VERSION = "v1";
const SIGNATURE_HEADER = "x-agent-games-signature";

/**
 * Steal the VFY request handling (framework-agnostic; shared by server.js
 * and any serverless adapter).
 *
 * Pipeline:
 *   1. Verify HMAC over the RAW body vs x-agent-games-signature BEFORE
 *      parsing (same convention as the Proof Gatekeeper agent, whose
 *      preflight passes on this platform).
 *   2. Preflight (type agent-games.preflight.v1) -> signed
 *      { ok: true, protocolVersion: "v1" }.
 *   3. Turn envelope (eventId "steal-the-vfy"): replay cached answer for
 *      a redelivered (matchId, turn); otherwise decide via the
 *      circuit-mirroring strategy, generate a REAL Groth16 policy proof
 *      with the official artifacts, locally verify it, and return the
 *      documented response schema, signed.
 *
 * Failure posture: a turn we cannot prove must still be answered if at
 * all possible (a timeout is -1/turn and a silent agent keeps
 * forfeiting). If proving fails unexpectedly, we answer with the
 * policy-conformant action and policyProof: null rather than not
 * answering at all — but with a strategy that mirrors the circuit this
 * path should never trigger (tests prove the conformant moves).
 */
class StealHandler {
  constructor(cfg, store) {
    this.cfg = cfg;
    this.store = store;
    this.prover = new Prover(cfg.circuitsDir);
    this._commitment = cfg.strategyCommitment || null;
  }

  async commitment() {
    if (!this._commitment) {
      if (!this.cfg.strategySalt) {
        throw new Error("STEAL_VFY_SALT not set and no STEAL_VFY_COMMITMENT given");
      }
      this._commitment = await computeCommitment(this.cfg.strategyParams, this.cfg.strategySalt);
    }
    return this._commitment;
  }

  health() {
    return {
      status: 200,
      body: JSON.stringify({ ok: true, protocolVersion: PROTOCOL_VERSION }),
      signature: null,
    };
  }

  async handlePost(rawBody, signatureHeader) {
    if (!this.cfg.hmacSecret) {
      return {
        status: 500,
        body: JSON.stringify({ error: "server_misconfigured", detail: "AGENT_GAMES_HMAC_SECRET not set" }),
        signature: null,
      };
    }
    if (!verifyBodySignature(this.cfg.hmacSecret, rawBody, signatureHeader)) {
      return { status: 401, body: JSON.stringify({ error: "invalid_signature" }), signature: null };
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return { status: 400, body: JSON.stringify({ error: "invalid_json" }), signature: null };
    }

    if (envelope.type === PREFLIGHT_TYPE) {
      return this.signed(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    }

    if (envelope.eventId === EVENT_ID && envelope.matchId && Number.isInteger(envelope.turn)) {
      try {
        return await this.handleTurn(envelope);
      } catch (err) {
        console.error("[steal] turn handling error:", err.message);
        // Fail open to a HOLD answer rather than silence: an unanswered
        // turn costs -1 AND forfeits the extraction window.
        return this.signed(200, {
          matchId: envelope.matchId,
          turn: envelope.turn,
          action: { type: "HOLD" },
          policyProof: null,
          agentTimestamp: new Date().toISOString(),
          idempotencyKey: idemKey(envelope.matchId, envelope.turn),
        });
      }
    }

    return { status: 400, body: JSON.stringify({ error: "unknown_envelope" }), signature: null };
  }

  async handleTurn(envelope) {
    const cacheKey = `${envelope.matchId}:${envelope.turn}`;
    const cached = this.store.getResponse(cacheKey);
    if (cached) return this.signedRaw(200, cached);

    const commitment = await this.commitment();

    // Sanity: the platform freezes the commitment at pairing; if the
    // envelope's frozen hash is not ours, our proofs will be rejected —
    // log loudly but still play (nothing better exists).
    const frozen = envelope.strategyCommitment && envelope.strategyCommitment.hash;
    if (frozen && BigInt(frozen).toString() !== BigInt(commitment).toString()) {
      console.error(
        `[steal] WARNING: envelope commitment ${frozen} != local commitment ${commitment} — registered strategy mismatch`
      );
    }

    const move = decideMove(envelope.state, this.cfg.strategyParams);
    const selfBalance = String(envelope.state.selfBalance);
    const opponentBalance = String(envelope.state.opponentBalance);

    const action = { type: move.type };
    if (move.type === "EXTRACT") action.amount = move.amountNum; // amount ONLY for EXTRACT — schema rejects it otherwise

    let policyProof = null;
    try {
      const input = this.prover.buildInput({
        commitment,
        matchId: envelope.matchId,
        turn: envelope.turn,
        selfBalance,
        opponentBalance,
        actionCode: move.actionCode,
        amount: move.amountNum,
        salt: this.cfg.strategySalt,
        strategyParams: this.cfg.strategyParams,
      });
      const { proof, publicSignals } = await this.prover.prove(input);
      const ok = await this.prover.verify(publicSignals, proof);
      if (!ok) throw new Error("local verification failed");
      policyProof = {
        circuitVersion: CIRCUIT_VERSION,
        proof,
        public_signals: publicSignals,
        publicInputsHash: computePublicInputsHash({
          commitment,
          matchId: envelope.matchId,
          turn: envelope.turn,
          selfBalance,
          opponentBalance,
          actionCode: move.actionCode,
          amount: move.amountNum,
        }),
      };
    } catch (err) {
      console.error("[steal] proving failed:", err.message);
    }

    const result = this.signed(200, {
      matchId: envelope.matchId,
      turn: envelope.turn,
      action,
      policyProof,
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: idemKey(envelope.matchId, envelope.turn),
    });
    this.store.recordResponse(cacheKey, result.body);
    return result;
  }

  signed(status, obj) {
    return this.signedRaw(status, JSON.stringify(obj));
  }

  signedRaw(status, body) {
    return { status, body, signature: signBody(this.cfg.hmacSecret, body) };
  }
}

/** Deterministic per-(match,turn) idempotency key; never reused across turns. */
function idemKey(matchId, turn) {
  return crypto.createHash("sha256").update(`steal-vfy:${matchId}:${turn}`).digest("hex").slice(0, 32);
}

module.exports = { StealHandler, PREFLIGHT_TYPE, EVENT_ID, PROTOCOL_VERSION, SIGNATURE_HEADER };
