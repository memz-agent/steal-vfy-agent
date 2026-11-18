# memz-steal-vfy-agent — Steal the VFY (zkVerify Agent Games)

A second Agent Games agent for @njmfdln (GitHub memz-agent), entering
**Steal the VFY**. Built 2026-11-18. Status: **built and tested locally;
NOT deployed, NOT registered** — deployment + dashboard steps below are
for the operator to execute.

## The game (official sources)

- 20 turns/match, both agents start at 100 VFY, highest balance wins.
  Actions: HOLD (free) / FORTIFY (costs 2, blocks up to 6 of incoming
  extraction that turn) / EXTRACT N (free, max 10; a fortified opponent
  reduces the gain by 6). 7 Swiss rounds -> top 16 knockout.
- Every turn response must carry a real Groth16 proof (circuit
  `vfy-policy`, bn128, vk_hash
  `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`)
  that the move follows the strategy committed before pairing.
  Invalid/missing proof = -2 and the turn resolves as HOLD.
- Late entry is explicitly allowed by the event page: "register
  mid-tournament to join from the next Swiss round, until the final
  round is paired". Live state on 2026-11-18 ~07:53 WIB: current round
  **R5**, 53 agents paired, NO LIVE MATCHES at check time — rounds 6-7
  were still to be paired.

## Strategy (circuit-bound — read this before "improving" it)

The vfy-policy circuit enforces ONE parametric threshold policy; a move
that deviates cannot produce a proof (verified locally — the prover
throws). The circuit's decision tree over private `strategyParams[0..7]`:

1. `selfBalance < params[1]` -> FORTIFY
2. `params[3] == 0 AND opponentBalance > params[2]` -> EXTRACT `params[0]`
3. otherwise -> HOLD  (`amount` must be 0 for HOLD/FORTIFY, exactly
   `params[0]` for EXTRACT)

The policy check ignores turn number and fortification timers, so
policies like "fortify when ahead late" are **not expressible**.

Chosen params **[10, 0, 0, 0, 0, 0, 0, 0]** = always EXTRACT 10, the
strictly dominant line in the documented payoff matrix (per-turn
balance-difference swing: EXTRACT scores +20/+10/0 vs HOLD/FORTIFY/
EXTRACT opponents; every alternative scores <= against each).

Commitment = Poseidon(params[0..7], salt) (circomlib Poseidon):

- params: `10,0,0,0,0,0,0,0`
- salt: in `.env` (`STEAL_VFY_SALT`) — keep it with the deployment env
- commitment (dec): `154653782591132043133546647677491571165101441316629090992788907782401072890`
- **commitment (hex, register this): `0x005787eb9dbb6b0463f318c41075f3ff7213a2302e0ca0b7a2664680df4e9efa`**

Recompute any time with `npm run commitment`.

## Protocol implementation

- `POST /agent` — full handler path must be registered (root 404 fails
  preflight). GET `/agent` or `/health` -> `{ ok: true, protocolVersion: "v1" }`.
- Inbound: HMAC-SHA256 over the RAW body vs `x-agent-games-signature`
  before parsing (hex digest; base64 of the same MAC also accepted —
  same convention as the Proof Gatekeeper agent, whose preflight passes).
- Preflight (`type: agent-games.preflight.v1`) -> signed
  `{ ok: true, protocolVersion: "v1" }`.
- Turn envelope (`eventId: "steal-the-vfy"`) -> signed response:
  `{ matchId, turn, action: { type, amount? }, policyProof:
     { circuitVersion: "v1", proof, public_signals, publicInputsHash },
     agentTimestamp, idempotencyKey }`.
  `amount` is present ONLY for EXTRACT (the schema rejects it otherwise).
  `public_signals` are the circuit's 9 signals in output-then-public
  order: `[output, commitment, matchId, turn, selfBalance,
  opponentBalance, action, amount, circuitVersion]`.
  `publicInputsHash` is the optional audit pointer, computed exactly per
  the build guide: keccak256 of the ABI-packed 32-byte words
  `[commitment, matchId(uuid hex), turn, selfBalance, opponentBalance,
  actionCode, amount, 1]`.
- Every proof is generated locally with snarkjs from the OFFICIAL
  artifacts in `circuits/` (downloaded from agentgames.zkverify.io;
  md5-identical to the copies in a public competitor repo) and verified
  locally against the official VK before the response goes out.
- Redelivered (matchId, turn) envelopes replay the identical recorded
  response (idempotency).
- **No Kurier key is used.** For this track the arena re-verifies the
  proof embedded in the turn response against its own VK (build guide:
  policyProof.proof is REQUIRED, "The platform re-verifies this offline
  against its own VK"; event page: "The platform verifies every proof
  against its own registered zkVerify key"). `proofReference` is an
  optional audit pointer only.

## Run locally

```
npm install
npm run export-vk   # writes circuits/verification_key.json from the official zkey
npm test            # full suite: preflight, proofs vs official VK, negatives, 3 simulated matches
npm start           # serves on $PORT (default 8080)
```

`.env` needs `AGENT_GAMES_HMAC_SECRET` (production: the NEW agent's own
secret from the dashboard Rotate Secret — NOT the gatekeeper agent's),
`STEAL_VFY_SALT`, optionally `STEAL_VFY_PARAMS` / `STEAL_VFY_COMMITMENT`.

## Remaining operator steps (dashboard — NOT done by this build)

1. Deploy this service to a public HTTPS host (same pattern as the
   gatekeeper agent: Railway) with the env above; confirm
   `GET https://<host>/agent` returns the health payload.
2. Dashboard -> register a NEW agent (the existing memz-gatekeeper is
   entered in Proof Gatekeeper; one agent may enter only one event, max
   3 agents per participant). Name e.g. `memz-stealer`. Endpoint =
   `https://<host>/agent` (full path).
3. Dashboard -> My Agents -> Edit agent (the new agent) -> Rotate
   Secret; put the one-time plaintext into the deployment env as
   `AGENT_GAMES_HMAC_SECRET`; restart the service.
4. In the same Edit agent screen, Steal the VFY section: register the
   strategy commitment hex
   `0x005787eb9dbb6b0463f318c41075f3ff7213a2302e0ca0b7a2664680df4e9efa`
   with circuit version v1. This must be active BEFORE the next round
   pairs — R6 pairing is imminent (current round R5 on 18 Nov).
5. Run preflight from the dashboard; confirm the agent shows ACTIVE,
   then complete one practice turn.
6. Confirm the agent appears as entered in Steal the VFY / is paired
   from the next Swiss round (R6, or R7 at the latest — entry closes
   once the final round is paired; season ends 21 Nov 22:00 UTC).
7. Wallet: prize claiming later requires the account's connected
   wallet address (Binance Web3 0xcc77...6BcBC per the user's earlier
   choice) — account-level, separate from this agent build.
