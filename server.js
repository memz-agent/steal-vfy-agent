"use strict";

const http = require("http");
const { loadConfig } = require("./src/config");
const { StealHandler, SIGNATURE_HEADER } = require("./src/handler");
const { SeenStore } = require("./src/store");

/**
 * Plain Node HTTP server (same shape as the Proof Gatekeeper agent).
 * Routes:
 *   POST /agent   — registered agent endpoint (preflight + turn envelopes)
 *   GET  /agent   — health check { ok: true, protocolVersion: "v1" }
 *   GET  /health  — same health payload
 * Register the FULL path (e.g. https://<host>/agent) as the endpoint.
 */
const MAX_BODY_BYTES = 1_048_576;

function createAgentServer() {
  const cfg = loadConfig();
  if (!cfg.hmacSecret) {
    console.warn("[steal] WARNING: AGENT_GAMES_HMAC_SECRET is not set — POSTs will fail with 500 until it is.");
  }
  if (!cfg.strategySalt && !cfg.strategyCommitment) {
    console.warn("[steal] WARNING: STEAL_VFY_SALT is not set — turn proofs cannot be generated.");
  }
  const handler = new StealHandler(cfg, new SeenStore(cfg.seenStorePath));

  return http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const isAgentPath = url.pathname === "/agent" || url.pathname === "/";

    if (req.method === "GET" && (isAgentPath || url.pathname === "/health")) {
      const r = handler.health();
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(r.body);
      return;
    }

    if (req.method === "POST" && isAgentPath) {
      const chunks = [];
      let size = 0;
      let tooLarge = false;
      req.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          tooLarge = true;
          res.writeHead(413, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "payload_too_large" }));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", async () => {
        if (tooLarge) return;
        const rawBody = Buffer.concat(chunks);
        const signature = req.headers[SIGNATURE_HEADER];
        const result = await handler.handlePost(rawBody, Array.isArray(signature) ? signature[0] : signature);
        const headers = { "content-type": "application/json" };
        if (result.signature) headers[SIGNATURE_HEADER] = result.signature;
        res.writeHead(result.status, headers);
        res.end(result.body);
      });
      req.on("error", () => {
        if (!res.headersSent) res.writeHead(400);
        res.end();
      });
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
}

if (require.main === module) {
  const cfg = loadConfig();
  const server = createAgentServer();
  server.listen(cfg.port, () => {
    console.log(`[steal] Steal the VFY agent listening on :${cfg.port} (POST /agent)`);
  });
}

module.exports = { createAgentServer };
