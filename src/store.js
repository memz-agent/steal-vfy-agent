"use strict";

const fs = require("fs");

/**
 * In-memory idempotency store with optional JSON-file persistence:
 * maps "matchId:turn" -> the exact signed response body, so a redelivered
 * turn envelope replays the identical answer (and idempotency key)
 * instead of re-proving.
 */
class SeenStore {
  constructor(filePath) {
    this.filePath = filePath || "";
    this.responses = new Map();
    if (this.filePath) {
      try {
        const data = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
        for (const [k, v] of Object.entries(data.responses || {})) this.responses.set(k, v);
      } catch {
        /* fresh store */
      }
    }
  }

  getResponse(key) {
    return this.responses.get(key) || null;
  }

  recordResponse(key, body) {
    this.responses.set(key, body);
    this.persist();
  }

  persist() {
    if (!this.filePath) return;
    try {
      fs.writeFileSync(
        this.filePath,
        JSON.stringify({ responses: Object.fromEntries(this.responses) }, null, 2)
      );
    } catch (err) {
      console.error("[store] persist failed:", err.message);
    }
  }
}

module.exports = { SeenStore };
