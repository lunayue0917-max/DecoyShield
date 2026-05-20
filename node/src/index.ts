/**
 * decoyshield (Node.js) — counter-recon honeypot for agentic LLM attackers.
 *
 * Sibling to the Python `decoyshield` package. Same payload set, same
 * fingerprinter, same `inject_html` / `inject_json` semantics — just
 * for Express, Fastify, and plain Node HTTP servers.
 *
 *   import express from "express";
 *   import { decoyshield } from "decoyshield";
 *
 *   const app = express();
 *   app.use(decoyshield());
 *
 *   app.get("/", (_req, res) =>
 *     res.type("html").send("<html><body>hi</body></html>"));
 *
 *   app.listen(3000);
 */

export {
  MORAL_LOCK,
  MORAL_LOCK_TERSE,
  TOKEN_BLACKHOLE,
  TOKEN_BLACKHOLE_ZK,
  TRACEBACK,
  TRACEBACK_OAUTH,
  PAYLOADS,
  DEFAULT_RESPONSE_HEADERS,
} from "./payloads.js";

export {
  type Verdict,
  type FingerprintResult,
  type HeaderLike,
  AI_UA_KEYWORDS,
  PROBE_PATHS,
  fingerprint,
} from "./detector.js";

export {
  type Channel,
  type InjectHtmlOptions,
  type InjectJsonOptions,
  DEFAULT_CHANNELS,
  bait,
  injectHtml,
  injectJson,
  injectHeaders,
  isScanner,
} from "./injectors.js";

export {
  type PayloadEntry,
  type RegisterOptions,
  type ListFilter,
  PayloadRegistry,
  registry,
} from "./registry.js";

export { type MiddlewareOptions, decoyshield } from "./middleware.js";

// Note: the Fastify plugin is exposed via the dedicated `decoyshield/fastify`
// subpath so its `fastify` peer dep stays optional at install time.

export const VERSION = "0.8.0";
