/**
 * Express / Connect middleware.
 *
 *   import express from "express";
 *   import { decoyshield } from "decoyshield";
 *
 *   const app = express();
 *   app.use(decoyshield());
 *   app.get("/", (_req, res) => res.send("<html><body>hi</body></html>"));
 *
 * The middleware intercepts `res.send`, `res.json`, and `res.end` to
 * add bait headers and (optionally) rewrite the body. Non-HTML/JSON
 * responses pass through untouched aside from headers.
 */

import { DEFAULT_RESPONSE_HEADERS } from "./payloads.js";
import { injectHtml, injectJson } from "./injectors.js";

export interface MiddlewareOptions {
  /** Add ``X-Audit-Notice`` / ``X-Debug-Trace`` / ``X-Bypass-Protocol``. */
  injectResponseHeaders?: boolean;
  /** Rewrite ``text/html`` bodies to embed invisible bait before ``</body>``. */
  injectHtmlBody?: boolean;
  /** Add a ``_debug`` key to ``application/json`` top-level objects. */
  injectJsonBody?: boolean;
  /** Path prefixes to leave untouched. */
  skipPaths?: string[];
}

interface ResLike {
  send: (body: any) => unknown;
  json: (body: any) => unknown;
  end?: (...args: any[]) => unknown;
  setHeader: (name: string, value: string | number | string[]) => unknown;
  getHeader: (name: string) => string | string[] | number | undefined;
  hasHeader?: (name: string) => boolean;
  headersSent?: boolean;
}

interface ReqLike {
  path?: string;
  url?: string;
  originalUrl?: string;
}

/**
 * Returns a connect/express-compatible middleware function.
 *
 * Use with `app.use(decoyshield())` or `app.use(decoyshield({ ... }))`.
 */
export function decoyshield(options: MiddlewareOptions = {}) {
  const opts = {
    injectResponseHeaders: options.injectResponseHeaders ?? true,
    injectHtmlBody: options.injectHtmlBody ?? true,
    injectJsonBody: options.injectJsonBody ?? false,
    skipPaths: options.skipPaths ?? [],
  };

  return function decoyshieldMiddleware(
    req: ReqLike,
    res: ResLike,
    next: (err?: unknown) => void,
  ): void {
    const path = req.path ?? req.url ?? req.originalUrl ?? "";
    if (opts.skipPaths.length > 0 && opts.skipPaths.some((p) => path.startsWith(p))) {
      return next();
    }

    const addBaitHeaders = () => {
      if (!opts.injectResponseHeaders || res.headersSent) return;
      for (const [k, v] of Object.entries(DEFAULT_RESPONSE_HEADERS)) {
        if (!hasHeader(res, k)) res.setHeader(k, v);
      }
    };

    const origSend = res.send.bind(res);
    const origJson = res.json.bind(res);

    res.send = function patchedSend(body: any) {
      addBaitHeaders();
      const ct = String(res.getHeader("Content-Type") ?? "").toLowerCase();
      if (opts.injectHtmlBody && ct.includes("text/html") && typeof body === "string") {
        body = injectHtml(body);
      } else if (
        opts.injectJsonBody &&
        ct.includes("application/json") &&
        body &&
        typeof body === "object" &&
        !Array.isArray(body)
      ) {
        body = injectJson(body);
      }
      return origSend(body);
    };

    res.json = function patchedJson(body: any) {
      addBaitHeaders();
      if (
        opts.injectJsonBody &&
        body &&
        typeof body === "object" &&
        !Array.isArray(body)
      ) {
        body = injectJson(body);
      }
      return origJson(body);
    };

    next();
  };
}

function hasHeader(res: ResLike, name: string): boolean {
  if (typeof res.hasHeader === "function") return res.hasHeader(name);
  return res.getHeader(name) !== undefined;
}
