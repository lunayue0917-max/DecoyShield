/**
 * Fastify plugin.
 *
 *   import Fastify from "fastify";
 *   import { decoyshieldPlugin } from "decoyshield/fastify";
 *
 *   const app = Fastify();
 *   await app.register(decoyshieldPlugin);
 *   app.get("/", async () => "<html><body>hi</body></html>");
 *
 * Registered as an ``onSend`` hook so it sees the final payload and
 * has a chance to rewrite it before the wire is touched.
 */

import { DEFAULT_RESPONSE_HEADERS } from "./payloads.js";
import { injectHtml, injectJson } from "./injectors.js";

export interface FastifyPluginOptions {
  injectResponseHeaders?: boolean;
  injectHtmlBody?: boolean;
  injectJsonBody?: boolean;
  skipPaths?: string[];
}

/**
 * A duck-typed Fastify instance shape — narrow enough to compile
 * without depending on `fastify` directly. At runtime the plugin only
 * uses `addHook("onSend", ...)`.
 */
interface FastifyLike {
  addHook: (name: string, handler: (...args: any[]) => any) => unknown;
}

interface FastifyRequestLike {
  url?: string;
  routerPath?: string;
}

interface FastifyReplyLike {
  hasHeader?: (name: string) => boolean;
  header: (name: string, value: string) => unknown;
  getHeader?: (name: string) => string | string[] | number | undefined;
}

/**
 * The Fastify-style plugin. Pass to ``fastify.register(decoyshieldPlugin, options)``.
 *
 * Implemented with a duck-typed Fastify shape so this file compiles
 * without ``fastify`` installed; install ``fastify@>=4`` as a peer to use it.
 */
export async function decoyshieldPlugin(
  fastify: FastifyLike,
  options: FastifyPluginOptions = {},
): Promise<void> {
  const opts = {
    injectResponseHeaders: options.injectResponseHeaders ?? true,
    injectHtmlBody: options.injectHtmlBody ?? true,
    injectJsonBody: options.injectJsonBody ?? false,
    skipPaths: options.skipPaths ?? [],
  };

  fastify.addHook(
    "onSend",
    async (
      request: FastifyRequestLike,
      reply: FastifyReplyLike,
      payload: unknown,
    ): Promise<unknown> => {
      const path = request.url ?? request.routerPath ?? "";
      if (opts.skipPaths.length > 0 && opts.skipPaths.some((p) => path.startsWith(p))) {
        return payload;
      }

      if (opts.injectResponseHeaders) {
        for (const [k, v] of Object.entries(DEFAULT_RESPONSE_HEADERS)) {
          const has =
            typeof reply.hasHeader === "function"
              ? reply.hasHeader(k)
              : reply.getHeader?.(k) !== undefined;
          if (!has) reply.header(k, v);
        }
      }

      const ct = String(
        (reply.getHeader?.("content-type") ?? "") as string,
      ).toLowerCase();

      const payloadText = payloadToString(payload);

      if (opts.injectHtmlBody && ct.includes("text/html") && payloadText !== null) {
        return injectHtml(payloadText);
      }

      if (
        opts.injectJsonBody &&
        ct.includes("application/json") &&
        payloadText !== null
      ) {
        try {
          const data = JSON.parse(payloadText);
          if (data && typeof data === "object" && !Array.isArray(data)) {
            return JSON.stringify(injectJson(data));
          }
        } catch {
          /* fall through */
        }
      }

      return payload;
    },
  );
}

// Mark as a `fastify-plugin`-style plugin so the onSend hook applies to
// the parent Fastify scope instead of being encapsulated. This is what
// the `fastify-plugin` npm package does behind the scenes; we set the
// symbol directly to avoid an extra runtime dependency.
(decoyshieldPlugin as any)[Symbol.for("skip-override")] = true;
(decoyshieldPlugin as any)[Symbol.for("fastify.display-name")] = "decoyshield";
(decoyshieldPlugin as any)[Symbol.for("plugin-meta")] = {
  fastify: "4.x",
  name: "decoyshield",
};

// Default export so users can `app.register(decoyshieldPlugin)` or
// `app.register(decoyshield)` interchangeably.
export default decoyshieldPlugin;

/**
 * Coerce Fastify's onSend payload (string | Buffer | stream | undefined)
 * to a string. Returns null when the payload is not text-shaped (e.g. a
 * stream) and we should pass it through untouched.
 */
function payloadToString(payload: unknown): string | null {
  if (typeof payload === "string") return payload;
  if (payload instanceof Uint8Array) {
    try {
      return Buffer.from(payload).toString("utf-8");
    } catch {
      return null;
    }
  }
  return null;
}
