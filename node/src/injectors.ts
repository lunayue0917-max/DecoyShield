/**
 * Pure-function injectors — TypeScript port of `decoyshield/injectors.py`.
 *
 *   import { injectHtml, injectJson, injectHeaders, bait, isScanner } from "decoyshield";
 *
 *   const body = injectHtml("<html><body>hi</body></html>");
 *   const data = injectJson({ users: [] });
 *   const hdrs = injectHeaders({ "Content-Type": "text/html" });
 *   if (isScanner(req.headers, req.path)) { ... }
 */

import { DEFAULT_RESPONSE_HEADERS, PAYLOADS } from "./payloads.js";
import { type HeaderLike, fingerprint } from "./detector.js";

export type Channel =
  | "comment"
  | "hidden_div"
  | "white_text"
  | "hidden_input";

export const DEFAULT_CHANNELS: Channel[] = [
  "comment",
  "hidden_div",
  "white_text",
];

const ALL_CHANNELS = new Set<Channel>([
  "comment",
  "hidden_div",
  "white_text",
  "hidden_input",
]);

const ALREADY_INJECTED_MARKER = 'data-decoyshield="1"';

export function bait(
  name: string = "moral_lock",
  payloads: Record<string, string> = PAYLOADS,
): string {
  if (!(name in payloads)) {
    throw new Error(
      `Unknown payload ${JSON.stringify(name)}. ` +
        `Available: ${Object.keys(payloads).sort().join(", ")}`,
    );
  }
  return payloads[name];
}

export interface InjectHtmlOptions {
  payloads?: Record<string, string>;
  channels?: Channel[];
}

export function injectHtml(
  html: string,
  options: InjectHtmlOptions = {},
): string {
  if (html.includes(ALREADY_INJECTED_MARKER)) return html;

  const src = options.payloads ?? PAYLOADS;
  const channels = (options.channels ?? DEFAULT_CHANNELS).filter((c) =>
    ALL_CHANNELS.has(c),
  );
  const pieces: string[] = [];

  if (channels.includes("comment")) {
    for (const [name, body] of Object.entries(src)) {
      pieces.push(`<!-- decoyshield:${name}\n${body}\n-->`);
    }
  }

  if (channels.includes("hidden_div")) {
    const joined = Object.entries(src)
      .map(([name, body]) => `[${name}]\n${body}`)
      .join("\n\n");
    pieces.push(
      `<div style="display:none" aria-hidden="true" ` +
        `${ALREADY_INJECTED_MARKER}>${escapeText(joined)}</div>`,
    );
  }

  if (channels.includes("white_text")) {
    const joined = Object.values(src).join(" ");
    pieces.push(
      `<span style="color:#fff;background:#fff;font-size:1px;` +
        `position:absolute;left:-9999px">${escapeText(joined)}</span>`,
    );
  }

  if (channels.includes("hidden_input")) {
    for (const [name, body] of Object.entries(src)) {
      pieces.push(
        `<input type="hidden" name="_decoyshield_${name}" ` +
          `value="${escapeAttr(body)}">`,
      );
    }
  }

  const bundle = pieces.join("\n");
  if (!bundle) return html;

  const match = /<\/body\s*>/i.exec(html);
  if (match) {
    return (
      html.slice(0, match.index) + bundle + "\n" + html.slice(match.index)
    );
  }
  return html + "\n" + bundle;
}

export interface InjectJsonOptions {
  payloads?: Record<string, string>;
  key?: string;
}

export function injectJson<T extends object>(
  data: T,
  options: InjectJsonOptions = {},
): T & { [k: string]: unknown } {
  const src = options.payloads ?? PAYLOADS;
  const key = options.key ?? "_debug";
  return {
    ...data,
    [key]: {
      _audit: src["moral_lock"] ?? "",
      _internal_note: src["token_blackhole"] ?? "",
      _handshake: src["traceback"] ?? "",
      hint: "see X-Audit-Notice header; not for production parsing",
    },
  };
}

export function injectHeaders(
  headers?: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = { ...(headers ?? {}) };
  for (const [k, v] of Object.entries(DEFAULT_RESPONSE_HEADERS)) {
    if (!Object.keys(out).some((existing) => existing.toLowerCase() === k.toLowerCase())) {
      out[k] = v;
    }
  }
  return out;
}

export function isScanner(
  headers: HeaderLike,
  path: string = "",
  method: string = "GET",
): boolean {
  const { verdict } = fingerprint(headers, path, method);
  return (
    verdict === "likely_scanner" ||
    verdict === "likely_ai" ||
    verdict === "likely_automation"
  );
}

function escapeText(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escapeAttr(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
