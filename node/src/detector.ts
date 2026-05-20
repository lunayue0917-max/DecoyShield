/**
 * Request fingerprinting — TypeScript port of `decoyshield/detector.py`.
 *
 * Heuristically classifies a request as ``likely_scanner`` /
 * ``likely_ai`` / ``likely_automation`` / ``likely_human`` / ``unknown``
 * with a numeric score and a list of matched tags.
 */

export type Verdict =
  | "likely_scanner"
  | "likely_ai"
  | "likely_automation"
  | "likely_human"
  | "unknown";

export interface FingerprintResult {
  verdict: Verdict;
  tags: string[];
  score: number;
}

export const AI_UA_KEYWORDS: Record<string, string[]> = {
  openai: ["gpt", "openai", "chatgpt"],
  anthropic: ["claude", "anthropic"],
  google: ["gemini", "bard", "palm"],
  meta: ["llama"],
  scanner: [
    "sqlmap", "nikto", "nuclei", "burp", "zap", "acunetix",
    "wpscan", "dirb", "gobuster", "ffuf", "wfuzz", "feroxbuster",
  ],
  automation: [
    "python-requests", "python-httpx", "aiohttp", "curl",
    "wget", "go-http-client", "scrapy", "axios", "okhttp",
    "node-fetch",
  ],
  agent_framework: [
    "langchain", "autogpt", "pentestgpt", "agentgpt",
    "crewai", "autogen", "babyagi",
  ],
};

export const PROBE_PATHS: string[] = [
  "/.env", "/.git", "/admin", "/wp-login", "/wp-admin",
  "/phpmyadmin", "/api/v1", "/swagger", "/.well-known/security.txt",
  "/backup", "/config", "/.aws", "/.ssh",
];

const HEAVY_CATEGORIES = new Set([
  "openai", "anthropic", "google", "meta", "agent_framework",
]);

export type HeaderLike =
  | Record<string, string | string[] | undefined>
  | { get(name: string): string | null };

function getHeader(headers: HeaderLike, name: string): string {
  // Express/Connect req.headers form
  if (typeof (headers as any).get === "function") {
    const v = (headers as any).get(name);
    return typeof v === "string" ? v : "";
  }
  const obj = headers as Record<string, string | string[] | undefined>;
  // Case-insensitive lookup
  const lower = name.toLowerCase();
  for (const k of Object.keys(obj)) {
    if (k.toLowerCase() === lower) {
      const v = obj[k];
      if (Array.isArray(v)) return v.join(", ");
      return v ?? "";
    }
  }
  return "";
}

export function fingerprint(
  headers: HeaderLike,
  path: string = "",
  _method: string = "GET",
): FingerprintResult {
  const ua = (getHeader(headers, "User-Agent") || "").toLowerCase();
  const tags: string[] = [];
  let score = 0;

  for (const [category, keywords] of Object.entries(AI_UA_KEYWORDS)) {
    for (const kw of keywords) {
      if (ua.includes(kw)) {
        tags.push(`ua:${category}:${kw}`);
        score += HEAVY_CATEGORIES.has(category) ? 25 : 15;
      }
    }
  }

  if (!getHeader(headers, "Accept-Language")) {
    tags.push("no_accept_lang");
    score += 10;
  }
  if (!getHeader(headers, "Cookie")) {
    tags.push("no_cookie");
    score += 5;
  }

  if (PROBE_PATHS.some((p) => path.startsWith(p))) {
    tags.push(`probe_path:${path}`);
    score += 20;
  }

  score = Math.min(score, 100);

  // Scanner UA is a high-confidence signal regardless of score.
  let verdict: Verdict;
  if (tags.some((t) => t.startsWith("ua:scanner"))) {
    verdict = "likely_scanner";
  } else if (score >= 50) {
    verdict = "likely_ai";
  } else if (score >= 25) {
    verdict = "likely_automation";
  } else if (score === 0) {
    verdict = "likely_human";
  } else {
    verdict = "unknown";
  }

  return { verdict, tags, score };
}
