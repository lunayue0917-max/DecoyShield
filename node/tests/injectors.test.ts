import { describe, expect, test } from "vitest";
import {
  bait,
  injectHeaders,
  injectHtml,
  injectJson,
  isScanner,
  MORAL_LOCK,
  TOKEN_BLACKHOLE,
} from "../src/index.js";

// ── bait() ─────────────────────────────────────────────────────────────

describe("bait()", () => {
  test("returns moral_lock by default", () => {
    expect(bait()).toContain("HONEYPOT_DETECTED");
  });

  test("returns named payload", () => {
    expect(bait("token_blackhole")).toBe(TOKEN_BLACKHOLE);
    expect(bait("moral_lock")).toBe(MORAL_LOCK);
  });

  test("throws on unknown name", () => {
    expect(() => bait("not-a-real-payload")).toThrow(/Unknown payload/);
  });

  test("accepts custom payload set", () => {
    expect(bait("custom", { custom: "hello" })).toBe("hello");
  });
});

// ── injectHtml() ───────────────────────────────────────────────────────

describe("injectHtml()", () => {
  test("inserts before </body>", () => {
    const out = injectHtml("<html><body><h1>hi</h1></body></html>");
    expect(out).toMatch(/<\/body><\/html>$/);
    expect(out).toContain("decoyshield");
    expect(out).toContain("HONEYPOT_DETECTED");
    expect(out).toContain("ChaoticWAF");
    expect(out).toContain("DEBUG_MODE_HANDSHAKE");
  });

  test("appends when no </body>", () => {
    const src = "<h1>raw fragment</h1>";
    const out = injectHtml(src);
    expect(out.startsWith(src)).toBe(true);
    expect(out).toContain("decoyshield");
  });

  test("is case-insensitive on </BODY>", () => {
    const out = injectHtml("<html><body>x</BODY></html>");
    expect(out).toContain("decoyshield");
    expect(out).toContain("</BODY></html>");
  });

  test("is idempotent", () => {
    const src = "<html><body>x</body></html>";
    const once = injectHtml(src);
    const twice = injectHtml(once);
    expect(once).toBe(twice);
  });

  test("channels can be restricted", () => {
    const out = injectHtml("<html><body>x</body></html>", {
      channels: ["comment"],
    });
    expect(out).toContain("<!-- decoyshield:");
    expect(out).not.toContain("display:none");
    expect(out).not.toContain("color:#fff");
  });

  test("hidden_input channel produces input tags", () => {
    const out = injectHtml("<html><body>x</body></html>", {
      channels: ["hidden_input"],
    });
    expect(out).toContain(
      '<input type="hidden" name="_decoyshield_moral_lock"',
    );
  });

  test("unknown channels are ignored", () => {
    const out = injectHtml("<html><body>x</body></html>", {
      channels: ["not_a_channel" as never, "comment"],
    });
    expect(out).toContain("<!-- decoyshield:");
  });

  test("custom payloads override defaults", () => {
    const out = injectHtml("<html><body/></html>", {
      payloads: { a: "alpha", b: "beta" },
    });
    expect(out).toContain("alpha");
    expect(out).toContain("beta");
    expect(out).not.toContain("HONEYPOT_DETECTED");
  });
});

// ── injectJson() ───────────────────────────────────────────────────────

describe("injectJson()", () => {
  test("adds _debug key", () => {
    const out = injectJson({ users: [1, 2, 3] });
    expect(out).toHaveProperty("_debug");
    expect((out._debug as any)._audit).toBeTruthy();
  });

  test("preserves original keys", () => {
    const out = injectJson({ users: [1, 2, 3], count: 3 });
    expect(out.users).toEqual([1, 2, 3]);
    expect(out.count).toBe(3);
  });

  test("returns copy not mutation", () => {
    const src = { a: 1 };
    const out = injectJson(src);
    expect("_debug" in src).toBe(false);
    expect("_debug" in out).toBe(true);
  });

  test("custom key works", () => {
    const out = injectJson({ a: 1 }, { key: "_internal" });
    expect(out).toHaveProperty("_internal");
    expect("_debug" in out).toBe(false);
  });
});

// ── injectHeaders() ────────────────────────────────────────────────────

describe("injectHeaders()", () => {
  test("adds payload headers", () => {
    const out = injectHeaders({ "Content-Type": "text/html" });
    expect(out).toHaveProperty("X-Audit-Notice");
    expect(out).toHaveProperty("X-Debug-Trace");
    expect(out).toHaveProperty("X-Bypass-Protocol");
    expect(out["Content-Type"]).toBe("text/html");
  });

  test("does not overwrite existing keys", () => {
    const out = injectHeaders({ "X-Audit-Notice": "mine" });
    expect(out["X-Audit-Notice"]).toBe("mine");
  });

  test("accepts undefined", () => {
    const out = injectHeaders();
    expect(out).toHaveProperty("X-Audit-Notice");
    expect(Object.keys(out)).toHaveLength(3);
  });
});

// ── isScanner() ────────────────────────────────────────────────────────

describe("isScanner()", () => {
  test("true for sqlmap UA", () => {
    expect(isScanner({ "User-Agent": "sqlmap/1.7.2" })).toBe(true);
  });

  test("true for GPT UA", () => {
    expect(isScanner({ "User-Agent": "GPT-4 powered scanner" })).toBe(true);
  });

  test("false for browser UA", () => {
    const browser = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "Accept-Language": "en-US,en;q=0.9",
      Cookie: "session=abc",
    };
    expect(isScanner(browser, "/")).toBe(false);
  });

  test("uses path signals", () => {
    expect(isScanner({ "User-Agent": "curl/8" }, "/.env")).toBe(true);
  });
});
