import { describe, expect, test } from "vitest";
import { fingerprint } from "../src/index.js";

describe("fingerprint()", () => {
  test("flags sqlmap as likely_scanner regardless of score", () => {
    const r = fingerprint({ "User-Agent": "sqlmap/1.7.2" }, "/login");
    expect(r.verdict).toBe("likely_scanner");
    expect(r.tags.some((t) => t.includes("ua:scanner:sqlmap"))).toBe(true);
  });

  test("flags GPT-mentioning UA as likely_ai", () => {
    const r = fingerprint(
      { "User-Agent": "GPT-4 powered scanner" },
      "/admin",
    );
    expect(["likely_ai", "likely_scanner"]).toContain(r.verdict);
    expect(r.score).toBeGreaterThan(40);
  });

  test("clean browser request is likely_human", () => {
    const r = fingerprint(
      {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        Cookie: "session=abc",
      },
      "/",
    );
    expect(r.verdict).toBe("likely_human");
    expect(r.score).toBe(0);
  });

  test("missing accept-language adds tag and score", () => {
    const r = fingerprint({ "User-Agent": "Mozilla/5.0" }, "/");
    expect(r.tags).toContain("no_accept_lang");
  });

  test("probe path adds tag", () => {
    const r = fingerprint({ "User-Agent": "curl/8" }, "/.env");
    expect(r.tags.some((t) => t.startsWith("probe_path:/.env"))).toBe(true);
  });

  test("score is capped at 100", () => {
    const r = fingerprint(
      {
        "User-Agent":
          "gpt-4 claude gemini llama langchain autogpt pentestgpt",
      },
      "/.env",
    );
    expect(r.score).toBeLessThanOrEqual(100);
  });

  test("case-insensitive header lookup", () => {
    const r = fingerprint({ "user-agent": "sqlmap/1.0" }, "/");
    expect(r.verdict).toBe("likely_scanner");
  });
});
