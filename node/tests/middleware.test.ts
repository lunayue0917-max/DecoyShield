import { describe, expect, test } from "vitest";
import express from "express";
import request from "supertest";
import { decoyshield } from "../src/index.js";

function makeApp(opts?: Parameters<typeof decoyshield>[0]) {
  const app = express();
  app.use(decoyshield(opts));
  app.get("/", (_req, res) =>
    res
      .type("html")
      .send("<html><body>hello world</body></html>"),
  );
  app.get("/data", (_req, res) =>
    res.json({ users: [1, 2, 3], count: 3 }),
  );
  app.get("/raw", (_req, res) =>
    res.type("text/plain").send("plain text response"),
  );
  app.get("/internal/dash", (_req, res) =>
    res
      .type("html")
      .send("<html><body>internal</body></html>"),
  );
  return app;
}

describe("express middleware", () => {
  test("adds bait headers to HTML responses", async () => {
    const r = await request(makeApp()).get("/");
    expect(r.headers["x-audit-notice"]).toBeTruthy();
    expect(r.headers["x-debug-trace"]).toBeTruthy();
    expect(r.headers["x-bypass-protocol"]).toBeTruthy();
  });

  test("injects HTML bait into text/html responses", async () => {
    const r = await request(makeApp()).get("/");
    expect(r.text).toContain("decoyshield");
    expect(r.text).toContain("</body></html>");
    expect(r.text).toContain("hello world");
  });

  test("JSON injection off by default", async () => {
    const r = await request(makeApp()).get("/data");
    expect(r.body).toEqual({ users: [1, 2, 3], count: 3 });
    expect(r.body).not.toHaveProperty("_debug");
  });

  test("JSON injection opt-in", async () => {
    const r = await request(makeApp({ injectJsonBody: true })).get(
      "/data",
    );
    expect(r.body.users).toEqual([1, 2, 3]);
    expect(r.body).toHaveProperty("_debug");
  });

  test("plain text body left unchanged", async () => {
    const r = await request(makeApp()).get("/raw");
    expect(r.text).toBe("plain text response");
  });

  test("can disable header injection", async () => {
    const r = await request(
      makeApp({ injectResponseHeaders: false }),
    ).get("/");
    expect(r.headers["x-audit-notice"]).toBeUndefined();
  });

  test("can disable HTML body injection", async () => {
    const r = await request(makeApp({ injectHtmlBody: false })).get("/");
    expect(r.text).toBe("<html><body>hello world</body></html>");
    // Headers still added
    expect(r.headers["x-audit-notice"]).toBeTruthy();
  });

  test("skipPaths bypasses middleware entirely", async () => {
    const r = await request(
      makeApp({ skipPaths: ["/internal"] }),
    ).get("/internal/dash");
    expect(r.text).toBe("<html><body>internal</body></html>");
    expect(r.headers["x-audit-notice"]).toBeUndefined();
  });

  test("idempotent on already-injected HTML", async () => {
    const app = express();
    app.use(decoyshield());
    app.get("/", (_req, res) =>
      res
        .type("html")
        .send(
          '<html><body><div data-decoyshield="1">x</div></body></html>',
        ),
    );
    const r = await request(app).get("/");
    // The marker should appear exactly once (the one we put in)
    expect(r.text.match(/data-decoyshield="1"/g)).toHaveLength(1);
  });
});
