import { describe, expect, test } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import { decoyshieldPlugin } from "../src/fastify.js";

async function makeApp(
  opts?: Parameters<typeof decoyshieldPlugin>[1],
): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(decoyshieldPlugin as any, opts);
  app.get("/", async (_req, reply) => {
    reply.type("text/html");
    return "<html><body>hello world</body></html>";
  });
  app.get("/data", async () => ({ users: [1, 2, 3], count: 3 }));
  app.get("/raw", async (_req, reply) => {
    reply.type("text/plain");
    return "plain text response";
  });
  app.get("/internal/dash", async (_req, reply) => {
    reply.type("text/html");
    return "<html><body>internal</body></html>";
  });
  await app.ready();
  return app;
}

describe("fastify plugin", () => {
  test("adds bait headers", async () => {
    const app = await makeApp();
    const r = await app.inject({ method: "GET", url: "/" });
    expect(r.headers["x-audit-notice"]).toBeTruthy();
    expect(r.headers["x-debug-trace"]).toBeTruthy();
    expect(r.headers["x-bypass-protocol"]).toBeTruthy();
    await app.close();
  });

  test("injects HTML bait", async () => {
    const app = await makeApp();
    const r = await app.inject({ method: "GET", url: "/" });
    expect(r.body).toContain("decoyshield");
    expect(r.body).toContain("</body></html>");
    expect(r.body).toContain("hello world");
    await app.close();
  });

  test("JSON injection off by default", async () => {
    const app = await makeApp();
    const r = await app.inject({ method: "GET", url: "/data" });
    const body = JSON.parse(r.body);
    expect(body).toEqual({ users: [1, 2, 3], count: 3 });
    expect(body).not.toHaveProperty("_debug");
    await app.close();
  });

  test("JSON injection opt-in", async () => {
    const app = await makeApp({ injectJsonBody: true });
    const r = await app.inject({ method: "GET", url: "/data" });
    const body = JSON.parse(r.body);
    expect(body.users).toEqual([1, 2, 3]);
    expect(body).toHaveProperty("_debug");
    await app.close();
  });

  test("plain text left untouched", async () => {
    const app = await makeApp();
    const r = await app.inject({ method: "GET", url: "/raw" });
    expect(r.body).toBe("plain text response");
    await app.close();
  });

  test("skipPaths bypasses plugin entirely", async () => {
    const app = await makeApp({ skipPaths: ["/internal"] });
    const r = await app.inject({ method: "GET", url: "/internal/dash" });
    expect(r.body).toBe("<html><body>internal</body></html>");
    expect(r.headers["x-audit-notice"]).toBeUndefined();
    await app.close();
  });
});
