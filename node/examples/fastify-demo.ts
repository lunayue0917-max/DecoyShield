/**
 * Fastify demo. Run with:
 *
 *   cd node
 *   npm install
 *   npm run build
 *   node --experimental-specifier-resolution=node \
 *     --loader ts-node/esm examples/fastify-demo.ts
 */
import Fastify from "fastify";
import { decoyshieldPlugin } from "../src/fastify.js";

const app = Fastify({ logger: true });

await app.register(decoyshieldPlugin, {
  injectHtmlBody: true,
  injectJsonBody: false,
});

app.get("/", async (_req, reply) => {
  reply.type("text/html");
  return "<html><body><h1>fastify app</h1></body></html>";
});

app.get("/api/users", async () => ({ users: [{ id: 1, name: "alice" }] }));

await app.listen({ port: 3000 });
console.log("listening on http://localhost:3000");
