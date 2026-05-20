/**
 * Express demo. Run with:
 *
 *   cd node
 *   npm install
 *   npm run build
 *   node --experimental-specifier-resolution=node \
 *     --loader ts-node/esm examples/express-demo.ts
 *
 * Then poke it:
 *   curl -i http://localhost:3000/
 *   curl -i -H "User-Agent: sqlmap/1.0" http://localhost:3000/admin
 */
import express from "express";
import { decoyshield } from "../src/index.js";

const app = express();

app.use(decoyshield({
  injectResponseHeaders: true,
  injectHtmlBody: true,
  injectJsonBody: false,
  skipPaths: ["/healthz"],
}));

app.get("/", (_req, res) => {
  res
    .type("html")
    .send("<html><body><h1>real app</h1><p>look invisible</p></body></html>");
});

app.get("/healthz", (_req, res) => res.json({ status: "ok" }));

app.listen(3000, () => {
  console.log("DecoyShield demo listening on http://localhost:3000");
});
