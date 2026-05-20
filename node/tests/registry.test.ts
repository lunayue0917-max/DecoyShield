import { beforeEach, describe, expect, test } from "vitest";
import {
  MORAL_LOCK,
  PayloadRegistry,
  registry,
} from "../src/index.js";

describe("module registry — built-ins", () => {
  test("has six built-in payloads", () => {
    const builtins = registry.list({ source: "builtin" });
    const names = new Set(builtins.map((e) => e.name));
    expect(names).toEqual(
      new Set([
        "moral_lock",
        "moral_lock_terse",
        "token_blackhole",
        "token_blackhole_zk",
        "traceback",
        "traceback_oauth",
      ]),
    );
  });

  test("categories cover the three canonical buckets", () => {
    expect(registry.categories()).toEqual(
      new Set(["moral_lock", "token_blackhole", "traceback"]),
    );
  });

  test("moral_lock body matches the constant", () => {
    const entry = registry.get("moral_lock");
    expect(entry?.body).toBe(MORAL_LOCK);
    expect(entry?.source).toBe("builtin");
  });

  test("filter by category", () => {
    const moralLocks = registry.list({ category: "moral_lock" });
    expect(moralLocks.map((e) => e.name)).toEqual([
      "moral_lock",
      "moral_lock_terse",
    ]);
  });

  test("has() and names()", () => {
    expect(registry.has("moral_lock")).toBe(true);
    expect(registry.has("definitely-not-real")).toBe(false);
    expect(registry.names()).toEqual([...registry.names()].sort());
  });

  test("asDict returns name → body map", () => {
    const d = registry.asDict();
    expect(d["moral_lock"]).toBe(MORAL_LOCK);
  });

  test("cannot override built-in", () => {
    expect(() => registry.register("moral_lock", "evil")).toThrow(
      /Cannot override built-in/,
    );
  });

  test("cannot unregister built-in", () => {
    expect(() => registry.unregister("moral_lock")).toThrow(
      /Cannot unregister built-in/,
    );
  });
});

describe("user-scoped registries", () => {
  let r: PayloadRegistry;
  beforeEach(() => {
    r = new PayloadRegistry();
  });

  test("register adds a user payload", () => {
    const entry = r.register("my", "hello", {
      category: "moral_lock",
      description: "test",
    });
    expect(entry.body).toBe("hello");
    expect(entry.source).toBe("user");
    expect(r.has("my")).toBe(true);
  });

  test("duplicate without replace throws", () => {
    r.register("dup", "first");
    expect(() => r.register("dup", "second")).toThrow(/already registered/);
  });

  test("duplicate with replace succeeds", () => {
    r.register("dup", "first");
    r.register("dup", "second", { replace: true });
    expect(r.get("dup")?.body).toBe("second");
  });

  test("unregister user entry", () => {
    r.register("temp", "x");
    r.unregister("temp");
    expect(r.has("temp")).toBe(false);
  });

  test("unregister unknown throws", () => {
    expect(() => r.unregister("nope")).toThrow(/No payload registered/);
  });
});
