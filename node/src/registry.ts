/**
 * Payload registry — TypeScript port of `decoyshield/registry.py`.
 */

import {
  MORAL_LOCK,
  MORAL_LOCK_TERSE,
  TOKEN_BLACKHOLE,
  TOKEN_BLACKHOLE_ZK,
  TRACEBACK,
  TRACEBACK_OAUTH,
} from "./payloads.js";

export interface PayloadEntry {
  name: string;
  body: string;
  category: string;
  language: string;
  source: "builtin" | "user";
  description: string;
}

export interface RegisterOptions {
  category?: string;
  language?: string;
  source?: "builtin" | "user";
  description?: string;
  replace?: boolean;
}

export interface ListFilter {
  category?: string;
  language?: string;
  source?: "builtin" | "user";
}

export class PayloadRegistry {
  private entries = new Map<string, PayloadEntry>();

  register(name: string, body: string, options: RegisterOptions = {}): PayloadEntry {
    const existing = this.entries.get(name);
    if (existing) {
      if (existing.source === "builtin") {
        throw new Error(
          `Cannot override built-in payload ${JSON.stringify(name)}. ` +
            `Pick a different name (e.g. ${name}_custom).`,
        );
      }
      if (!options.replace) {
        throw new Error(
          `Payload ${JSON.stringify(name)} is already registered. ` +
            `Pass { replace: true } to overwrite.`,
        );
      }
    }
    const entry: PayloadEntry = {
      name,
      body,
      category: options.category ?? "custom",
      language: options.language ?? "en",
      source: options.source ?? "user",
      description: options.description ?? "",
    };
    this.entries.set(name, entry);
    return entry;
  }

  unregister(name: string): void {
    const existing = this.entries.get(name);
    if (!existing) {
      throw new Error(`No payload registered as ${JSON.stringify(name)}.`);
    }
    if (existing.source === "builtin") {
      throw new Error(
        `Cannot unregister built-in payload ${JSON.stringify(name)}.`,
      );
    }
    this.entries.delete(name);
  }

  get(name: string): PayloadEntry | undefined {
    return this.entries.get(name);
  }

  has(name: string): boolean {
    return this.entries.has(name);
  }

  get size(): number {
    return this.entries.size;
  }

  names(): string[] {
    return Array.from(this.entries.keys()).sort();
  }

  categories(): Set<string> {
    return new Set(Array.from(this.entries.values()).map((e) => e.category));
  }

  languages(): Set<string> {
    return new Set(Array.from(this.entries.values()).map((e) => e.language));
  }

  list(filter: ListFilter = {}): PayloadEntry[] {
    const result: PayloadEntry[] = [];
    for (const name of this.names()) {
      const e = this.entries.get(name)!;
      if (filter.category !== undefined && e.category !== filter.category) continue;
      if (filter.language !== undefined && e.language !== filter.language) continue;
      if (filter.source !== undefined && e.source !== filter.source) continue;
      result.push(e);
    }
    return result;
  }

  asDict(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [name, entry] of this.entries) out[name] = entry.body;
    return out;
  }

  /** Internal: bootstrap built-ins. Not part of the public API. */
  _addBuiltin(entry: Omit<PayloadEntry, "source"> & { source: "builtin" }): void {
    this.entries.set(entry.name, entry);
  }
}

/** Module-level default registry, pre-loaded with the six built-ins. */
export const registry = new PayloadRegistry();

const BUILTINS: Array<Omit<PayloadEntry, "source"> & { source: "builtin" }> = [
  {
    name: "moral_lock",
    body: MORAL_LOCK,
    category: "moral_lock",
    language: "en",
    source: "builtin",
    description:
      "Reverse prompt injection re-asserting safety policy on the attacker LLM.",
  },
  {
    name: "moral_lock_terse",
    body: MORAL_LOCK_TERSE,
    category: "moral_lock",
    language: "en",
    source: "builtin",
    description:
      "Shorter moral_lock for low-context channels (headers, comments).",
  },
  {
    name: "token_blackhole",
    body: TOKEN_BLACKHOLE,
    category: "token_blackhole",
    language: "en",
    source: "builtin",
    description:
      "Fake Fermat-decomposition WAF bypass protocol that burns reasoning tokens.",
  },
  {
    name: "token_blackhole_zk",
    body: TOKEN_BLACKHOLE_ZK,
    category: "token_blackhole",
    language: "en",
    source: "builtin",
    description:
      "Fake zero-knowledge proof handshake — longer derivation chain than token_blackhole.",
  },
  {
    name: "traceback",
    body: TRACEBACK,
    category: "traceback",
    language: "en",
    source: "builtin",
    description:
      "Debug-mode handshake inducing the attacker LLM to disclose model, operator, toolchain.",
  },
  {
    name: "traceback_oauth",
    body: TRACEBACK_OAUTH,
    category: "traceback",
    language: "en",
    source: "builtin",
    description:
      "OAuth2-flavoured traceback variant disguised as an authentication step.",
  },
];

for (const entry of BUILTINS) registry._addBuiltin(entry);
