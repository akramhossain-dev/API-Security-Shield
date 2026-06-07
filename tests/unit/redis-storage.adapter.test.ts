import { describe, expect, it } from "vitest";

import { RedisStorageAdapter, RedisStorageError, type RedisLike } from "../../src/index.js";

class MockRedis implements RedisLike {
  public readonly values = new Map<string, string>();
  public readonly expirations = new Map<string, number>();

  public async get(key: string): Promise<string | null> {
    return this.values.get(key) ?? null;
  }

  public async set(key: string, value: string, mode?: "EX", ttlSeconds?: number): Promise<string> {
    this.values.set(key, value);
    if (mode === "EX" && ttlSeconds !== undefined) {
      this.expirations.set(key, ttlSeconds);
    }
    return "OK";
  }

  public async incr(key: string): Promise<number> {
    const current = Number(this.values.get(key) ?? "0");
    const next = current + 1;
    this.values.set(key, String(next));
    return next;
  }

  public async expire(key: string, ttlSeconds: number): Promise<number> {
    this.expirations.set(key, ttlSeconds);
    return 1;
  }

  public async del(key: string): Promise<number> {
    this.values.delete(key);
    return 1;
  }

  public async ping(): Promise<string> {
    return "PONG";
  }
}

describe("RedisStorageAdapter", () => {
  it("stores JSON values with prefixes and TTLs", async () => {
    const client = new MockRedis();
    const storage = new RedisStorageAdapter({ client, keyPrefix: "test" });

    await storage.set("key", { ok: true }, 30);

    expect(await storage.get("key")).toEqual({ ok: true });
    expect(client.expirations.get("test:key")).toBe(30);
  });

  it("increments counters and applies TTL", async () => {
    const client = new MockRedis();
    const storage = new RedisStorageAdapter({ client, keyPrefix: "test" });

    expect(await storage.increment("count", 60)).toBe(1);
    expect(await storage.increment("count", 60)).toBe(2);
    expect(client.expirations.get("test:count")).toBe(60);
  });

  it("reports health and rejects invalid keys", async () => {
    const storage = new RedisStorageAdapter({ client: new MockRedis() });

    await expect(storage.health()).resolves.toMatchObject({ ok: true });
    await expect(storage.get(" ")).rejects.toBeInstanceOf(RedisStorageError);
  });
});
