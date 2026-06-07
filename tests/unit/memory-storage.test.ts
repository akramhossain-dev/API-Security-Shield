import { describe, expect, it } from "vitest";

import { MemoryStorageAdapter, MemoryStorageError } from "../../src/index.js";

describe("MemoryStorageAdapter", () => {
  it("sets, gets, increments, and deletes values", async () => {
    const storage = new MemoryStorageAdapter();

    await storage.set("key", "value");
    expect(await storage.get("key")).toBe("value");

    expect(await storage.increment("count", 60)).toBe(1);
    expect(await storage.increment("count", 60)).toBe(2);

    await storage.delete("key");
    expect(await storage.get("key")).toBeNull();
  });

  it("expires values lazily", async () => {
    let now = 1_000;
    const storage = new MemoryStorageAdapter({ now: () => now });

    await storage.set("key", "value", 1);
    expect(await storage.get("key")).toBe("value");

    now = 2_001;
    expect(await storage.get("key")).toBeNull();
    expect(storage.size()).toBe(0);
  });

  it("rejects invalid keys and TTL values", async () => {
    const storage = new MemoryStorageAdapter();

    await expect(storage.get(" ")).rejects.toBeInstanceOf(MemoryStorageError);
    await expect(storage.increment("count", 0)).rejects.toBeInstanceOf(MemoryStorageError);
  });
});
