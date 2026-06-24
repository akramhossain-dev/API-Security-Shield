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

  it("evicts oldest keys when max capacity is reached (LRU)", async () => {
    const storage = new MemoryStorageAdapter({ maxKeys: 2 });

    await storage.set("k1", "v1");
    await storage.set("k2", "v2");
    expect(await storage.get("k1")).toBe("v1");

    await storage.set("k3", "v3");

    expect(await storage.get("k1")).toBe("v1");
    expect(await storage.get("k2")).toBeNull();
    expect(await storage.get("k3")).toBe("v3");

    storage.destroy();
  });

  it("prunes expired keys in batches via background interval", async () => {
    let now = 1000;
    const storage = new MemoryStorageAdapter({
      now: () => now,
      pruneIntervalMs: 10,
      pruneBatchSize: 1
    });

    await storage.set("k1", "v1", 1);
    await storage.set("k2", "v2", 1);

    now = 2500;

    await new Promise((resolve) => setTimeout(resolve, 30));

    expect(storage.size()).toBe(0);
    storage.destroy();
  });
});
