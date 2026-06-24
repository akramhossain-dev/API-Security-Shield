import Redis from "ioredis";

import { AbstractStorage } from "../../../../src/interfaces/contracts.js";
import type { StorageHealth } from "../../../../src/types/index.js";

export interface RedisStorageOptions {
  readonly url?: string;
  readonly keyPrefix?: string;
  readonly client?: RedisLike;
  readonly connectTimeoutMs?: number;
}

export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: "EX", ttlSeconds?: number): Promise<unknown>;
  incr(key: string): Promise<number>;
  expire(key: string, ttlSeconds: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  ping(): Promise<string>;
  pipeline?(): any;
  mget?(keys: string[]): Promise<(string | null)[]>;
}

/**
 * Error thrown when Redis storage receives invalid input or Redis returns invalid data.
 */
export class RedisStorageError extends Error {
  /**
   * Creates a Redis storage error.
   */
  public constructor(message: string) {
    super(message);
    this.name = "RedisStorageError";
  }
}

/**
 * Redis-backed storage adapter for distributed security state.
 */
export class RedisStorageAdapter extends AbstractStorage {
  private readonly client: RedisLike;
  private readonly keyPrefix: string;

  /**
   * Creates a Redis storage adapter.
   */
  public constructor(options: RedisStorageOptions = {}) {
    super("redis");
    this.client =
      options.client ??
      createRedisLike(
        new Redis(options.url ?? "redis://127.0.0.1:6379", {
          connectTimeout: options.connectTimeoutMs ?? 5_000,
          lazyConnect: true,
          maxRetriesPerRequest: 2
        })
      );
    this.keyPrefix = options.keyPrefix ?? "ass";
  }

  /**
   * Reads and JSON-decodes a value from Redis.
   */
  public async get<T>(key: string): Promise<T | null> {
    this.validateKey(key);
    const raw = await this.client.get(this.key(key));

    if (raw === null) {
      return null;
    }

    try {
      return JSON.parse(raw) as T;
    } catch (error) {
      throw new RedisStorageError(
        `Stored value for key "${key}" is not valid JSON: ${
          error instanceof Error ? error.message : "unknown parse error"
        }`
      );
    }
  }

  /**
   * JSON-encodes and writes a value to Redis with optional TTL.
   */
  public async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    this.validateKey(key);
    const encoded = JSON.stringify(value);

    if (ttlSeconds === undefined) {
      await this.client.set(this.key(key), encoded);
      return;
    }

    this.validateTtl(ttlSeconds);
    await this.client.set(this.key(key), encoded, "EX", Math.ceil(ttlSeconds));
  }

  /**
   * Reads and JSON-decodes multiple values from Redis in a single network roundtrip.
   */
  public override async mget<T>(keys: readonly string[]): Promise<readonly (T | null)[]> {
    if (keys.length === 0) {
      return [];
    }

    for (const key of keys) {
      this.validateKey(key);
    }

    const fullKeys = keys.map((k) => this.key(k));
    let rawResults: (string | null)[];

    if (typeof this.client.mget === "function") {
      rawResults = await this.client.mget(fullKeys);
    } else {
      rawResults = await Promise.all(fullKeys.map((k) => this.client.get(k)));
    }

    return rawResults.map((raw, index) => {
      if (raw === null) {
        return null;
      }

      try {
        return JSON.parse(raw) as T;
      } catch (error) {
        throw new RedisStorageError(
          `Stored value for key "${keys[index]}" is not valid JSON: ${
            error instanceof Error ? error.message : "unknown parse error"
          }`
        );
      }
    });
  }

  /**
   * Atomically increments a Redis counter and applies a TTL.
   */
  public async increment(key: string, ttlSeconds: number): Promise<number> {
    this.validateKey(key);
    this.validateTtl(ttlSeconds);
    const fullKey = this.key(key);

    if (typeof this.client.pipeline === "function") {
      const pipeline = this.client.pipeline();
      pipeline.incr(fullKey);
      pipeline.expire(fullKey, Math.ceil(ttlSeconds));
      const results = await pipeline.exec();

      if (!results || !results[0]) {
        throw new RedisStorageError("Pipeline execution returned empty results");
      }

      const incrResult = results[0][1];
      if (typeof incrResult === "number") {
        return incrResult;
      }
      if (typeof incrResult === "string") {
        return Number(incrResult);
      }
      throw new RedisStorageError("Unexpected incr result type from pipeline");
    }

    const value = await this.client.incr(fullKey);
    await this.client.expire(fullKey, Math.ceil(ttlSeconds));
    return value;
  }

  /**
   * Deletes a Redis key.
   */
  public async delete(key: string): Promise<void> {
    this.validateKey(key);
    await this.client.del(this.key(key));
  }

  /**
   * Reports Redis health using PING.
   */
  public async health(): Promise<StorageHealth> {
    const started = Date.now();
    const pong = await this.client.ping();

    return {
      ok: pong.toUpperCase() === "PONG",
      latencyMs: Date.now() - started,
      message: pong
    };
  }

  private key(key: string): string {
    return `${this.keyPrefix}:${key}`;
  }

  private validateKey(key: string): void {
    if (key.trim().length === 0) {
      throw new RedisStorageError("Storage key must not be empty");
    }
  }

  private validateTtl(ttlSeconds: number): void {
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
      throw new RedisStorageError("TTL must be a positive finite number");
    }
  }
}

function createRedisLike(client: Redis): RedisLike {
  return {
    get: (key: string) => client.get(key),
    set: (key: string, value: string, mode?: "EX", ttlSeconds?: number) => {
      if (mode === "EX" && ttlSeconds !== undefined) {
        return client.set(key, value, "EX", ttlSeconds);
      }

      return client.set(key, value);
    },
    incr: (key: string) => client.incr(key),
    expire: (key: string, ttlSeconds: number) => client.expire(key, ttlSeconds),
    del: (key: string) => client.del(key),
    ping: () => client.ping(),
    pipeline: () => client.pipeline(),
    mget: (keys: string[]) => client.mget(keys)
  };
}
