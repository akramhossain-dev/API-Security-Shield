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
   * Atomically increments a Redis counter and applies a TTL.
   */
  public async increment(key: string, ttlSeconds: number): Promise<number> {
    this.validateKey(key);
    this.validateTtl(ttlSeconds);
    const fullKey = this.key(key);
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
    ping: () => client.ping()
  };
}
