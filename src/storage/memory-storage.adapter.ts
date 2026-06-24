import { AbstractStorage } from "../interfaces/contracts.js";
import type { StorageHealth } from "../types/index.js";

export interface MemoryStorageOptions {
  readonly now?: () => number;
  readonly maxKeys?: number;
  readonly pruneIntervalMs?: number;
  readonly pruneBatchSize?: number;
}

interface MemoryStorageEntry<T> {
  readonly value: T;
  readonly expiresAt?: number;
}

/**
 * Error thrown when memory storage receives invalid input.
 */
export class MemoryStorageError extends Error {
  /**
   * Creates a memory storage error.
   */
  public constructor(message: string) {
    super(message);
    this.name = "MemoryStorageError";
  }
}

/**
 * In-memory storage adapter for development, tests, and single-process deployments.
 */
export class MemoryStorageAdapter extends AbstractStorage {
  private readonly entries = new Map<string, MemoryStorageEntry<unknown>>();
  private readonly now: () => number;
  private readonly maxKeys: number;
  private readonly pruneIntervalMs: number;
  private readonly pruneBatchSize: number;
  private pruneInterval?: any;

  /**
   * Creates a memory storage adapter.
   */
  public constructor(options: MemoryStorageOptions = {}) {
    super("memory");
    this.now = options.now ?? Date.now;
    this.maxKeys = options.maxKeys ?? 10000;
    this.pruneIntervalMs = options.pruneIntervalMs ?? 30000;
    this.pruneBatchSize = options.pruneBatchSize ?? 100;
    this.startPruningInterval();
  }

  private startPruningInterval(): void {
    if (typeof setInterval === "function" && this.pruneIntervalMs > 0) {
      this.pruneInterval = setInterval(() => {
        let count = 0;
        for (const [key, entry] of this.entries.entries()) {
          if (this.isExpired(entry)) {
            this.entries.delete(key);
          }
          count++;
          if (count >= this.pruneBatchSize) {
            break;
          }
        }
      }, this.pruneIntervalMs);

      if (this.pruneInterval && typeof this.pruneInterval.unref === "function") {
        this.pruneInterval.unref();
      }
    }
  }

  /**
   * Cleans up the pruning interval timer.
   */
  public destroy(): void {
    if (this.pruneInterval) {
      clearInterval(this.pruneInterval);
    }
  }

  public async get<T>(key: string): Promise<T | null> {
    this.validateKey(key);
    const entry = this.entries.get(key);

    if (!entry) {
      return null;
    }

    if (this.isExpired(entry)) {
      this.entries.delete(key);
      return null;
    }

    this.entries.delete(key);
    this.entries.set(key, entry);

    return entry.value as T;
  }

  /**
   * Writes a value to storage with an optional TTL.
   */
  public async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    this.validateKey(key);
    const expiresAt = this.resolveExpiresAt(ttlSeconds);

    if (this.entries.has(key)) {
      this.entries.delete(key);
    } else if (this.entries.size >= this.maxKeys) {
      const oldestKey = this.entries.keys().next().value;
      if (oldestKey !== undefined) {
        this.entries.delete(oldestKey);
      }
    }

    this.entries.set(key, { value, expiresAt });
  }

  /**
   * Increments a numeric value, initializing missing values at zero.
   */
  public async increment(key: string, ttlSeconds: number): Promise<number> {
    this.validateKey(key);
    this.validateTtl(ttlSeconds);

    const current = await this.get<number>(key);
    if (current !== null && typeof current !== "number") {
      throw new MemoryStorageError(`Cannot increment non-numeric key: ${key}`);
    }

    const next = (current ?? 0) + 1;
    await this.set(key, next, ttlSeconds);
    return next;
  }

  /**
   * Deletes a value from storage.
   */
  public async delete(key: string): Promise<void> {
    this.validateKey(key);
    this.entries.delete(key);
  }

  /**
   * Reports memory storage health.
   */
  public async health(): Promise<StorageHealth> {
    const started = this.now();
    this.pruneExpired();

    return {
      ok: true,
      latencyMs: Math.max(0, this.now() - started),
      message: "memory storage healthy"
    };
  }

  /**
   * Removes all values from storage.
   */
  public clear(): void {
    this.entries.clear();
  }

  /**
   * Returns the number of non-expired values.
   */
  public size(): number {
    this.pruneExpired();
    return this.entries.size;
  }

  private validateKey(key: string): void {
    if (key.trim().length === 0) {
      throw new MemoryStorageError("Storage key must not be empty");
    }
  }

  private validateTtl(ttlSeconds: number): void {
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
      throw new MemoryStorageError("TTL must be a positive finite number");
    }
  }

  private resolveExpiresAt(ttlSeconds?: number): number | undefined {
    if (ttlSeconds === undefined) {
      return undefined;
    }

    this.validateTtl(ttlSeconds);
    return this.now() + ttlSeconds * 1000;
  }

  private isExpired(entry: MemoryStorageEntry<unknown>): boolean {
    return entry.expiresAt !== undefined && entry.expiresAt <= this.now();
  }

  private pruneExpired(): void {
    for (const [key, entry] of this.entries.entries()) {
      if (this.isExpired(entry)) {
        this.entries.delete(key);
      }
    }
  }
}
