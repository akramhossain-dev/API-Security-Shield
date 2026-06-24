import type { EventBus } from "../../../../src/events/event-bus.js";
import type { AbstractStorage } from "../../../../src/interfaces/contracts.js";
import { MemoryStorageAdapter } from "../../../../src/storage/index.js";
import type { RequestContext } from "../../../../src/types/index.js";

export interface BruteForceProtectionOptions {
  readonly storage?: AbstractStorage;
  readonly eventBus?: EventBus;
  readonly loginRoutes?: readonly string[];
  readonly maxAttempts?: number;
  readonly windowSeconds?: number;
  readonly lockSeconds?: number;
  readonly accountResolver?: (context: RequestContext) => string | null;
}

export interface BruteForceResult {
  readonly allowed: boolean;
  readonly routeMatched: boolean;
  readonly identity: string;
  readonly attempts: number;
  readonly locked: boolean;
  readonly retryAfterSeconds: number;
  readonly reason: string;
}

/**
 * Tracks repeated login attempts by account and IP and applies temporary locks.
 */
export class BruteForceProtection {
  private readonly storage: AbstractStorage;
  private readonly eventBus?: EventBus;
  private readonly loginRoutes: readonly string[];
  private readonly maxAttempts: number;
  private readonly windowSeconds: number;
  private readonly lockSeconds: number;
  private readonly accountResolver: (context: RequestContext) => string | null;

  /**
   * Creates brute force protection.
   */
  public constructor(options: BruteForceProtectionOptions = {}) {
    this.storage = options.storage ?? new MemoryStorageAdapter();
    this.eventBus = options.eventBus;
    this.loginRoutes = options.loginRoutes ?? ["/login", "/auth/login", "/api/login", "/api/auth/login"];
    this.maxAttempts = options.maxAttempts ?? 5;
    this.windowSeconds = options.windowSeconds ?? 15 * 60;
    this.lockSeconds = options.lockSeconds ?? 15 * 60;
    this.accountResolver = options.accountResolver ?? defaultAccountResolver;
  }

  /**
   * Checks whether the request is currently locked by brute force policy.
   */
  public async check(context: RequestContext): Promise<BruteForceResult> {
    if (!this.isLoginRoute(context)) {
      return this.result(true, false, this.identity(context), 0, false, 0, "route not protected");
    }

    const identity = this.identity(context);
    const lockKey = this.lockKey(identity);
    const locked = await this.storage.get<{ readonly reason: string }>(lockKey);

    if (locked !== null) {
      return this.result(false, true, identity, this.maxAttempts, true, this.lockSeconds, locked.reason);
    }

    return this.result(true, true, identity, 0, false, 0, "login attempt allowed");
  }

  /**
   * Records a login attempt and locks identity after too many attempts.
   */
  public async recordAttempt(context: RequestContext): Promise<BruteForceResult> {
    if (!this.isLoginRoute(context)) {
      return this.result(true, false, this.identity(context), 0, false, 0, "route not protected");
    }

    const identity = this.identity(context);
    const attempts = await this.storage.increment(this.attemptKey(identity), this.windowSeconds);

    if (attempts > this.maxAttempts) {
      await this.storage.set(this.lockKey(identity), { reason: "too many login attempts" }, this.lockSeconds);
      const result = this.result(false, true, identity, attempts, true, this.lockSeconds, "too many login attempts");
      this.emitDetected(context, result);
      return result;
    }

    return this.result(true, true, identity, attempts, false, 0, "login attempt recorded");
  }

  /**
   * Records a failed authentication attempt for host application integrations.
   */
  public async recordFailure(context: RequestContext): Promise<BruteForceResult> {
    return this.recordAttempt(context);
  }

  /**
   * Clears brute force counters after successful authentication.
   */
  public async recordSuccess(context: RequestContext): Promise<void> {
    const identity = this.identity(context);
    await this.storage.delete(this.attemptKey(identity));
    await this.storage.delete(this.lockKey(identity));
  }

  private isLoginRoute(context: RequestContext): boolean {
    if (context.method.toUpperCase() !== "POST") {
      return false;
    }

    const route = context.route ?? context.path;
    return this.loginRoutes.includes(route) || this.loginRoutes.includes(context.path);
  }

  private identity(context: RequestContext): string {
    const account = this.accountResolver(context) ?? "unknown-account";
    return `${this.safe(account)}:${this.safe(context.ip)}`;
  }

  private safe(value: string): string {
    return value.replace(/[^a-zA-Z0-9_.:@-]/g, "_").slice(0, 160);
  }

  private attemptKey(identity: string): string {
    return `brute-force:attempts:${identity}`;
  }

  private lockKey(identity: string): string {
    return `brute-force:lock:${identity}`;
  }

  private result(
    allowed: boolean,
    routeMatched: boolean,
    identity: string,
    attempts: number,
    locked: boolean,
    retryAfterSeconds: number,
    reason: string
  ): BruteForceResult {
    return {
      allowed,
      routeMatched,
      identity,
      attempts,
      locked,
      retryAfterSeconds,
      reason
    };
  }

  private emitDetected(context: RequestContext, result: BruteForceResult): void {
    void this.eventBus?.emitSafe({
      id: `${context.requestId}:brute-force`,
      type: "brute_force.detected",
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      severity: "critical",
      data: {
        identity: result.identity,
        attempts: result.attempts,
        retryAfterSeconds: result.retryAfterSeconds,
        reason: result.reason
      }
    });

    void this.eventBus?.emitSafe({
      id: `${context.requestId}:brute-force-alert`,
      type: "security.alert",
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      severity: "critical",
      data: {
        category: "brute_force",
        identity: result.identity,
        reason: result.reason
      }
    });
  }
}

function defaultAccountResolver(context: RequestContext): string | null {
  if (typeof context.body !== "object" || context.body === null) {
    return null;
  }

  const body = context.body as Record<string, unknown>;
  const value = body.email ?? body.username ?? body.account ?? body.user;
  return typeof value === "string" && value.trim().length > 0 ? value.trim().toLowerCase() : null;
}
