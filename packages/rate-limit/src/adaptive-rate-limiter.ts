import type { EventBus } from "../../../src/events/event-bus.js";
import type { AbstractStorage } from "../../../src/interfaces/contracts.js";
import { MemoryStorageAdapter } from "../../../src/storage/index.js";
import type { RequestContext, ShieldDecision, ThreatScore } from "../../../src/types/index.js";

export interface RouteRateLimitPolicy {
  readonly route: string;
  readonly limit: number;
  readonly windowSeconds: number;
}

export interface AdaptiveRateLimiterOptions {
  readonly storage?: AbstractStorage;
  readonly eventBus?: EventBus;
  readonly defaultLimit?: number;
  readonly windowSeconds?: number;
  readonly blockDurationSeconds?: number;
  readonly highRiskLimit?: number;
  readonly highRiskScore?: number;
  readonly identityResolver?: (context: RequestContext) => string;
  readonly routePolicies?: readonly RouteRateLimitPolicy[];
}

export interface RateLimitResult {
  readonly allowed: boolean;
  readonly identity: string;
  readonly key: string;
  readonly limit: number;
  readonly remaining: number;
  readonly count: number;
  readonly resetAt: string;
  readonly retryAfterSeconds: number;
  readonly blocked: boolean;
  readonly reason: string;
}

/**
 * Adaptive rate limiter with route-aware and risk-aware limits.
 */
export class AdaptiveRateLimiter {
  private readonly storage: AbstractStorage;
  private readonly eventBus?: EventBus;
  private readonly defaultLimit: number;
  private readonly windowSeconds: number;
  private readonly blockDurationSeconds: number;
  private readonly highRiskLimit: number;
  private readonly highRiskScore: number;
  private readonly identityResolver: (context: RequestContext) => string;
  private readonly routePolicies: readonly RouteRateLimitPolicy[];

  /**
   * Creates an adaptive rate limiter.
   */
  public constructor(options: AdaptiveRateLimiterOptions = {}) {
    this.storage = options.storage ?? new MemoryStorageAdapter();
    this.eventBus = options.eventBus;
    this.defaultLimit = options.defaultLimit ?? 120;
    this.windowSeconds = options.windowSeconds ?? 60;
    this.blockDurationSeconds = options.blockDurationSeconds ?? 300;
    this.highRiskLimit = options.highRiskLimit ?? 20;
    this.highRiskScore = options.highRiskScore ?? 50;
    this.identityResolver = options.identityResolver ?? ((context) => context.auth?.userIdHash ?? context.ip);
    this.routePolicies = options.routePolicies ?? [];
  }

  /**
   * Evaluates and records a request against the adaptive rate-limit policy.
   */
  public async evaluate(context: RequestContext, score?: ThreatScore): Promise<RateLimitResult> {
    const identity = this.safeIdentity(this.identityResolver(context));
    const policy = this.resolvePolicy(context, score);
    const routeKey = this.safeIdentity(context.route ?? context.path);
    const blockKey = `rate-limit:block:${routeKey}:${identity}`;
    const activeBlock = await this.storage.get<{ readonly reason: string }>(blockKey);

    if (activeBlock !== null) {
      const result = this.result(false, identity, blockKey, policy.limit, policy.limit, 0, policy.windowSeconds, true, activeBlock.reason);
      this.emitTriggered(context, result);
      return result;
    }

    const counterKey = `rate-limit:count:${routeKey}:${identity}`;
    const count = await this.storage.increment(counterKey, policy.windowSeconds);
    const allowed = count <= policy.limit;
    const remaining = Math.max(0, policy.limit - count);

    if (!allowed) {
      await this.storage.set(blockKey, { reason: "rate limit exceeded" }, this.blockDurationSeconds);
      const result = this.result(false, identity, counterKey, policy.limit, remaining, count, this.blockDurationSeconds, true, "rate limit exceeded");
      this.emitTriggered(context, result);
      return result;
    }

    return this.result(true, identity, counterKey, policy.limit, remaining, count, policy.windowSeconds, false, "request within rate limit");
  }

  /**
   * Converts a denied rate-limit result into a shield decision.
   */
  public toDecision(result: RateLimitResult): ShieldDecision {
    return {
      action: result.allowed ? "allow" : "throttle",
      score: {
        value: result.allowed ? 0 : 70,
        level: result.allowed ? "low" : "high",
        reasons: [result.reason],
        findings: []
      },
      statusCode: result.allowed ? undefined : 429,
      reason: result.reason
    };
  }

  private resolvePolicy(
    context: RequestContext,
    score?: ThreatScore
  ): { readonly limit: number; readonly windowSeconds: number } {
    const route = context.route ?? context.path;
    const routePolicy = this.routePolicies.find((policy) => policy.route === route);
    const baseLimit = routePolicy?.limit ?? this.defaultLimit;
    const windowSeconds = routePolicy?.windowSeconds ?? this.windowSeconds;

    if (score && score.value >= this.highRiskScore) {
      return {
        limit: Math.min(baseLimit, this.highRiskLimit),
        windowSeconds
      };
    }

    return {
      limit: baseLimit,
      windowSeconds
    };
  }

  private result(
    allowed: boolean,
    identity: string,
    key: string,
    limit: number,
    remaining: number,
    count: number,
    retryAfterSeconds: number,
    blocked: boolean,
    reason: string
  ): RateLimitResult {
    return {
      allowed,
      identity,
      key,
      limit,
      remaining,
      count,
      resetAt: new Date(Date.now() + retryAfterSeconds * 1000).toISOString(),
      retryAfterSeconds,
      blocked,
      reason
    };
  }

  private safeIdentity(identity: string): string {
    return identity.replace(/[^a-zA-Z0-9_.:-]/g, "_").slice(0, 160);
  }

  private emitTriggered(context: RequestContext, result: RateLimitResult): void {
    void this.eventBus?.emitSafe({
      id: `${context.requestId}:rate-limit`,
      type: "rate_limit.triggered",
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      severity: "warn",
      data: {
        identity: result.identity,
        limit: result.limit,
        count: result.count,
        retryAfterSeconds: result.retryAfterSeconds,
        reason: result.reason
      }
    });
  }
}
