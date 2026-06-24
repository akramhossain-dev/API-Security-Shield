import { describe, expect, it } from "vitest";

import { AdaptiveRateLimiter, EventBus, MemoryStorageAdapter, type SecurityEvent } from "../../src/index.js";
import { createRequestContext } from "../fixtures/request-context.js";

describe("AdaptiveRateLimiter", () => {
  it("allows requests within the default limit", async () => {
    const limiter = new AdaptiveRateLimiter({
      storage: new MemoryStorageAdapter(),
      defaultLimit: 2,
      windowSeconds: 60
    });

    const first = await limiter.evaluate(createRequestContext());
    const second = await limiter.evaluate(createRequestContext());

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(true);
    expect(second.remaining).toBe(0);
  });

  it("temporarily blocks identities after exceeding limits", async () => {
    const events: SecurityEvent[] = [];
    const eventBus = new EventBus();
    eventBus.on("rate_limit.triggered", (event) => {
      events.push(event);
    });
    const limiter = new AdaptiveRateLimiter({
      storage: new MemoryStorageAdapter(),
      eventBus,
      defaultLimit: 1,
      windowSeconds: 60,
      blockDurationSeconds: 30
    });

    await limiter.evaluate(createRequestContext());
    const denied = await limiter.evaluate(createRequestContext());
    const stillDenied = await limiter.evaluate(createRequestContext());

    expect(denied.allowed).toBe(false);
    expect(stillDenied.blocked).toBe(true);
    expect(events).toHaveLength(2);
  });

  it("uses stricter limits for high-risk scores", async () => {
    const limiter = new AdaptiveRateLimiter({
      storage: new MemoryStorageAdapter(),
      defaultLimit: 10,
      highRiskLimit: 1,
      highRiskScore: 50
    });
    const score = {
      value: 60,
      level: "warning" as const,
      reasons: ["risk"],
      findings: []
    };

    await limiter.evaluate(createRequestContext(), score);
    const denied = await limiter.evaluate(createRequestContext(), score);

    expect(denied.allowed).toBe(false);
    expect(denied.limit).toBe(1);
  });

  it("normalizes dynamic route parameters to avoid key fragmentation", async () => {
    const storage = new MemoryStorageAdapter();
    const limiter = new AdaptiveRateLimiter({
      storage,
      defaultLimit: 1,
      windowSeconds: 60
    });

    const context1 = createRequestContext({ path: "/api/users/123" });
    const context2 = createRequestContext({ path: "/api/users/456" });

    const first = await limiter.evaluate(context1);
    const second = await limiter.evaluate(context2);

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(false);
  });
});
