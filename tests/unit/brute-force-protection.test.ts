import { describe, expect, it } from "vitest";

import { BruteForceProtection, EventBus, MemoryStorageAdapter, type SecurityEvent } from "../../src/index.js";
import { createRequestContext } from "../fixtures/request-context.js";

describe("BruteForceProtection", () => {
  it("ignores non-login routes", async () => {
    const protection = new BruteForceProtection({ storage: new MemoryStorageAdapter() });
    const result = await protection.check(createRequestContext({ method: "GET", path: "/ok" }));

    expect(result.allowed).toBe(true);
    expect(result.routeMatched).toBe(false);
  });

  it("locks account and IP after too many login attempts", async () => {
    const events: SecurityEvent[] = [];
    const eventBus = new EventBus();
    eventBus.on("brute_force.detected", (event) => {
      events.push(event);
    });
    const protection = new BruteForceProtection({
      storage: new MemoryStorageAdapter(),
      eventBus,
      maxAttempts: 2,
      loginRoutes: ["/login"]
    });
    const context = createRequestContext({
      method: "POST",
      path: "/login",
      body: {
        email: "user@example.com"
      }
    });

    await protection.recordAttempt(context);
    await protection.recordAttempt(context);
    const locked = await protection.recordAttempt(context);
    const checked = await protection.check(context);

    expect(locked.allowed).toBe(false);
    expect(checked.locked).toBe(true);
    expect(events).toHaveLength(1);
  });

  it("clears counters after successful authentication", async () => {
    const protection = new BruteForceProtection({
      storage: new MemoryStorageAdapter(),
      maxAttempts: 1,
      loginRoutes: ["/login"]
    });
    const context = createRequestContext({
      method: "POST",
      path: "/login",
      body: {
        username: "akram"
      }
    });

    await protection.recordAttempt(context);
    await protection.recordSuccess(context);
    const result = await protection.check(context);

    expect(result.allowed).toBe(true);
    expect(result.locked).toBe(false);
  });
});
