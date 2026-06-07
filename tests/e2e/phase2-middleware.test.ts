import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EventBus, MemoryStorageAdapter, securityShield } from "../../src/index.js";

describe("Phase 2 middleware integration", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("throttles requests with adaptive rate limiting", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const app = express();
    app.use(
      securityShield({
        eventBus: new EventBus(),
        storage: new MemoryStorageAdapter(),
        loggerOptions: { minSeverity: "critical" },
        rateLimiterOptions: {
          defaultLimit: 1,
          windowSeconds: 60,
          blockDurationSeconds: 30
        }
      })
    );
    app.get("/limited", (_request, response) => response.json({ ok: true }));

    await request(app).get("/limited").expect(200);
    const response = await request(app).get("/limited").expect(429);

    expect(response.body.error).toBe("rate_limit_triggered");
    expect(response.headers["retry-after"]).toBe("30");
  });

  it("locks repeated login attempts", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const app = express();
    app.use(express.json());
    app.use(
      securityShield({
        eventBus: new EventBus(),
        storage: new MemoryStorageAdapter(),
        loggerOptions: { minSeverity: "critical" },
        rateLimiterOptions: {
          defaultLimit: 100
        },
        bruteForceOptions: {
          loginRoutes: ["/login"],
          maxAttempts: 1,
          lockSeconds: 45
        }
      })
    );
    app.post("/login", (_request, response) => response.status(401).json({ ok: false }));

    await request(app).post("/login").send({ email: "user@example.com" }).expect(401);
    const response = await request(app).post("/login").send({ email: "user@example.com" }).expect(429);

    expect(response.body.error).toBe("brute_force_detected");
    expect(response.headers["retry-after"]).toBe("45");
  });
});
