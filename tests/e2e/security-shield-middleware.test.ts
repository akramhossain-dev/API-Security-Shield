import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EventBus, securityShield, type SecurityEvent } from "../../src/index.js";

function createApp(eventBus: EventBus): express.Express {
  const app = express();
  app.use(express.json());
  app.use(
    securityShield({
      eventBus,
      botDetection: false,
      loggerOptions: {
        minSeverity: "critical"
      }
    })
  );
  app.get("/ok", (_request, response) => {
    response.json({ ok: true });
  });
  app.post("/comments", (_request, response) => {
    response.json({ ok: true });
  });
  return app;
}

describe("securityShield middleware", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("allows benign requests and emits request analysis events", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const eventBus = new EventBus();
    const events: SecurityEvent[] = [];
    eventBus.on("request.analyzed", (event) => {
      events.push(event);
    });

    const response = await request(createApp(eventBus)).get("/ok").expect(200);

    expect(response.body).toEqual({ ok: true });
    expect(events).toHaveLength(1);
    expect(events[0]?.data.action).toBe("allow");
  });

  it("blocks SQL injection requests", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const eventBus = new EventBus();

    const response = await request(createApp(eventBus))
      .get("/ok")
      .query({ q: "' OR 1=1 --" })
      .expect(403);

    expect(response.body.error).toBe("request_blocked");
    expect(response.body.level).toBe("high");
  });

  it("blocks XSS requests", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const eventBus = new EventBus();

    const response = await request(createApp(eventBus))
      .post("/comments")
      .send({ comment: "<script>alert(1)</script>" })
      .expect(403);

    expect(response.body.error).toBe("request_blocked");
    expect(response.body.level).toBe("high");
  });

  it("blocks bot requests with 403 when bot detection is enabled", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const eventBus = new EventBus();
    const app = express();
    app.use(
      securityShield({
        eventBus,
        botDetection: true,
        loggerOptions: { minSeverity: "critical" }
      })
    );
    app.get("/ok", (_request, response) => response.json({ ok: true }));

    const response = await request(app)
      .get("/ok")
      .set("User-Agent", "Googlebot")
      .expect(403);

    expect(response.body.error).toBe("bot_detected");
    expect(response.body.message).toContain("Automated request blocked");
  });

  it("allows bot requests when bot detection is disabled", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const eventBus = new EventBus();
    const app = express();
    app.use(
      securityShield({
        eventBus,
        botDetection: false,
        loggerOptions: { minSeverity: "critical" }
      })
    );
    app.get("/ok", (_request, response) => response.json({ ok: true }));

    const response = await request(app)
      .get("/ok")
      .set("User-Agent", "Googlebot")
      .expect(200);

    expect(response.body).toEqual({ ok: true });
  });

  it("loads and runs custom plugins in the middleware context", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const eventBus = new EventBus();
    const app = express();
    const analyzeHook = vi.fn().mockResolvedValue(undefined);

    class DummyPlugin {
      metadata = { name: "dummy-plugin", version: "1.0.0" };
      async onAnalyze(request: any, context: any) {
        await analyzeHook(request.path, context.requestId);
      }
    }

    app.use(
      securityShield({
        eventBus,
        botDetection: false,
        plugins: [new DummyPlugin() as any],
        loggerOptions: { minSeverity: "critical" }
      })
    );
    app.get("/ok", (_request, response) => response.json({ ok: true }));

    // Wait a brief moment to ensure async plugin loading is done
    await new Promise((resolve) => setTimeout(resolve, 50));

    await request(app).get("/ok").expect(200);

    expect(analyzeHook).toHaveBeenCalled();
    expect(analyzeHook.mock.calls[0]?.[0]).toBe("/ok");
  });

  it("resolves client IP using X-Forwarded-For when trustProxy is enabled", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const eventBus = new EventBus();
    const app = express();
    app.use(
      securityShield({
        eventBus,
        trustProxy: true,
        botDetection: false,
        loggerOptions: { minSeverity: "critical" }
      })
    );
    app.get("/ip", (request, response) => response.json({ ok: true }));

    const events: any[] = [];
    eventBus.on("request.received", (event) => {
      events.push(event);
    });

    await request(app)
      .get("/ip")
      .set("X-Forwarded-For", "1.2.3.4")
      .expect(200);

    expect(events).toHaveLength(1);
    expect(events[0]?.data.ip).toBe("1.2.3.4");
  });

  it("ignores X-Forwarded-For when trustProxy is disabled", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const eventBus = new EventBus();
    const app = express();
    app.use(
      securityShield({
        eventBus,
        trustProxy: false,
        botDetection: false,
        loggerOptions: { minSeverity: "critical" }
      })
    );
    app.get("/ip", (request, response) => response.json({ ok: true }));

    const events: any[] = [];
    eventBus.on("request.received", (event) => {
      events.push(event);
    });

    await request(app)
      .get("/ip")
      .set("X-Forwarded-For", "1.2.3.4")
      .expect(200);

    expect(events).toHaveLength(1);
    expect(events[0]?.data.ip).not.toBe("1.2.3.4");
  });

  it("does not lock after successful login attempts", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const eventBus = new EventBus();
    const app = express();
    app.use(express.json());
    app.use(
      securityShield({
        eventBus,
        botDetection: false,
        loggerOptions: { minSeverity: "critical" },
        bruteForceOptions: {
          loginRoutes: ["/login"],
          maxAttempts: 1,
          lockSeconds: 45
        }
      })
    );
    app.post("/login", (_request, response) => response.status(200).json({ ok: true }));

    await request(app).post("/login").send({ email: "user@example.com" }).expect(200);
    await request(app).post("/login").send({ email: "user@example.com" }).expect(200);
  });
});

