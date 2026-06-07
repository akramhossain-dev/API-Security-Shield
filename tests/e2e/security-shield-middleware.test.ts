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
});
