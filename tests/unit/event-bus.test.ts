import { describe, expect, it } from "vitest";

import { EventBus, type SecurityEvent } from "../../src/index.js";

function event(id: string, type: SecurityEvent["type"] = "request.analyzed"): SecurityEvent {
  return {
    id,
    type,
    timestamp: "2026-06-07T00:00:00.000Z",
    severity: "info",
    data: {}
  };
}

describe("EventBus", () => {
  it("subscribes, emits, and unsubscribes handlers", () => {
    const bus = new EventBus();
    const seen: string[] = [];
    const off = bus.on("request.analyzed", (securityEvent) => {
      seen.push(securityEvent.id);
    });

    expect(bus.emit(event("one"))).toBe(true);
    off();
    expect(bus.emit(event("two"))).toBe(false);

    expect(seen).toEqual(["one"]);
  });

  it("supports one-time handlers", () => {
    const bus = new EventBus();
    let count = 0;

    bus.once("request.analyzed", () => {
      count += 1;
    });

    bus.emit(event("one"));
    bus.emit(event("two"));

    expect(count).toBe(1);
  });

  it("emits diagnostic events when safe handlers fail", async () => {
    const bus = new EventBus();
    const diagnostics: SecurityEvent[] = [];

    bus.on("request.analyzed", () => {
      throw new Error("listener failed");
    });
    bus.on("plugin.error", (securityEvent) => {
      diagnostics.push(securityEvent);
    });

    await bus.emitSafe(event("source"));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.data.message).toBe("listener failed");
  });
});
