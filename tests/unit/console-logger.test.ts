import { afterEach, describe, expect, it, vi } from "vitest";

import { ConsoleLoggerAdapter, type SecurityEvent } from "../../src/index.js";

const securityEvent: SecurityEvent = {
  id: "event-1",
  type: "threat.detected",
  timestamp: "2026-06-07T00:00:00.000Z",
  severity: "warn",
  data: {
    message: "detected"
  }
};

describe("ConsoleLoggerAdapter", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("routes warning events to console.warn", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const logger = new ConsoleLoggerAdapter({ format: "pretty" });

    logger.handle(securityEvent);

    expect(warn).toHaveBeenCalledWith(
      "[2026-06-07T00:00:00.000Z] WARN threat.detected event-1"
    );
  });

  it("filters events below the minimum severity", () => {
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    const logger = new ConsoleLoggerAdapter({ minSeverity: "error" });

    logger.handle({ ...securityEvent, severity: "info" });

    expect(info).not.toHaveBeenCalled();
  });
});
