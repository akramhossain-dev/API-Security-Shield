import { describe, expect, it } from "vitest";

import {
  AbstractDetector,
  BasicThreatEngine,
  EventBus,
  type DetectorFinding,
  type RequestContext,
  type SecurityEvent
} from "../../src/index.js";
import { createRequestContext } from "../fixtures/request-context.js";

class FixedDetector extends AbstractDetector {
  public constructor(private readonly detectorFindings: readonly DetectorFinding[]) {
    super("fixed", "custom", 1);
  }

  public analyze(_context: RequestContext): readonly DetectorFinding[] {
    return this.detectorFindings;
  }
}

class FailingDetector extends AbstractDetector {
  public constructor() {
    super("failing", "custom", 1);
  }

  public analyze(_context: RequestContext): readonly DetectorFinding[] {
    throw new Error("detector failed");
  }
}

const finding: DetectorFinding = {
  id: "finding",
  category: "custom",
  severity: "high",
  confidence: 0.9,
  score: 75,
  message: "bad request"
};

describe("BasicThreatEngine", () => {
  it("scores findings and resolves block decisions", async () => {
    const engine = new BasicThreatEngine({ detectors: [new FixedDetector([finding])] });
    const result = await engine.analyze(createRequestContext());

    expect(result.score.value).toBe(75);
    expect(result.score.level).toBe("high");
    expect(result.decision.action).toBe("block");
  });

  it("emits events for findings, score, and action", async () => {
    const bus = new EventBus();
    const events: SecurityEvent[] = [];
    bus.on("threat.detected", (event) => {
      events.push(event);
    });
    bus.on("threat.scored", (event) => {
      events.push(event);
    });
    bus.on("action.enforced", (event) => {
      events.push(event);
    });

    const engine = new BasicThreatEngine({
      detectors: [new FixedDetector([finding])],
      eventBus: bus
    });

    await engine.analyze(createRequestContext());

    expect(events.map((event) => event.type)).toEqual([
      "threat.detected",
      "threat.scored",
      "action.enforced"
    ]);
  });

  it("isolates detector errors and continues scoring", async () => {
    const bus = new EventBus();
    const errors: SecurityEvent[] = [];
    bus.on("plugin.error", (event) => {
      errors.push(event);
    });

    const engine = new BasicThreatEngine({
      detectors: [new FailingDetector(), new FixedDetector([finding])],
      eventBus: bus
    });
    const result = await engine.analyze(createRequestContext());

    expect(errors).toHaveLength(1);
    expect(result.score.value).toBe(75);
  });
});
