import type { EventBus } from "../events/event-bus.js";
import type { AbstractDetector } from "../interfaces/contracts.js";
import type {
  DetectorFinding,
  RequestContext,
  ShieldActionType,
  ShieldDecision,
  ThreatLevel,
  ThreatScore
} from "../types/index.js";

export interface BasicThreatEngineOptions {
  readonly detectors?: readonly AbstractDetector[];
  readonly warnAt?: number;
  readonly blockAt?: number;
  readonly criticalAt?: number;
  readonly eventBus?: EventBus;
}

export interface ThreatEngineResult {
  readonly context: RequestContext;
  readonly findings: readonly DetectorFinding[];
  readonly score: ThreatScore;
  readonly decision: ShieldDecision;
}

/**
 * Basic deterministic threat engine for Phase 1 detection and enforcement.
 */
export class BasicThreatEngine {
  private readonly detectors: readonly AbstractDetector[];
  private readonly warnAt: number;
  private readonly blockAt: number;
  private readonly criticalAt: number;
  private readonly eventBus?: EventBus;

  /**
   * Creates a basic threat engine.
   */
  public constructor(options: BasicThreatEngineOptions = {}) {
    this.detectors = [...(options.detectors ?? [])].sort((left, right) => left.priority - right.priority);
    this.warnAt = options.warnAt ?? 50;
    this.blockAt = options.blockAt ?? 70;
    this.criticalAt = options.criticalAt ?? 90;
    this.eventBus = options.eventBus;
  }

  /**
   * Runs detectors, calculates score, resolves action, and emits security events.
   */
  public async analyze(context: RequestContext): Promise<ThreatEngineResult> {
    const findings: DetectorFinding[] = [];

    for (const detector of this.detectors) {
      try {
        const detectorFindings = await detector.analyze(context);
        findings.push(...detectorFindings);

        for (const finding of detectorFindings) {
          await this.eventBus?.emitSafe({
            id: `${context.requestId}:${finding.id}`,
            type: "threat.detected",
            timestamp: new Date().toISOString(),
            requestId: context.requestId,
            severity: this.eventSeverity(finding.severity),
            data: {
              detector: detector.name,
              category: finding.category,
              findingId: finding.id,
              score: finding.score,
              confidence: finding.confidence,
              message: finding.message
            }
          });
        }
      } catch (error) {
        await this.eventBus?.emitSafe({
          id: `${context.requestId}:${detector.name}:error`,
          type: "plugin.error",
          timestamp: new Date().toISOString(),
          requestId: context.requestId,
          severity: "error",
          data: {
            detector: detector.name,
            message: error instanceof Error ? error.message : "Unknown detector error"
          }
        });
      }
    }

    const score = this.calculateScore(findings);
    const decision = this.resolveDecision(score);
    const analyzedContext: RequestContext = { ...context, findings, score };

    await this.eventBus?.emitSafe({
      id: `${context.requestId}:score`,
      type: "threat.scored",
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      severity: score.value >= this.blockAt ? "warn" : "info",
      data: {
        score: score.value,
        level: score.level,
        findings: findings.length
      }
    });

    await this.eventBus?.emitSafe({
      id: `${context.requestId}:action`,
      type: "action.enforced",
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      severity: decision.action === "block" ? "warn" : "info",
      data: {
        action: decision.action,
        reason: decision.reason,
        statusCode: decision.statusCode ?? 0
      }
    });

    return {
      context: analyzedContext,
      findings,
      score,
      decision
    };
  }

  private calculateScore(findings: readonly DetectorFinding[]): ThreatScore {
    const value = Math.min(
      100,
      Math.max(
        0,
        findings.reduce((total, finding) => total + finding.score, 0)
      )
    );
    const level = this.resolveLevel(value);

    return {
      value,
      level,
      reasons: findings.map((finding) => finding.message),
      findings
    };
  }

  private resolveLevel(score: number): ThreatLevel {
    if (score >= this.criticalAt) {
      return "critical";
    }

    if (score >= this.blockAt) {
      return "high";
    }

    if (score >= this.warnAt) {
      return "warning";
    }

    if (score >= 25) {
      return "watch";
    }

    return "low";
  }

  private resolveDecision(score: ThreatScore): ShieldDecision {
    const action: ShieldActionType = score.value >= this.blockAt ? "block" : score.value >= this.warnAt ? "warn" : "allow";

    return {
      action,
      score,
      statusCode: action === "block" ? 403 : undefined,
      reason: score.reasons[0] ?? "No threat detected"
    };
  }

  private eventSeverity(severity: DetectorFinding["severity"]): "info" | "warn" | "critical" {
    if (severity === "critical") {
      return "critical";
    }

    if (severity === "high" || severity === "medium") {
      return "warn";
    }

    return "info";
  }
}
