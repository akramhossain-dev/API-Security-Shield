import type { JsonObject, ThreatSeverity } from "../types/index.js";

export * from "./console-logger.adapter.js";
export * from "./event-bus.js";

/**
 * Public event names emitted by the security platform.
 */
export type SecurityEventType =
  | "request.received"
  | "request.analyzed"
  | "threat.detected"
  | "threat.scored"
  | "action.enforced"
  | "rate_limit.triggered"
  | "rate_limit.exceeded"
  | "brute_force.detected"
  | "ip.blacklisted"
  | "security.alert"
  | "fingerprint.changed"
  | "honeypot.triggered"
  | "bot.detected"
  | "webhook.triggered"
  | "threat.blocked"
  | "plugin.registered"
  | "plugin.error"
  | "storage.error";

export type SecurityEventSeverity = "debug" | "info" | "warn" | "error" | "critical";

export interface SecurityEvent {
  readonly id: string;
  readonly type: SecurityEventType;
  readonly timestamp: string;
  readonly requestId?: string;
  readonly severity: SecurityEventSeverity;
  readonly data: JsonObject;
}

export interface SecurityEventHandler {
  /**
   * Handles a security event emitted by the platform.
   */
  handle(event: SecurityEvent): void | Promise<void>;
}

export interface ThreatDetectedEventData extends JsonObject {
  readonly category: ThreatSeverity | string;
  readonly detector: string;
}
