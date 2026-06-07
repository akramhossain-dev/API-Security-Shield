/* eslint-disable no-console */
import type { SecurityEvent, SecurityEventHandler, SecurityEventSeverity } from "./index.js";

export type ConsoleLoggerFormat = "json" | "pretty";

export interface ConsoleLoggerOptions {
  readonly minSeverity?: SecurityEventSeverity;
  readonly format?: ConsoleLoggerFormat;
  readonly includeData?: boolean;
}

const severityRank: Record<SecurityEventSeverity, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  critical: 50
};

/**
 * Console-backed event logger for development and basic production setups.
 */
export class ConsoleLoggerAdapter implements SecurityEventHandler {
  private readonly minSeverity: SecurityEventSeverity;
  private readonly format: ConsoleLoggerFormat;
  private readonly includeData: boolean;

  /**
   * Creates a console logger adapter.
   */
  public constructor(options: ConsoleLoggerOptions = {}) {
    this.minSeverity = options.minSeverity ?? "info";
    this.format = options.format ?? "json";
    this.includeData = options.includeData ?? true;
  }

  /**
   * Handles a security event by writing it to the appropriate console method.
   */
  public handle(event: SecurityEvent): void {
    if (!this.shouldLog(event.severity)) {
      return;
    }

    const message = this.formatEvent(event);

    if (event.severity === "debug") {
      console.debug(message);
      return;
    }

    if (event.severity === "warn") {
      console.warn(message);
      return;
    }

    if (event.severity === "error" || event.severity === "critical") {
      console.error(message);
      return;
    }

    console.info(message);
  }

  private shouldLog(severity: SecurityEventSeverity): boolean {
    return severityRank[severity] >= severityRank[this.minSeverity];
  }

  private formatEvent(event: SecurityEvent): string {
    const safeEvent = this.includeData ? event : { ...event, data: {} };

    if (this.format === "pretty") {
      return `[${safeEvent.timestamp}] ${safeEvent.severity.toUpperCase()} ${safeEvent.type} ${safeEvent.id}`;
    }

    return JSON.stringify(safeEvent);
  }
}
