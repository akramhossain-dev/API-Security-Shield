import EventEmitter from "eventemitter3";

import type { SecurityEvent, SecurityEventType } from "./index.js";

export type EventBusHandler = (event: SecurityEvent) => void | Promise<void>;

export interface EventBusSubscriptionOptions {
  readonly signal?: AbortSignal;
}

/**
 * Typed event bus for security events.
 */
export class EventBus {
  private readonly emitter = new EventEmitter<SecurityEventType, EventBusHandler>();
  private emittingDiagnostic = false;

  /**
   * Creates an event bus instance.
   */
  public constructor() {}

  /**
   * Subscribes to an event and returns an unsubscribe function.
   */
  public on(
    event: SecurityEventType,
    handler: EventBusHandler,
    options: EventBusSubscriptionOptions = {}
  ): () => void {
    this.emitter.on(event, handler);

    const unsubscribe = (): void => {
      this.off(event, handler);
    };

    options.signal?.addEventListener("abort", unsubscribe, { once: true });
    return unsubscribe;
  }

  /**
   * Subscribes to a single event occurrence.
   */
  public once(event: SecurityEventType, handler: EventBusHandler): () => void {
    this.emitter.once(event, handler);
    return (): void => {
      this.off(event, handler);
    };
  }

  /**
   * Removes an event handler.
   */
  public off(event: SecurityEventType, handler: EventBusHandler): void {
    this.emitter.off(event, handler);
  }

  /**
   * Emits an event synchronously through EventEmitter.
   */
  public emit(event: SecurityEvent): boolean {
    return this.emitter.emit(event.type, event);
  }

  /**
   * Emits an event and catches synchronous or asynchronous listener failures.
   */
  public async emitSafe(event: SecurityEvent): Promise<void> {
    const handlers = this.emitter.listeners(event.type);

    await Promise.all(
      handlers.map(async (handler) => {
        try {
          await handler(event);
        } catch (error) {
          await this.emitHandlerError(event, error);
        }
      })
    );
  }

  /**
   * Returns the number of listeners for an event.
   */
  public listenerCount(event: SecurityEventType): number {
    return this.emitter.listenerCount(event);
  }

  private async emitHandlerError(sourceEvent: SecurityEvent, error: unknown): Promise<void> {
    if (this.emittingDiagnostic) {
      return;
    }

    this.emittingDiagnostic = true;
    try {
      await this.emitSafe({
        id: `${sourceEvent.id}:handler-error`,
        type: "plugin.error",
        timestamp: new Date().toISOString(),
        requestId: sourceEvent.requestId,
        severity: "error",
        data: {
          sourceType: sourceEvent.type,
          message: error instanceof Error ? error.message : "Unknown event handler error"
        }
      });
    } finally {
      this.emittingDiagnostic = false;
    }
  }
}
