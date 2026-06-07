import type { EventBus } from "../../../../src/events/event-bus.js";
import type { SecurityEvent, SecurityEventType } from "../../../../src/events/index.js";
import type { WebhookProvider } from "../providers/generic.js";

export interface WebhookConfig {
    readonly eventTypes: SecurityEventType[] | "*";
    readonly provider: WebhookProvider;
}

export class WebhookDispatcher {
    private readonly configs: WebhookConfig[] = [];

    public constructor(private readonly eventBus: EventBus) {
        this.subscribe();
    }

    public register(config: WebhookConfig): void {
        this.configs.push(config);
    }

    private subscribe(): void {
        const allEvents: SecurityEventType[] = [
            "request.received", "request.analyzed", "threat.detected", "threat.scored",
            "action.enforced", "rate_limit.triggered", "rate_limit.exceeded",
            "brute_force.detected", "ip.blacklisted", "security.alert",
            "fingerprint.changed", "honeypot.triggered", "bot.detected",
            "webhook.triggered", "threat.blocked", "plugin.registered",
            "plugin.error", "storage.error"
        ];

        allEvents.forEach(eventType => {
            this.eventBus.on(eventType, async (event: SecurityEvent) => {
                await this.dispatch(event);
            });
        });
    }

    public async dispatch(event: SecurityEvent): Promise<void> {
        const matchingConfigs = this.configs.filter(config =>
            config.eventTypes === "*" || config.eventTypes.includes(event.type)
        );

        await Promise.allSettled(
            matchingConfigs.map(async config => {
                try {
                    await config.provider.send(event);

                    // Emit webhook.triggered event
                    this.eventBus.emit({
                        id: `webhook-triggered-${Date.now()}`,
                        type: "webhook.triggered",
                        timestamp: new Date().toISOString(),
                        requestId: event.requestId,
                        severity: "info",
                        data: {
                            sourceEvent: event.type,
                            provider: config.provider.name
                        }
                    });
                } catch (error) {
                    // Emit plugin.error if webhook fails
                    this.eventBus.emit({
                        id: `webhook-error-${Date.now()}`,
                        type: "plugin.error",
                        timestamp: new Date().toISOString(),
                        requestId: event.requestId,
                        severity: "error",
                        data: {
                            component: "webhook-dispatcher",
                            message: error instanceof Error ? error.message : "Webhook delivery failed",
                            provider: config.provider.name
                        }
                    });
                }
            })
        );
    }
}
