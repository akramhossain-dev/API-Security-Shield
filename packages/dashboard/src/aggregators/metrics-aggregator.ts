import type { EventBus } from "../../../../src/events/event-bus.js";
import type { SecurityEvent } from "../../../../src/events/index.js";
import type { AbstractStorage } from "../../../../src/interfaces/contracts.js";

export interface SecurityMetrics {
    totalRequests: number;
    threatsDetected: number;
    botsDetected: number;
    ipsBlocked: number;
    rateLimitEvents: number;
}

export class MetricsAggregator {
    private readonly METRICS_KEY = "dashboard:metrics";
    private readonly TOP_THREATS_KEY = "dashboard:top_threats";
    private readonly EVENTS_LOG_KEY = "dashboard:events_log";

    private updateChain: Promise<void> = Promise.resolve();

    public constructor(
        private readonly eventBus: EventBus,
        private readonly storage: AbstractStorage
    ) {
        this.subscribe();
    }

    private subscribe(): void {
        this.eventBus.on("request.received", () => this.incrementMetric("totalRequests"));
        this.eventBus.on("threat.detected", () => this.incrementMetric("threatsDetected"));
        this.eventBus.on("bot.detected", () => this.incrementMetric("botsDetected"));
        this.eventBus.on("ip.blacklisted", () => this.incrementMetric("ipsBlocked"));
        this.eventBus.on("rate_limit.triggered", () => this.incrementMetric("rateLimitEvents"));

        // Log all important events
        const loggableEvents = [
            "threat.detected", "bot.detected", "ip.blacklisted",
            "rate_limit.exceeded", "brute_force.detected", "security.alert"
        ];

        loggableEvents.forEach(type => {
            this.eventBus.on(type as any, (event: SecurityEvent) => this.logEvent(event));
        });
    }

    private async incrementMetric(field: keyof SecurityMetrics): Promise<void> {
        this.updateChain = this.updateChain.then(async () => {
            try {
                const metrics = await this.storage.get<SecurityMetrics>(this.METRICS_KEY) || {
                    totalRequests: 0,
                    threatsDetected: 0,
                    botsDetected: 0,
                    ipsBlocked: 0,
                    rateLimitEvents: 0
                };
                metrics[field]++;
                await this.storage.set(this.METRICS_KEY, metrics);
            } catch (error) {
                // Ignore storage errors for metrics
            }
        });
        await this.updateChain;
    }

    private async logEvent(event: SecurityEvent): Promise<void> {
        this.updateChain = this.updateChain.then(async () => {
            try {
                const logs = await this.storage.get<SecurityEvent[]>(this.EVENTS_LOG_KEY) || [];
                logs.unshift(event);
                if (logs.length > 100) logs.pop(); // Keep last 100 events
                await this.storage.set(this.EVENTS_LOG_KEY, logs);
            } catch (error) {
                // Ignore storage errors for logs
            }
        });
        await this.updateChain;
    }

    public async getMetrics(): Promise<SecurityMetrics> {
        return await this.storage.get<SecurityMetrics>(this.METRICS_KEY) || {
            totalRequests: 0,
            threatsDetected: 0,
            botsDetected: 0,
            ipsBlocked: 0,
            rateLimitEvents: 0
        };
    }

    public async getRecentEvents(): Promise<SecurityEvent[]> {
        return await this.storage.get<SecurityEvent[]>(this.EVENTS_LOG_KEY) || [];
    }
}
