import type { EventBus } from "../../../../src/events/event-bus.js";
import type { BotDetectionStrategy, BotDetectionResult } from "./strategies/user-agent.js";

export interface BotDetectorOptions {
    readonly confidenceThreshold: number;
}

export class BotDetector {
    private readonly strategies: BotDetectionStrategy[] = [];

    public constructor(
        private readonly eventBus: EventBus,
        private readonly options: BotDetectorOptions = { confidenceThreshold: 0.7 }
    ) { }

    public use(strategy: BotDetectionStrategy): this {
        this.strategies.push(strategy);
        return this;
    }

    public async analyze(request: any, requestId: string): Promise<BotDetectionResult> {
        let maxConfidence = 0;
        let combinedReason = "";
        const results: Record<string, BotDetectionResult> = {};

        for (const strategy of this.strategies) {
            const result = await strategy.detect(request);
            results[strategy.name] = result;

            if (result.isBot) {
                if (result.confidence > maxConfidence) {
                    maxConfidence = result.confidence;
                    combinedReason = result.reason || "Bot detected by " + strategy.name;
                }
            }
        }

        const isBot = maxConfidence >= this.options.confidenceThreshold;

        if (isBot) {
            this.eventBus.emit({
                id: `bot-event-${Date.now()}`,
                type: "bot.detected",
                timestamp: new Date().toISOString(),
                requestId,
                severity: maxConfidence > 0.9 ? "critical" : "warn",
                data: {
                    confidence: maxConfidence,
                    reason: combinedReason,
                    strategies: results as any
                }
            });
        }

        return {
            isBot,
            confidence: maxConfidence,
            reason: combinedReason,
            metadata: results as unknown as NonNullable<BotDetectionResult["metadata"]>
        };
    }
}
