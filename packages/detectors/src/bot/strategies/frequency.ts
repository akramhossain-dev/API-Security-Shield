import type { AbstractStorage } from "../../../../src/interfaces/contracts.js";
import type { BotDetectionResult, BotDetectionStrategy } from "./user-agent.js";

export interface FrequencyStrategyOptions {
    readonly threshold: number;
    readonly windowSeconds: number;
}

export class FrequencyStrategy implements BotDetectionStrategy {
    public readonly name = "frequency-analysis";

    public constructor(
        private readonly storage: AbstractStorage,
        private readonly options: FrequencyStrategyOptions = { threshold: 50, windowSeconds: 60 }
    ) { }

    public async detect(request: any): Promise<BotDetectionResult> {
        const ip = request.ip || request.headers["x-forwarded-for"] || "unknown";
        const key = `bot:freq:${ip}`;

        try {
            const count = await this.storage.increment(key, this.options.windowSeconds);

            if (count > this.options.threshold) {
                return {
                    isBot: true,
                    confidence: Math.min(0.5 + (count - this.options.threshold) / 100, 0.9),
                    reason: `High request frequency: ${count} requests in ${this.options.windowSeconds}s`,
                    metadata: { count, threshold: this.options.threshold, windowSeconds: this.options.windowSeconds }
                };
            }
        } catch (error) {
            // Fallback if storage fails
        }

        return {
            isBot: false,
            confidence: 0,
            metadata: {}
        };
    }
}
