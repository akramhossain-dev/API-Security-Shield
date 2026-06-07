import type { AbstractStorage } from "../../../../src/interfaces/contracts.js";
import type { BotDetectionResult, BotDetectionStrategy } from "./user-agent.js";

export class FingerprintStrategy implements BotDetectionStrategy {
    public readonly name = "fingerprint-correlation";

    public constructor(
        private readonly storage: AbstractStorage,
        private readonly options = { maxIpsPerFingerprint: 5, windowSeconds: 3600 }
    ) { }

    public async detect(request: any): Promise<BotDetectionResult> {
        const fingerprint = request.fingerprint || request.headers["x-fingerprint"];
        const ip = request.ip || request.headers["x-forwarded-for"] || "unknown";

        if (!fingerprint) {
            return {
                isBot: false,
                confidence: 0,
                metadata: {}
            };
        }

        const key = `bot:fp:${fingerprint}:ips`;
        try {
            // Store IP in a set for this fingerprint (simplified for this implementation)
            // In real implementation, this would use Redis SADD/SCARD
            // Here we'll simulate with a string value containing IP count

            const currentIps = await this.storage.get<string[]>(key) || [];
            if (!currentIps.includes(ip)) {
                currentIps.push(ip);
                await this.storage.set(key, currentIps, this.options.windowSeconds);
            }

            const ipCount = currentIps.length;

            if (ipCount > this.options.maxIpsPerFingerprint) {
                return {
                    isBot: true,
                    confidence: Math.min(0.6 + (ipCount - this.options.maxIpsPerFingerprint) / 10, 0.95),
                    reason: `Single fingerprint associated with too many IPs: ${ipCount}`,
                    metadata: { ipCount, maxIps: this.options.maxIpsPerFingerprint }
                };
            }
        } catch (error) {
            // Ignore storage errors
        }

        return {
            isBot: false,
            confidence: 0,
            metadata: {}
        };
    }
}
