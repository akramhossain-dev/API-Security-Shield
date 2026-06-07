import type { BotDetectionResult, BotDetectionStrategy } from "./user-agent.js";

export class HeaderConsistencyStrategy implements BotDetectionStrategy {
    public readonly name = "header-consistency";

    public async detect(request: any): Promise<BotDetectionResult> {
        const headers = request.headers || {};
        const userAgent = headers["user-agent"] || "";

        // 1. Check for suspicious header combinations
        // Common browsers usually have 'accept-language' and 'accept-encoding'
        const hasAcceptLanguage = !!headers["accept-language"];
        const hasAcceptEncoding = !!headers["accept-encoding"];

        if (userAgent.includes("Mozilla") && (!hasAcceptLanguage || !hasAcceptEncoding)) {
            return {
                isBot: true,
                confidence: 0.7,
                reason: "Suspicious browser-like User-Agent missing standard browser headers",
                metadata: { hasAcceptLanguage, hasAcceptEncoding }
            };
        }

        // 2. Check for inconsistent connection/cache headers
        const cacheControl = headers["cache-control"];
        const pragma = headers["pragma"];
        if (cacheControl === "no-cache" && pragma === "no-cache" && !userAgent) {
            return {
                isBot: true,
                confidence: 0.6,
                reason: "Suspicious no-cache headers with missing User-Agent",
                metadata: { cacheControl, pragma }
            };
        }

        // 3. Check for specific bot headers
        if (headers["x-bot-name"] || headers["x-crawler-agent"]) {
            return {
                isBot: true,
                confidence: 0.9,
                reason: "Explicit bot headers found",
                metadata: { botHeader: headers["x-bot-name"] || headers["x-crawler-agent"] }
            };
        }

        return {
            isBot: false,
            confidence: 0,
            metadata: {}
        };
    }
}
