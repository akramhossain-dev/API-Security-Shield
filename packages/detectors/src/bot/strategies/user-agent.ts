import type { JsonObject } from "../../../../../src/types/index.js";

export interface BotDetectionResult {
    readonly isBot: boolean;
    readonly confidence: number;
    readonly reason?: string;
    readonly metadata?: JsonObject;
}

export interface BotDetectionStrategy {
    readonly name: string;
    detect(request: any): Promise<BotDetectionResult>;
}

/**
 * Known bot User-Agent patterns.
 */
const KNOWN_BOT_PATTERNS = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /slurp/i,
    /search/i,
    /mediapartners/i,
    /wget/i,
    /curl/i,
    /python-requests/i,
    /go-http-client/i,
    /postmanruntime/i,
    /headlesschrome/i,
    /selenium/i,
    /puppeteer/i,
    /playwright/i,
    /shodan/i,
    /censys/i
];

export class UserAgentStrategy implements BotDetectionStrategy {
    public readonly name = "user-agent-analysis";

    public async detect(request: any): Promise<BotDetectionResult> {
        const userAgent = request.headers["user-agent"] || "";

        if (!userAgent) {
            return {
                isBot: true,
                confidence: 0.8,
                reason: "Missing User-Agent header",
                metadata: { userAgent: "" }
            };
        }

        for (const pattern of KNOWN_BOT_PATTERNS) {
            if (pattern.test(userAgent)) {
                return {
                    isBot: true,
                    confidence: 0.95,
                    reason: `Known bot User-Agent pattern matched: ${pattern}`,
                    metadata: { userAgent, matchedPattern: pattern.toString() }
                };
            }
        }

        return {
            isBot: false,
            confidence: 0,
            metadata: { userAgent }
        };
    }
}
