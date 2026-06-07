import { describe, it, expect, vi } from "vitest";
import { BotDetector } from "../../packages/detectors/src/bot/detector.js";
import { UserAgentStrategy } from "../../packages/detectors/src/bot/strategies/user-agent.js";
import { HeaderConsistencyStrategy } from "../../packages/detectors/src/bot/strategies/header-consistency.js";
import { EventBus } from "../../src/events/event-bus.js";

describe("Bot Detection System", () => {
    const eventBus = new EventBus();

    it("should detect bots based on User-Agent patterns", async () => {
        const detector = new BotDetector(eventBus);
        detector.use(new UserAgentStrategy());

        const botRequest = {
            headers: { "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" }
        };

        const result = await detector.analyze(botRequest, "req-123");
        expect(result.isBot).toBe(true);
        expect(result.confidence).toBeGreaterThan(0.9);
    });

    it("should detect bots missing standard headers for browser-like User-Agents", async () => {
        const detector = new BotDetector(eventBus);
        detector.use(new HeaderConsistencyStrategy());

        const suspiciousRequest = {
            headers: { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" }
            // Missing Accept-Language and Accept-Encoding
        };

        const result = await detector.analyze(suspiciousRequest, "req-456");
        expect(result.isBot).toBe(true);
        expect(result.reason).toContain("missing standard browser headers");
    });

    it("should not flag legitimate traffic", async () => {
        const detector = new BotDetector(eventBus);
        detector.use(new UserAgentStrategy());

        const humanRequest = {
            headers: { "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" }
        };

        const result = await detector.analyze(humanRequest, "req-789");
        expect(result.isBot).toBe(false);
    });
});
