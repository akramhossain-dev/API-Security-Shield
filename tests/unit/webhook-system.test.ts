import { describe, it, expect, vi } from "vitest";
import { WebhookDispatcher } from "../../packages/webhook/src/dispatcher/webhook-dispatcher.js";
import { GenericWebhookProvider } from "../../packages/webhook/src/providers/generic.js";
import { EventBus } from "../../src/events/event-bus.js";

describe("Webhook System", () => {
    const eventBus = new EventBus();

    it("should dispatch webhooks when events occur", async () => {
        const dispatcher = new WebhookDispatcher(eventBus);
        const mockProvider = {
            name: "mock-provider",
            send: vi.fn().mockResolvedValue(undefined)
        };

        dispatcher.register({
            eventTypes: ["threat.detected"],
            provider: mockProvider
        });

        const event = {
            id: "evt-1",
            type: "threat.detected" as const,
            timestamp: new Date().toISOString(),
            severity: "warn" as const,
            data: { reason: "test" }
        };

        await dispatcher.dispatch(event);

        expect(mockProvider.send).toHaveBeenCalledWith(event);
    });

    it("should sign payloads if secret is provided", async () => {
        // This is more of an integration test for GenericWebhookProvider
        // We'll mock fetch to verify headers
        const globalFetch = global.fetch;
        global.fetch = vi.fn().mockResolvedValue({ ok: true });

        const provider = new GenericWebhookProvider({
            url: "http://example.com/webhook",
            secret: "test-secret"
        });

        const event = {
            id: "evt-2",
            type: "security.alert" as const,
            timestamp: new Date().toISOString(),
            severity: "critical" as const,
            data: { msg: "critical alert" }
        };

        await provider.send(event);

        const fetchCall = vi.mocked(global.fetch).mock.calls[0];
        expect(fetchCall).toBeDefined();
        const headers = (fetchCall?.[1]?.headers ?? {}) as Record<string, string>;
        expect(headers["X-Shield-Signature"]).toBeDefined();

        global.fetch = globalFetch; // Restore fetch
    });
});
