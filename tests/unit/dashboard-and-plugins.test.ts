import { describe, it, expect, vi } from "vitest";
import { MetricsAggregator } from "../../packages/dashboard/src/aggregators/metrics-aggregator.js";
import { MemoryStorageAdapter } from "../../src/storage/memory-storage.adapter.js";
import { EventBus } from "../../src/events/event-bus.js";
import { PluginRuntime } from "../../packages/plugins/src/runtime/plugin-runtime.js";
import { PluginRegistry } from "../../packages/plugins/src/registry/plugin-registry.js";
import { SecurityPlugin } from "../../packages/plugins/src/sdk/plugin-base.js";

describe("Dashboard and Plugin Systems", () => {
    const eventBus = new EventBus();
    const storage = new MemoryStorageAdapter();

    describe("Dashboard API", () => {
        it("should aggregate metrics correctly", async () => {
            const aggregator = new MetricsAggregator(eventBus, storage);

            eventBus.emit({
                id: "e1", type: "bot.detected", timestamp: new Date().toISOString(), severity: "warn", data: {}
            });
            eventBus.emit({
                id: "e2", type: "threat.detected", timestamp: new Date().toISOString(), severity: "critical", data: {}
            });

            // Wait a bit for async event handlers
            await new Promise(resolve => setTimeout(resolve, 50));

            const metrics = await aggregator.getMetrics();
            expect(metrics.botsDetected).toBeGreaterThan(0);
            expect(metrics.threatsDetected).toBeGreaterThan(0);
        });
    });

    describe("Plugin System", () => {
        it("should register and trigger plugin hooks", async () => {
            const registry = new PluginRegistry();
            const runtime = new PluginRuntime(eventBus, registry);

            const mockHook = vi.fn().mockResolvedValue(undefined);

            class TestPlugin extends SecurityPlugin {
                public readonly metadata = { name: "test-plugin", version: "1.0.0" };
                public override async onEvent() { await mockHook(); }
            }

            const plugin = new TestPlugin();
            await runtime.load(plugin);

            eventBus.emit({
                id: "p1", type: "bot.detected", timestamp: new Date().toISOString(), severity: "warn", data: {}
            });

            await new Promise(resolve => setTimeout(resolve, 100));
            expect(mockHook).toHaveBeenCalled();
        });
    });
});
