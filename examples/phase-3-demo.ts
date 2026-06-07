import { EventBus } from "../src/events/event-bus.js";
import { BotDetector, UserAgentStrategy, HeaderConsistencyStrategy } from "../packages/detectors/src/bot/index.js";
import { WebhookDispatcher, GenericWebhookProvider } from "../packages/webhook/src/index.js";
import { MetricsAggregator } from "../packages/dashboard/src/index.js";
import { PluginRuntime, PluginRegistry, SecurityPlugin } from "../packages/plugins/src/index.js";
import { MemoryStorageAdapter } from "../src/storage/memory-storage.adapter.js";

async function main() {
    console.log("🚀 Initializing API Security Shield - Phase 3 Demo\n");

    const eventBus = new EventBus();
    const storage = new MemoryStorageAdapter();

    // 1. Setup Bot Detection
    const botDetector = new BotDetector(eventBus);
    botDetector.use(new UserAgentStrategy());
    botDetector.use(new HeaderConsistencyStrategy());
    console.log("✅ Bot Detection System initialized");

    // 2. Setup Webhooks
    const webhookDispatcher = new WebhookDispatcher(eventBus);
    webhookDispatcher.register({
        eventTypes: ["bot.detected", "threat.detected"],
        provider: new GenericWebhookProvider({ url: "https://httpbin.org/post" })
    });
    console.log("✅ Webhook System initialized");

    // 3. Setup Dashboard
    const metricsAggregator = new MetricsAggregator(eventBus, storage);
    console.log("✅ Security Dashboard API initialized");

    // 4. Setup Plugin System
    const pluginRegistry = new PluginRegistry();
    const pluginRuntime = new PluginRuntime(eventBus, pluginRegistry);

    class MyCustomPlugin extends SecurityPlugin {
        metadata = { name: "custom-logger", version: "1.0.0" };
        async onEvent(event) {
            console.log(`[Plugin] Event received: ${event.type}`);
        }
    }

    await pluginRuntime.load(new MyCustomPlugin());
    console.log("✅ Plugin System initialized\n");

    // --- Simulate Traffic ---
    console.log("--- Simulating Bot Traffic ---");
    const botReq = { headers: { "user-agent": "Googlebot" } };
    const botResult = await botDetector.analyze(botReq, "req-bot-1");
    console.log("Bot Detection Result:", botResult.isBot ? "🔴 BOT" : "🟢 HUMAN");

    console.log("\n--- Simulating Human Traffic ---");
    const humanReq = { headers: { "user-agent": "Mozilla/5.0 (Macintosh)" } };
    const humanResult = await botDetector.analyze(humanReq, "req-human-1");
    console.log("Human Detection Result:", humanResult.isBot ? "🔴 BOT" : "🟢 HUMAN");

    // --- Check Dashboard ---
    console.log("\n--- Dashboard Metrics ---");
    const metrics = await metricsAggregator.getMetrics();
    console.log(JSON.stringify(metrics, null, 2));

    console.log("\n✨ Phase 3 Demo completed successfully!");
}

main().catch(console.error);
