import type { EventBus } from "../../../../src/events/event-bus.js";
import type { SecurityEvent } from "../../../../src/events/index.js";
import type { PluginRegistry } from "../registry/plugin-registry.js";
import type { SecurityPlugin } from "../sdk/plugin-base.js";

export class PluginRuntime {
    public constructor(
        private readonly eventBus: EventBus,
        private readonly registry: PluginRegistry
    ) {
        this.subscribeToEvents();
    }

    public async load(plugin: SecurityPlugin): Promise<void> {
        try {
            this.registry.register(plugin);
            if (plugin.onRegister) {
                await plugin.onRegister();
            }

            this.eventBus.emit({
                id: `plugin-reg-${Date.now()}`,
                type: "plugin.registered",
                timestamp: new Date().toISOString(),
                severity: "info",
                data: {
                    name: plugin.metadata.name,
                    version: plugin.metadata.version
                }
            });
        } catch (error) {
            this.eventBus.emit({
                id: `plugin-error-${Date.now()}`,
                type: "plugin.error",
                timestamp: new Date().toISOString(),
                severity: "error",
                data: {
                    component: "plugin-runtime",
                    message: error instanceof Error ? error.message : "Failed to load plugin",
                    plugin: plugin.metadata.name
                }
            });
            throw error;
        }
    }

    public async unload(name: string): Promise<void> {
        const plugin = this.registry.unregister(name);
        if (plugin && plugin.onUnregister) {
            await plugin.onUnregister();
        }
    }

    private subscribeToEvents(): void {
        // Listen to all events and pass to plugins
        const allEvents = ["threat.detected", "bot.detected", "security.alert"]; // selective for performance

        allEvents.forEach(type => {
            this.eventBus.on(type as any, async (event: SecurityEvent) => {
                const plugins = this.registry.getAll();
                await Promise.allSettled(
                    plugins.map(async plugin => {
                        if (plugin.onEvent) {
                            await this.safeExecute(() => plugin.onEvent!(event), plugin.metadata.name);
                        }
                    })
                );
            });
        });
    }

    public async runAnalysisHooks(request: any, context: any): Promise<void> {
        const plugins = this.registry.getAll();
        for (const plugin of plugins) {
            if (plugin.onAnalyze) {
                await this.safeExecute(() => plugin.onAnalyze!(request, context), plugin.metadata.name);
            }
        }
    }

    private async safeExecute<T>(fn: () => Promise<T>, pluginName: string): Promise<T | undefined> {
        try {
            // Basic timeout-based sandbox (simulated)
            const timeout = new Promise<undefined>((_, reject) =>
                setTimeout(() => reject(new Error("Plugin execution timed out")), 5000)
            );
            return await Promise.race([fn(), timeout]) as T;
        } catch (error) {
            this.eventBus.emit({
                id: `plugin-exec-error-${Date.now()}`,
                type: "plugin.error",
                timestamp: new Date().toISOString(),
                severity: "error",
                data: {
                    component: "plugin-runtime",
                    message: error instanceof Error ? error.message : "Plugin execution failed",
                    plugin: pluginName
                }
            });
            return undefined;
        }
    }
}
