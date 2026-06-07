import type { SecurityPlugin } from "../sdk/plugin-base.js";

export class PluginRegistry {
    private readonly plugins = new Map<string, SecurityPlugin>();

    public register(plugin: SecurityPlugin): void {
        if (this.plugins.has(plugin.metadata.name)) {
            throw new Error(`Plugin ${plugin.metadata.name} is already registered`);
        }
        this.plugins.set(plugin.metadata.name, plugin);
    }

    public unregister(name: string): SecurityPlugin | undefined {
        const plugin = this.plugins.get(name);
        if (plugin) {
            this.plugins.delete(name);
        }
        return plugin;
    }

    public get(name: string): SecurityPlugin | undefined {
        return this.plugins.get(name);
    }

    public getAll(): SecurityPlugin[] {
        return Array.from(this.plugins.values());
    }
}
