import type { SecurityEvent } from "../../../../src/events/index.js";

export interface PluginMetadata {
    readonly name: string;
    readonly version: string;
    readonly description?: string;
    readonly author?: string;
}

export abstract class SecurityPlugin {
    public abstract readonly metadata: PluginMetadata;

    /**
     * Called when the plugin is being registered.
     */
    public async onRegister?(): Promise<void>;

    /**
     * Called when the plugin is being unregistered.
     */
    public async onUnregister?(): Promise<void>;

    /**
     * Hook for analyzing a request.
     */
    public async onAnalyze?(request: any, context: any): Promise<any>;

    /**
     * Hook for handling a security event.
     */
    public async onEvent?(event: SecurityEvent): Promise<void>;
}
