import type { SecurityEvent } from "../../../../src/events/index.js";
import { RetryHandler } from "../utils/retry-handler.js";

export interface WebhookProvider {
    readonly name: string;
    send(event: SecurityEvent): Promise<void>;
}

export interface GenericWebhookOptions {
    readonly url: string;
    readonly secret?: string;
    readonly headers?: Record<string, string>;
}

export class GenericWebhookProvider implements WebhookProvider {
    public readonly name: string = "generic-webhook";

    public constructor(protected readonly options: GenericWebhookOptions) { }

    public async send(event: SecurityEvent): Promise<void> {
        const payload = JSON.stringify(event);
        const headers: Record<string, string> = {
            "Content-Type": "application/json",
            ...this.options.headers
        };

        if (this.options.secret) {
            const { PayloadSigner } = await import("../signing/payload-signer.js");
            headers["X-Shield-Signature"] = PayloadSigner.sign(payload, this.options.secret);
        }

        await RetryHandler.execute(async () => {
            const response = await fetch(this.options.url, {
                method: "POST",
                headers,
                body: payload
            });

            if (!response.ok) {
                throw new Error(`Webhook failed with status ${response.status}: ${await response.text()}`);
            }
        });
    }
}
