import type { SecurityEvent } from "../../../../src/events/index.js";
import { GenericWebhookProvider } from "./generic.js";

export class DiscordWebhookProvider extends GenericWebhookProvider {
    public override readonly name = "discord-webhook";

    public override async send(event: SecurityEvent): Promise<void> {
        const discordPayload = {
            embeds: [{
                title: `Security Alert: ${event.type}`,
                color: event.severity === "critical" ? 0xFF0000 : 0xFFAA00,
                fields: [
                    { name: "ID", value: event.id, inline: true },
                    { name: "Severity", value: event.severity, inline: true },
                    { name: "Timestamp", value: event.timestamp },
                    { name: "Details", value: JSON.stringify(event.data).substring(0, 1024) }
                ],
                footer: { text: "API Security Shield" }
            }]
        };

        // We can't use super.send because we need to transform the body
        await this.postToDiscord(discordPayload);
    }

    private async postToDiscord(payload: any): Promise<void> {
        const { RetryHandler } = await import("../utils/retry-handler.js");
        await RetryHandler.execute(async () => {
            const response = await fetch((this as any).options.url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error(`Discord webhook failed: ${response.status}`);
            }
        });
    }
}

export class SlackWebhookProvider extends GenericWebhookProvider {
    public override readonly name = "slack-webhook";

    public override async send(event: SecurityEvent): Promise<void> {
        const slackPayload = {
            blocks: [
                {
                    type: "header",
                    text: { type: "plain_text", text: "🚨 Security Alert" }
                },
                {
                    type: "section",
                    fields: [
                        { type: "mrkdwn", text: `*Type:*\n${event.type}` },
                        { type: "mrkdwn", text: `*Severity:*\n${event.severity}` }
                    ]
                },
                {
                    type: "section",
                    text: { type: "mrkdwn", text: `*Details:* \`\`\`${JSON.stringify(event.data, null, 2)}\`\`\`` }
                }
            ]
        };

        await this.postToSlack(slackPayload);
    }

    private async postToSlack(payload: any): Promise<void> {
        const { RetryHandler } = await import("../utils/retry-handler.js");
        await RetryHandler.execute(async () => {
            const response = await fetch((this as any).options.url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error(`Slack webhook failed: ${response.status}`);
            }
        });
    }
}
