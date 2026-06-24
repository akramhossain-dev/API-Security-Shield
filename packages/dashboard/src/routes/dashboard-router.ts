import type { MetricsAggregator } from "../aggregators/metrics-aggregator.js";

export interface DashboardRouterOptions {
    readonly apiKey?: string;
    readonly authMiddleware?: (req: any, res: any, next: () => void) => void;
}

export class DashboardRouter {
    private readonly apiKey?: string;
    private readonly authMiddleware?: (req: any, res: any, next: () => void) => void;

    public constructor(
        private readonly aggregator: MetricsAggregator,
        options: DashboardRouterOptions = {}
    ) {
        this.apiKey = options.apiKey;
        this.authMiddleware = options.authMiddleware;
    }

    /**
     * Express-compatible middleware/router handler.
     */
    public async handleRequest(req: any, res: any): Promise<void> {
        const runLogic = async () => {
            const { pathname } = new URL(req.url, `http://${req.headers.host || "localhost"}`);

            try {
                if (pathname === "/api/security/stats") {
                    const metrics = await this.aggregator.getMetrics();
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify(metrics));
                    return;
                }

                if (pathname === "/api/security/events") {
                    const events = await this.aggregator.getRecentEvents();
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify(events));
                    return;
                }

                res.writeHead(404);
                res.end("Not Found");
            } catch (error) {
                res.writeHead(500);
                res.end(JSON.stringify({ error: "Internal Dashboard Error" }));
            }
        };

        if (this.apiKey) {
            const authHeader = req.headers["authorization"] || req.headers["x-api-key"];
            const token = typeof authHeader === "string" && authHeader.startsWith("Bearer ")
                ? authHeader.substring(7)
                : authHeader;

            if (token !== this.apiKey) {
                res.writeHead(401, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ error: "Unauthorized: Invalid API Key" }));
                return;
            }
        }

        if (this.authMiddleware) {
            await new Promise<void>((resolve, reject) => {
                this.authMiddleware!(req, res, () => {
                    runLogic().then(resolve, reject);
                });
            });
            return;
        }

        await runLogic();
    }
}
