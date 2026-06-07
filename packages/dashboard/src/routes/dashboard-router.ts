import type { MetricsAggregator } from "../aggregators/metrics-aggregator.js";

export class DashboardRouter {
    public constructor(private readonly aggregator: MetricsAggregator) { }

    /**
     * Express-compatible middleware/router handler.
     */
    public async handleRequest(req: any, res: any): Promise<void> {
        const { pathname } = new URL(req.url, `http://${req.headers.host}`);

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
    }
}
