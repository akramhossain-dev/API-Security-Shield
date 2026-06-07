# API Security Shield API Reference

This document describes the intended public API for API Security Shield. TypeScript snippets are conceptual documentation examples only.

## Installation

Package name:

```text
api-security-shield
```

Primary runtime target:

```text
Express.js on Node.js with TypeScript
```

## Basic Usage

```ts
import express from "express";
import { securityShield } from "api-security-shield";

const app = express();

app.use(
  securityShield({
    threatEngine: true,
    fingerprinting: true,
    botDetection: true,
    adaptiveRateLimit: true
  })
);
```

## `securityShield(options?)`

Creates Express middleware.

```ts
function securityShield(options?: SecurityShieldOptions): ExpressMiddleware;
```

## Configuration

```ts
interface SecurityShieldOptions {
  enabled?: boolean;
  environment?: "development" | "test" | "production";
  trustProxy?: boolean | string[] | TrustProxyResolver;
  threatEngine?: boolean | ThreatEngineOptions;
  fingerprinting?: boolean | FingerprintingOptions;
  adaptiveRateLimit?: boolean | RateLimitOptions;
  botDetection?: boolean | BotDetectionOptions;
  bruteForce?: boolean | BruteForceOptions;
  sqli?: boolean | DetectorOptions;
  xss?: boolean | DetectorOptions;
  reputation?: boolean | ReputationOptions;
  logger?: boolean | LoggerOptions;
  redis?: RedisOptions;
  dashboard?: boolean | DashboardOptions;
  webhooks?: WebhookOptions[];
  plugins?: SecurityShieldPlugin[];
}
```

Default behavior:

- `enabled` defaults to `true`.
- MVP detectors are enabled by zero-config defaults in production-safe mode.
- Redis is recommended for production.
- In-memory storage may be used for development.

## Threat Engine Options

```ts
interface ThreatEngineOptions {
  enabled?: boolean;
  warnAt?: number;
  blockAt?: number;
  criticalAt?: number;
  routeSensitivity?: Record<string, number>;
  customRules?: ScoringRule[];
  actions?: ActionPolicy[];
}
```

## Detector Interface

```ts
interface Detector {
  name: string;
  category: ThreatCategory;
  priority?: number;
  analyze(context: RequestContext): Promise<DetectorFinding[]> | DetectorFinding[];
}
```

```ts
interface DetectorFinding {
  id: string;
  category: ThreatCategory;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  score: number;
  location?: "query" | "body" | "headers" | "params" | "path" | "ip" | "fingerprint";
  evidence?: RedactedEvidence;
  message: string;
}
```

## Request Context

```ts
interface RequestContext {
  requestId: string;
  method: string;
  path: string;
  route?: string;
  ip: string;
  headers: Record<string, string | string[] | undefined>;
  query: unknown;
  body: unknown;
  params: Record<string, string>;
  fingerprint?: FingerprintResult;
  auth?: AuthContext;
  findings: DetectorFinding[];
  score?: ThreatScore;
}
```

## Threat Score

```ts
interface ThreatScore {
  value: number;
  level: "low" | "watch" | "warning" | "high" | "critical";
  reasons: string[];
  findings: DetectorFinding[];
}
```

## Actions

```ts
type ShieldActionType =
  | "allow"
  | "warn"
  | "throttle"
  | "challenge"
  | "block"
  | "ban";
```

```ts
interface ActionPolicy {
  when: ActionCondition;
  action: ShieldActionType;
  response?: ActionResponse;
}
```

```ts
interface CustomAction {
  name: string;
  execute(context: RequestContext, decision: ShieldDecision): Promise<ActionResult> | ActionResult;
}
```

## Storage Adapter

```ts
interface ShieldStorage {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttlSeconds?: number): Promise<void>;
  increment(key: string, ttlSeconds: number): Promise<number>;
  delete(key: string): Promise<void>;
  health(): Promise<StorageHealth>;
}
```

## Redis Options

```ts
interface RedisOptions {
  url?: string;
  keyPrefix?: string;
  connectTimeoutMs?: number;
  commandTimeoutMs?: number;
  maxRetries?: number;
}
```

Production guidance:

- Use Redis for multi-instance deployments.
- Configure explicit key prefix per environment.
- Monitor Redis latency and errors.

## Event API

```ts
type SecurityEventType =
  | "request.analyzed"
  | "threat.detected"
  | "threat.scored"
  | "action.enforced"
  | "rate_limit.exceeded"
  | "brute_force.detected"
  | "fingerprint.changed"
  | "honeypot.triggered"
  | "plugin.error"
  | "storage.error";
```

```ts
interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  timestamp: string;
  requestId?: string;
  severity: "debug" | "info" | "warn" | "error" | "critical";
  data: Record<string, unknown>;
}
```

## Plugin API

```ts
interface SecurityShieldPlugin {
  name: string;
  version: string;
  register(context: PluginContext): void | Promise<void>;
}
```

```ts
interface PluginContext {
  addDetector(detector: Detector): void;
  addAction(action: CustomAction): void;
  addScoringRule(rule: ScoringRule): void;
  on(event: SecurityEventType, handler: EventHandler): void;
  provideStorage?(storage: ShieldStorage): void;
}
```

Example:

```ts
const customPlugin = {
  name: "company-security-rules",
  version: "1.0.0",
  register(ctx) {
    ctx.addDetector(customDetector);
    ctx.on("threat.detected", handleThreat);
  }
};
```

## Dashboard API

```ts
function createDashboardRouter(options?: DashboardOptions): ExpressRouter;
```

```ts
interface DashboardOptions {
  storage?: ShieldStorage;
  includeRecentEvents?: boolean;
  maxRecentEvents?: number;
}
```

Dashboard routes:

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/summary` | Threat and traffic summary |
| `GET` | `/events` | Recent security events |
| `GET` | `/attackers` | Top attacking IPs or fingerprints |
| `GET` | `/rate-limits` | Current rate-limit pressure |
| `GET` | `/reputation/:identity` | Reputation lookup |
| `GET` | `/health` | Storage, plugin, and logger health |

Security requirement:

- The host application must mount authentication and authorization middleware before the dashboard router.

## Webhook Configuration

```ts
interface WebhookOptions {
  provider: "slack" | "discord" | "generic";
  url: string;
  minSeverity?: SecurityEvent["severity"];
  secret?: string;
  retry?: {
    attempts: number;
    backoffMs: number;
  };
}
```

Webhooks are post-MVP but should follow this public shape unless implementation work discovers a safer contract.

## Brute Force Integration

Host applications can report authentication outcomes for accurate brute force protection.

```ts
interface AuthAttemptReporter {
  success(context: RequestContext, identity: string): Promise<void>;
  failure(context: RequestContext, identity: string): Promise<void>;
}
```

## Error Behavior

Default failure policy:

- Detector failures emit `plugin.error` or internal error events and continue when safe.
- Storage failures emit `storage.error`.
- Production deployments may configure fail-open or fail-closed behavior for critical modules.
- Dashboard errors must not leak sensitive internals.

## Public API Stability

MVP public APIs should be stable for:

- Middleware initialization.
- Detector authoring.
- Event subscription.
- Redis storage configuration.
- Dashboard router mounting.

Experimental APIs should be clearly marked before release.
