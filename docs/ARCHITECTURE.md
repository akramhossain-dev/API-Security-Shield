# API Security Shield Architecture

## Vision

API Security Shield is an intelligent API protection library for modern Node.js applications. It is designed to act as a lightweight API firewall, bot protection layer, threat detection engine, and abuse prevention system for Express.js services.

The project should feel simple to adopt and serious enough for production. A developer should be able to enable protection with a single middleware call, then progressively add Redis, custom detectors, dashboard routes, webhooks, and organization-specific policies as their application grows.

```ts
import { securityShield } from "api-security-shield";

app.use(
  securityShield({
    threatEngine: true,
    fingerprinting: true,
    botDetection: true,
    adaptiveRateLimit: true
  })
);
```

## Architecture Goals

- Modular packages with clear ownership boundaries.
- High performance request analysis with predictable latency.
- Event-driven internals for observability and extensibility.
- Type-safe public APIs and plugin contracts.
- Redis-backed distributed protection for production deployments.
- Zero-configuration default setup for quick adoption.
- Adapter-oriented future support for Fastify and NestJS.
- Optional MongoDB persistence for long-term audit and analytics.

## High-Level Components

```mermaid
flowchart TB
  Client[API Client] --> Express[Express Application]
  Express --> Middleware[Security Shield Middleware]
  Middleware --> Context[Request Context Builder]
  Context --> Fingerprint[Fingerprint Engine]
  Context --> RateLimit[Adaptive Rate Limiter]
  Context --> ThreatEngine[Threat Score Engine]
  ThreatEngine --> Detectors[Detector Pipeline]
  Detectors --> SQLi[SQLi Detector]
  Detectors --> XSS[XSS Detector]
  Detectors --> Bot[Bot Detector]
  Detectors --> BruteForce[Brute Force Detector]
  Detectors --> Reputation[IP Reputation]
  ThreatEngine --> Actions[Action Resolver]
  Actions --> Allow[Allow]
  Actions --> Warn[Warn]
  Actions --> Challenge[Challenge]
  Actions --> Block[Block]
  Middleware --> Events[Security Event Bus]
  Events --> Logger[Event Logger]
  Events --> Webhooks[Webhook Integrations]
  Events --> Dashboard[Dashboard API]
  RateLimit --> Redis[(Redis)]
  BruteForce --> Redis
  Reputation --> Redis
  Logger --> Mongo[(Optional MongoDB)]
```

## Core Concepts

### Request Context

The request context is the normalized internal object created for each incoming request. It contains request metadata, headers, IP data, body/query samples, route metadata, fingerprint data, detector findings, threat score, and the final enforcement decision.

### Detector

A detector inspects a request context and returns one or more findings. Detectors should be small, deterministic, and individually testable. Examples include SQL injection pattern detection, XSS payload detection, suspicious user-agent analysis, credential stuffing detection, and honeypot trap matches.

### Finding

A finding is a structured security signal produced by a detector. It includes severity, confidence, category, matched location, optional evidence, and scoring contribution.

### Threat Score

The threat score is a normalized risk value from `0` to `100`. It is calculated from detector findings, rate-limit state, IP reputation, fingerprint consistency, and route sensitivity.

### Action

An action is the enforcement outcome selected from the final threat score and policy configuration. Default actions are allow, warn, challenge, throttle, block, and ban.

### Event

An event is a structured message emitted by the system. Events are used for logging, dashboard analytics, webhooks, and plugin integrations.

### Plugin

A plugin extends the platform with custom detectors, actions, enrichers, event subscribers, integrations, or storage adapters.

## Security Model

API Security Shield uses layered decision-making:

1. Normalize the request into a safe internal context.
2. Apply fast pre-checks such as bypass rules, known bans, and trusted proxy parsing.
3. Run fingerprinting and state lookups.
4. Execute enabled detectors.
5. Calculate a threat score.
6. Resolve an action based on score thresholds and route policy.
7. Emit security events.
8. Continue, warn, throttle, challenge, block, or ban.

Default threat levels:

| Score | Level | Default action | Meaning |
| --- | --- | --- | --- |
| 0-24 | Low | Allow | Normal or low-risk traffic |
| 25-49 | Watch | Allow and log | Suspicious but not enough to disrupt |
| 50-69 | Warning | Warn and increase scrutiny | Multiple weak signals or one strong signal |
| 70-89 | High | Block or throttle | Likely attack or abuse |
| 90-100 | Critical | Block and escalate | Confirmed malicious behavior |

## Middleware Flow

```mermaid
sequenceDiagram
  participant C as Client
  participant E as Express
  participant S as Security Shield
  participant R as Redis
  participant D as Detectors
  participant A as Action Resolver
  participant App as Route Handler

  C->>E: HTTP request
  E->>S: Invoke middleware
  S->>S: Build request context
  S->>R: Load rate/reputation/fingerprint state
  S->>D: Run enabled detectors
  D-->>S: Findings
  S->>S: Calculate threat score
  S->>A: Resolve action
  alt Allow
    A-->>S: continue
    S->>App: next()
  else Throttle or Block
    A-->>S: enforce response
    S-->>C: security response
  end
  S->>S: Emit security events
```

## Request Lifecycle

```mermaid
flowchart LR
  A[Receive Request] --> B[Trust Proxy and IP Resolution]
  B --> C[Context Normalization]
  C --> D[Fingerprint Generation]
  D --> E[State Lookup]
  E --> F[Detector Pipeline]
  F --> G[Score Aggregation]
  G --> H[Policy Evaluation]
  H --> I{Decision}
  I -->|Allow| J[Call next]
  I -->|Warn| K[Add Headers and Log]
  I -->|Throttle| L[429 Response]
  I -->|Challenge| M[Challenge Response]
  I -->|Block| N[403 Response]
  I -->|Ban| O[Persist Ban and Block]
  J --> P[Emit Events]
  K --> P
  L --> P
  M --> P
  N --> P
  O --> P
```

## Threat Engine Design

The threat engine owns scoring, detector orchestration, and action resolution.

Responsibilities:

- Execute detectors in deterministic priority order.
- Support short-circuit behavior for known bans and honeypot hits.
- Merge detector findings into a normalized threat score.
- Apply route sensitivity multipliers.
- Support custom scoring rules.
- Emit score, finding, and action events.

Scoring inputs:

- Detector severity and confidence.
- Request route and HTTP method.
- Rate-limit pressure.
- IP reputation.
- Fingerprint stability.
- Authentication context when provided by the host app.
- Historical behavior from Redis.

```mermaid
flowchart TD
  Findings[Detector Findings] --> BaseScore[Base Score]
  Rate[Rate Limit State] --> Modifiers[Risk Modifiers]
  Reputation[IP Reputation] --> Modifiers
  Fingerprint[Fingerprint State] --> Modifiers
  Route[Route Sensitivity] --> Modifiers
  BaseScore --> Aggregate[Score Aggregation]
  Modifiers --> Aggregate
  Aggregate --> Thresholds[Threshold Evaluation]
  Thresholds --> Action[Final Action]
```

## Fingerprinting Design

Fingerprinting creates a stable but privacy-conscious identifier for request correlation and abuse detection.

Signals:

- IP address or trusted proxy client IP.
- User-Agent family and version.
- Accept, Accept-Language, Accept-Encoding, and connection headers.
- TLS/proxy-derived hints when available from the hosting environment.
- Session ID, authenticated user ID, or API key hash when provided.
- Optional browser hints for browser-facing APIs.

Principles:

- Do not store raw secrets, tokens, cookies, or full authorization headers.
- Hash sensitive values before persistence.
- Allow applications to provide custom fingerprint components.
- Support both strict and loose fingerprints for different detection modes.

## Adaptive Rate Limiting Design

Adaptive rate limiting combines static route limits with dynamic risk-based limits.

Inputs:

- Route policy.
- HTTP method.
- Fingerprint ID.
- IP address.
- Authenticated account or API key.
- Threat score.
- Recent attack events.

The limiter should support fixed window, sliding window, and token bucket strategies. Redis is required for distributed production deployments. In-memory storage is acceptable only for development and tests.

## Bot Detection Design

Bot detection uses layered signals:

- User-Agent allowlist and denylist checks.
- Missing or inconsistent browser headers.
- Suspicious request cadence.
- Repeated path discovery patterns.
- High error-rate behavior.
- Fingerprint churn.
- Known automation tooling signatures.

Bot detection should distinguish between malicious automation, unknown automation, and verified good bots. Verified good bots require cautious validation, preferably DNS or provider verification in a future phase.

## Event System Design

The event system is the backbone for observability and integration.

```mermaid
flowchart LR
  Middleware[Middleware] --> Bus[Event Bus]
  Threat[Threat Engine] --> Bus
  Rate[Rate Limiter] --> Bus
  Plugins[Plugins] --> Bus
  Bus --> Logger[Logger]
  Bus --> Dashboard[Dashboard Aggregator]
  Bus --> Webhooks[Webhook Dispatcher]
  Bus --> Custom[Custom Subscribers]
```

Event categories:

- `request.analyzed`
- `threat.detected`
- `threat.scored`
- `action.enforced`
- `rate_limit.exceeded`
- `brute_force.detected`
- `fingerprint.changed`
- `honeypot.triggered`
- `plugin.error`
- `storage.error`

Events should be structured, typed, and safe to serialize. Sensitive fields must be redacted before emission.

## Plugin System Design

Plugins are registered during middleware initialization and receive a typed registration context.

Plugin extension points:

- Detectors.
- Scorers.
- Actions.
- Request enrichers.
- Event subscribers.
- Storage adapters.
- Dashboard panels.
- Webhook providers.

```mermaid
flowchart TD
  Plugin[Plugin Package] --> Register[register context]
  Register --> Detectors[Add Detector]
  Register --> Actions[Add Action]
  Register --> Events[Subscribe to Events]
  Register --> Storage[Provide Storage Adapter]
  Register --> Dashboard[Add Dashboard Module]
```

Plugin requirements:

- Plugins must declare a name and version.
- Plugin hooks must be isolated from core failures.
- Plugin errors must emit events.
- Plugins must not mutate request context outside documented APIs.

## Redis Architecture

Redis stores short-lived and distributed security state.

Primary data:

- Rate-limit counters.
- Brute force attempt counters.
- IP and fingerprint reputation.
- Temporary bans.
- Honeypot escalations.
- Recent event aggregates for dashboard APIs.
- Fingerprint history.

Key pattern examples:

| Purpose | Key pattern | TTL |
| --- | --- | --- |
| Route rate limit | `ass:rl:{route}:{identity}` | Window duration |
| Brute force account | `ass:bf:acct:{accountHash}` | 15 minutes to 24 hours |
| IP reputation | `ass:rep:ip:{ipHash}` | Rolling, configurable |
| Temporary ban | `ass:ban:{identity}` | Ban duration |
| Fingerprint history | `ass:fp:{fingerprintHash}` | 7 to 30 days |
| Dashboard aggregate | `ass:dash:{metric}:{bucket}` | 24 hours to 30 days |

Redis operations should prefer atomic commands, Lua scripts, or transactions where correctness depends on multi-key updates.

## Dashboard Architecture

The dashboard API is an optional Express router mounted by the host application. It exposes security analytics and operational state, but authentication and authorization remain the host application's responsibility.

```mermaid
flowchart TB
  Admin[Admin Client] --> Host[Host App Auth]
  Host --> DashboardAPI[Security Dashboard API]
  DashboardAPI --> Aggregates[Metrics Aggregator]
  Aggregates --> Redis[(Redis)]
  DashboardAPI --> Events[Recent Events]
  Events --> Redis
  Events --> Mongo[(Optional MongoDB)]
```

Dashboard capabilities:

- Threat counts by category.
- Blocked request statistics.
- Top attacking IPs or fingerprints.
- Rate-limit pressure by route.
- Recent high-severity events.
- Ban and reputation inspection.
- Health status for Redis, logger, and plugins.

## API Design

Primary public entrypoints:

- `securityShield(options?)`: Express middleware factory.
- `createDashboardRouter(options?)`: optional dashboard API router.
- `createRedisStorage(options)`: Redis storage adapter.
- `definePlugin(plugin)`: plugin helper.
- `createDetector(detector)`: custom detector helper.

The public API should keep common usage simple while allowing deep customization through typed module options.

## Performance Considerations

- Keep detector execution bounded and configurable.
- Limit body scanning size by default.
- Avoid blocking network calls in the hot request path.
- Use Redis pipelining for state lookups.
- Cache compiled detection patterns.
- Support detector priority and early exits for critical decisions.
- Emit events asynchronously where possible.
- Redact and sample logs during high-volume attacks.

## Security Considerations

- Default to safe parsing and bounded scanning.
- Never log secrets, raw tokens, passwords, or full cookies.
- Treat `X-Forwarded-For` as untrusted unless trusted proxy configuration is enabled.
- Dashboard routes must require host-provided authentication.
- Webhooks must support signing or shared-secret validation where possible.
- Avoid regex patterns vulnerable to catastrophic backtracking.
- Store hashes for sensitive identity components.
- Provide clear controls for false positive tuning.

