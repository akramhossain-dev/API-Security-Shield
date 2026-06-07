# API Security Shield Specification

## Product Summary

API Security Shield is a production-ready TypeScript security middleware for Express.js. It provides API firewall behavior, threat scoring, adaptive rate limiting, request fingerprinting, bot detection, brute force protection, event logging, Redis-backed distributed state, dashboard APIs, webhooks, and a plugin system.

## Feature Status

| Feature | MVP v1.0 | Later phase |
| --- | --- | --- |
| Threat Score Engine | Yes | Advanced ML-assisted scoring |
| Adaptive Rate Limiting | Yes | Global tenant-aware controls |
| Request Fingerprinting | Yes | Browser challenge fingerprints |
| SQL Injection Detection | Yes | Managed rule feeds |
| XSS Detection | Yes | Context-aware sanitization guidance |
| Bot Detection | Partial | Verified bot validation and behavior models |
| Brute Force Protection | Yes | Credential stuffing intelligence feeds |
| Honeypot System | No | Yes |
| IP Reputation System | Partial | Shared reputation feeds |
| Geo Protection | No | Yes |
| OpenAPI Schema Protection | No | Yes |
| Security Event Logger | Yes | Long-term analytics and SIEM export |
| Dashboard API | Yes | Full web UI and RBAC |
| Security Webhooks | No | Yes |
| Plugin System | Basic | Marketplace-ready ecosystem |

## Threat Score Engine

The threat score engine calculates a normalized score from `0` to `100` for each request.

Requirements:

- Accept findings from all enabled detectors.
- Support severity, confidence, and category weights.
- Apply route sensitivity and identity reputation modifiers.
- Resolve score-based actions.
- Support custom scoring rules.
- Emit score and action events.
- Expose safe debugging metadata when enabled.

Default score policy:

| Level | Range | Default behavior |
| --- | --- | --- |
| Low | 0-24 | Allow |
| Watch | 25-49 | Allow and log |
| Warning | 50-69 | Warn and increase scrutiny |
| High | 70-89 | Block or throttle |
| Critical | 90-100 | Block and escalate |

## Adaptive Rate Limiting

Adaptive rate limiting protects endpoints based on route policy and request risk.

Requirements:

- Route-based limits.
- Identity-based limits using IP, fingerprint, user ID, API key, or custom identity.
- Risk-based limit tightening when threat score rises.
- Redis-backed distributed counters.
- In-memory development adapter.
- Configurable algorithms: fixed window, sliding window, token bucket.
- Standard `Retry-After` and rate-limit response metadata.

Default behavior:

- Public routes receive conservative generic limits.
- Authentication routes receive stricter brute force-aware limits.
- High-risk requests receive reduced effective quotas.

## Request Fingerprinting

Fingerprinting generates stable request identity signals without storing sensitive raw data.

Requirements:

- Generate IP fingerprint, header fingerprint, browser fingerprint, and session fingerprint.
- Support strict and loose fingerprint modes.
- Hash sensitive identity components.
- Allow custom fingerprint fields.
- Track fingerprint changes and emit events.
- Store fingerprint history in Redis for distributed deployments.

Fingerprint components:

- Client IP after trusted proxy resolution.
- User-Agent classification.
- Accept and language headers.
- Session ID hash when provided.
- Authenticated user ID hash when provided.
- API key hash when provided.

## SQL Injection Detection

SQLi detection scans structured request locations for malicious patterns.

Requirements:

- Scan query string, body, selected headers, and route params.
- Use a compiled pattern engine.
- Detect boolean-based, union-based, stacked query, comment, tautology, and time-based payloads.
- Record matched location and category.
- Enforce maximum scanned payload size.
- Avoid vulnerable regular expressions.
- Support custom SQLi rules.

Default action:

- High-confidence SQLi findings should produce a high or critical threat score.

## XSS Detection

XSS detection identifies dangerous script payloads and browser execution vectors.

Requirements:

- Scan query string, body, selected headers, and route params.
- Detect script tags, event handlers, dangerous URLs, encoded payloads, template injection patterns, and SVG/browser execution vectors.
- Normalize common encodings before scanning.
- Limit scan depth and payload size.
- Support custom XSS rules.

Default action:

- High-confidence executable payloads should trigger blocking on sensitive routes.

## Bot Detection

Bot detection identifies automated traffic and separates likely harmful automation from expected integrations.

Requirements:

- Analyze User-Agent and header consistency.
- Detect missing browser headers on browser-only routes.
- Detect suspicious request cadence.
- Detect path probing and excessive 404 behavior.
- Support allowlists for trusted API clients.
- Emit bot classification events.

MVP scope:

- Static and heuristic analysis.
- No verified good-bot DNS validation in v1.0.

## Brute Force Protection

Brute force protection tracks repeated authentication failures and account targeting.

Requirements:

- Track failed login attempts by IP, fingerprint, user/account identifier, and route.
- Detect credential stuffing patterns across multiple accounts.
- Detect account targeting from multiple fingerprints.
- Support temporary lockouts and escalating delays.
- Integrate with host applications through explicit success/failure reporting hooks.
- Store attempt state in Redis.

Host integration:

- The middleware can protect login routes generically.
- Accurate success/failure tracking requires the host app to report authentication outcomes.

## Honeypot System

Honeypots are post-MVP trap routes or hidden fields used to escalate suspicious actors.

Requirements:

- Register hidden endpoints.
- Detect access to trap routes.
- Increase reputation risk.
- Emit high-severity honeypot events.
- Optionally ban fingerprints or IPs.

## IP Reputation System

IP reputation tracks suspicious and malicious behavior over time.

Requirements:

- Maintain reputation score per IP hash.
- Support temporary bans and permanent bans.
- Support manual allowlist and blocklist.
- Decay scores over time.
- Integrate threat findings and honeypot events.

MVP scope:

- Basic local reputation state in Redis.
- No shared cloud intelligence feed.

## Geo Protection

Geo protection is a post-MVP policy layer.

Requirements:

- Country blocklist.
- Country allowlist.
- Region restrictions.
- Per-route overrides.
- Configurable behavior when location cannot be resolved.

Geo lookups must be optional to avoid forcing external dependencies into the hot path.

## OpenAPI Schema Protection

OpenAPI protection validates requests against the expected API contract.

Requirements:

- Validate method, path, params, query, headers, and body.
- Detect unexpected fields.
- Detect schema abuse and type confusion.
- Support route-level strictness.
- Produce structured findings instead of generic validation errors.

This feature is post-MVP because it requires careful schema loading, route matching, and performance design.

## Security Event Logger

The logger records security events for audit and monitoring.

Requirements:

- Emit structured JSON events.
- Redact sensitive fields.
- Support console, file, Redis stream, and optional MongoDB destinations.
- Support sampling and severity filtering.
- Provide exportable event format.

MVP scope:

- Console and Redis-backed recent event storage.
- MongoDB documented as optional adapter.

## Security Dashboard API

The dashboard API exposes operational security data.

Requirements:

- Mount as an optional Express router.
- Require host-provided authentication and authorization.
- Provide threat analytics, attack statistics, recent events, rate-limit pressure, reputation state, and system health.
- Use Redis aggregates by default.
- Avoid exposing raw secrets or request bodies.

Example route groups:

| Route | Purpose |
| --- | --- |
| `GET /summary` | High-level threat metrics |
| `GET /events` | Recent security events |
| `GET /attackers` | Top IPs or fingerprints |
| `GET /rate-limits` | Rate-limit pressure |
| `GET /reputation/:identity` | Reputation lookup |
| `GET /health` | Storage and plugin health |

## Security Webhooks

Webhooks are post-MVP integrations for alerting and automation.

Requirements:

- Discord webhook.
- Slack webhook.
- Generic webhook.
- Severity filtering.
- Retry with backoff.
- Request signing or shared secret support.
- Dead-letter handling for repeated failures.

## Plugin System

The plugin system provides controlled extension points.

Requirements:

- Register custom detectors.
- Register custom actions.
- Register storage adapters.
- Register event subscribers.
- Register request enrichers.
- Register dashboard modules.
- Isolate plugin failures.
- Validate plugin metadata.

MVP scope:

- Detector, action, and event subscriber plugins.

