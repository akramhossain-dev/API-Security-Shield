# API Security Shield Development Guide

## Development Principles

- Build TypeScript-first public APIs.
- Keep core middleware small and composition-focused.
- Isolate detectors into independent modules.
- Make Redis the production state backend.
- Avoid synchronous heavy work in the request path.
- Treat every log and event as potentially sensitive.
- Prefer explicit extension contracts over undocumented mutation.
- Keep Express.js as the v1 target and design future frameworks as adapters.

## Intended Repository Tree

```text
api-security-shield/
├── packages/
│   ├── core/
│   │   ├── src/
│   │   │   ├── middleware/
│   │   │   ├── context/
│   │   │   ├── config/
│   │   │   ├── events/
│   │   │   ├── actions/
│   │   │   ├── types/
│   │   │   └── utils/
│   │   └── package.json
│   ├── threat-engine/
│   │   ├── src/
│   │   │   ├── scorers/
│   │   │   ├── rules/
│   │   │   ├── thresholds/
│   │   │   └── types/
│   │   └── package.json
│   ├── rate-limit/
│   │   ├── src/
│   │   │   ├── algorithms/
│   │   │   ├── policies/
│   │   │   └── stores/
│   │   └── package.json
│   ├── fingerprint/
│   │   ├── src/
│   │   │   ├── generators/
│   │   │   ├── normalizers/
│   │   │   └── hashing/
│   │   └── package.json
│   ├── detectors/
│   │   ├── src/
│   │   │   ├── sqli/
│   │   │   ├── xss/
│   │   │   ├── bot/
│   │   │   ├── brute-force/
│   │   │   ├── honeypot/
│   │   │   └── openapi/
│   │   └── package.json
│   ├── reputation/
│   │   ├── src/
│   │   │   ├── ip/
│   │   │   ├── identity/
│   │   │   └── bans/
│   │   └── package.json
│   ├── logger/
│   │   ├── src/
│   │   │   ├── sinks/
│   │   │   ├── redaction/
│   │   │   └── exporters/
│   │   └── package.json
│   ├── dashboard/
│   │   ├── src/
│   │   │   ├── routes/
│   │   │   ├── aggregators/
│   │   │   └── serializers/
│   │   └── package.json
│   ├── webhook/
│   │   ├── src/
│   │   │   ├── providers/
│   │   │   ├── dispatcher/
│   │   │   └── signing/
│   │   └── package.json
│   ├── redis/
│   │   ├── src/
│   │   │   ├── client/
│   │   │   ├── scripts/
│   │   │   ├── keys/
│   │   │   └── adapters/
│   │   └── package.json
│   ├── plugins/
│   │   ├── src/
│   │   │   ├── registry/
│   │   │   ├── lifecycle/
│   │   │   └── validation/
│   │   └── package.json
│   ├── express/
│   │   ├── src/
│   │   │   ├── middleware/
│   │   │   └── router/
│   │   └── package.json
│   ├── fastify/
│   │   └── package.json
│   └── nestjs/
│       └── package.json
├── src/
│   ├── index.ts
│   ├── middleware/
│   ├── detectors/
│   ├── analyzers/
│   ├── scorers/
│   ├── actions/
│   ├── storage/
│   ├── integrations/
│   ├── utils/
│   ├── constants/
│   ├── types/
│   ├── interfaces/
│   ├── config/
│   └── events/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SPECIFICATION.md
│   ├── DEVELOPMENT.md
│   ├── ROADMAP.md
│   ├── CONTRIBUTING.md
│   └── API_REFERENCE.md
├── examples/
│   ├── express-basic/
│   ├── express-redis/
│   ├── dashboard-api/
│   └── custom-plugin/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   ├── fixtures/
│   └── security/
├── benchmarks/
│   ├── middleware-overhead/
│   ├── detector-throughput/
│   └── redis-latency/
├── scripts/
│   ├── benchmark/
│   ├── release/
│   └── docs/
├── .github/
│   ├── workflows/
│   └── ISSUE_TEMPLATE/
├── package.json
├── tsconfig.json
├── pnpm-workspace.yaml
└── README.md
```

## Package Responsibilities

| Package | Responsibility |
| --- | --- |
| `core` | Request context, middleware orchestration, configuration, events, actions, shared types |
| `threat-engine` | Score calculation, severity mapping, custom scoring rules, threshold policies |
| `rate-limit` | Adaptive limits, route policies, algorithms, distributed counter abstraction |
| `fingerprint` | Request identity generation, hashing, fingerprint comparison |
| `detectors` | Built-in SQLi, XSS, bot, brute force, honeypot, and OpenAPI detectors |
| `reputation` | IP, account, fingerprint, and ban reputation state |
| `logger` | Event redaction, sinks, exporters, audit log handling |
| `dashboard` | Optional Express dashboard API and metric aggregation |
| `webhook` | Slack, Discord, and generic webhook dispatch |
| `redis` | Redis client adapter, key builders, scripts, distributed state |
| `plugins` | Plugin registry, lifecycle, validation, error isolation |
| `express` | Express.js middleware and router adapter |
| `fastify` | Future Fastify adapter |
| `nestjs` | Future NestJS module adapter |

## Root Source Layer

The root `src/` layer composes public exports for the main `api-security-shield` package. It should avoid duplicating logic owned by packages. Its job is to provide ergonomic imports, defaults, and compatibility helpers.

## TypeScript Standards

- Use strict TypeScript.
- Export public types intentionally.
- Avoid `any` in public interfaces.
- Prefer discriminated unions for event and action types.
- Keep detector results serializable.
- Treat configuration as immutable after initialization.
- Keep internal utility types private unless they are part of plugin authoring.

## Event-Driven Design Rules

- Core modules emit events but should not depend on concrete logger or webhook implementations.
- Events must be redacted before leaving the request lifecycle.
- Event subscribers must not block enforcement decisions.
- Plugin event errors should emit `plugin.error` and continue where safe.

## Storage Development

Production storage should use Redis. Local development may use an in-memory adapter for unit tests and simple examples.

Redis development expectations:

- Use namespaced keys.
- Keep TTLs explicit.
- Use atomic operations for counters and bans.
- Prefer pipelining when multiple state lookups are required.
- Provide integration tests against a real Redis instance.

MongoDB expectations:

- MongoDB is optional and used only for persistent event/audit storage.
- Core enforcement must not require MongoDB.

## Testing Strategy

Required test layers:

- Unit tests for detectors, scorers, config normalization, redaction, and key builders.
- Integration tests for Redis storage, rate limiting, brute force state, and dashboard routes.
- E2E Express tests for middleware behavior.
- Security regression tests for SQLi and XSS payload corpora.
- Performance benchmarks for middleware overhead and detector throughput.

Acceptance targets:

- Middleware adds minimal latency for normal traffic.
- Detector scans are bounded by size and time.
- Redis-backed limits remain correct under concurrency.
- Sensitive fields are redacted in all event sinks.

## Benchmarking

Benchmarks should measure:

- Baseline Express route without middleware.
- Middleware enabled with zero-config defaults.
- Middleware with all MVP detectors enabled.
- Redis latency under common rate-limit workloads.
- Detector throughput for common payload sizes.

Benchmark results should be documented for each release.

## Release Workflow

- Use semantic versioning.
- Publish prereleases for detector or scoring changes that may affect false positives.
- Maintain changelog entries for security behavior changes.
- Include migration notes for configuration changes.
- Run test, lint, typecheck, and benchmark smoke tests before release.

## Documentation Workflow

- Keep architecture and API docs updated with public API changes.
- Document false positive implications for new detector rules.
- Include examples for every public extension point.
- Mark experimental APIs clearly.

