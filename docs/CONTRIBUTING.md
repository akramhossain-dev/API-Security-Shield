# Contributing to API Security Shield

Thank you for helping build API Security Shield. This project is security-sensitive, so contributions must balance developer experience, performance, correctness, and false positive risk.

## Code of Conduct

Contributors are expected to be respectful, constructive, and careful with security-related claims. Disagreements should focus on evidence, tests, and user impact.

## Security Reports

Do not open public issues for vulnerabilities in API Security Shield or bypasses that could put users at risk.

Responsible disclosure placeholder:

- Email: `security@example.com`
- Include affected version, reproduction steps, expected impact, and suggested mitigation when available.
- The maintainers should acknowledge valid reports, coordinate fixes privately, and publish advisories when appropriate.

The final security contact should be replaced before the first public release.

## Contribution Types

Useful contributions include:

- Detector rules with tests and false positive analysis.
- Performance improvements with benchmarks.
- Redis correctness fixes.
- Documentation improvements.
- Express integration improvements.
- Dashboard API improvements.
- Plugin examples.
- Security regression payloads.

## Development Expectations

- Use strict TypeScript.
- Keep public APIs typed and documented.
- Avoid introducing heavy dependencies into the request path.
- Redact sensitive data from logs and test snapshots.
- Add tests for security behavior changes.
- Include benchmark notes for performance-sensitive changes.
- Preserve backwards compatibility unless the change is explicitly breaking.

## Detector Rule Contributions

Detector rules require extra care.

Every detector rule contribution should include:

- The attack category.
- Example malicious payloads.
- Expected finding severity and confidence.
- Benign examples that should not match.
- Notes about possible false positives.
- Tests for encoded or normalized variants when relevant.

Rules must avoid regex patterns that can cause catastrophic backtracking.

## Pull Request Workflow

1. Open an issue for significant behavior changes.
2. Keep pull requests focused.
3. Add or update tests.
4. Update documentation when public behavior changes.
5. Include security and performance notes for detector, scorer, storage, or middleware changes.
6. Wait for maintainer review before merging.

## Commit Guidance

Use clear commit messages that describe behavior. Examples:

- `add xss detector payload normalization tests`
- `document redis key naming strategy`
- `fix brute force counter ttl handling`

## Testing Expectations

Before submitting a security behavior change, run the relevant checks:

- Unit tests for changed modules.
- Integration tests for Redis-backed behavior.
- E2E middleware tests for request outcomes.
- Security regression tests for detector payloads.
- Benchmark smoke tests for hot-path changes.

## Documentation Expectations

Documentation should be updated when:

- A public option is added or changed.
- A detector category changes behavior.
- A new event is emitted.
- A dashboard route changes shape.
- A plugin extension point is added.
- A storage key or TTL policy changes.

## False Positive Policy

False positives are security product bugs. Contributions that increase strictness must document:

- Why the stricter behavior is needed.
- Which applications might be affected.
- How users can tune or disable the behavior.
- Whether the change should be opt-in, warning-only, or blocking by default.

## Release Safety

Detector and scoring changes can disrupt production traffic. Maintainers should prefer prereleases, clear changelog entries, and migration guidance for changes that alter enforcement behavior.

