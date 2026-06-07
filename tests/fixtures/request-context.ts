import type { RequestContext } from "../../src/types/index.js";

export function createRequestContext(overrides: Partial<RequestContext> = {}): RequestContext {
  return {
    requestId: "test-request",
    method: "GET",
    path: "/api/users",
    ip: "203.0.113.10",
    headers: {
      "user-agent": "vitest",
      accept: "application/json",
      "accept-language": "en-US",
      "accept-encoding": "gzip"
    },
    query: {},
    body: {},
    params: {},
    findings: [],
    ...overrides
  };
}
