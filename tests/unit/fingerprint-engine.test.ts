import { describe, expect, it } from "vitest";

import { FingerprintEngine } from "../../src/index.js";
import { createRequestContext } from "../fixtures/request-context.js";

describe("FingerprintEngine", () => {
  it("generates deterministic fingerprints", () => {
    const engine = new FingerprintEngine({ salt: "test" });
    const context = createRequestContext();

    expect(engine.generate(context)).toEqual(engine.generate(context));
  });

  it("changes strict fingerprints when strict headers change", () => {
    const engine = new FingerprintEngine({ salt: "test" });
    const first = engine.generate(createRequestContext());
    const second = engine.generate(
      createRequestContext({
        headers: {
          "user-agent": "vitest",
          accept: "text/html",
          "accept-language": "en-US",
          "accept-encoding": "gzip"
        }
      })
    );

    expect(first.strict).not.toBe(second.strict);
  });

  it("does not expose sensitive authorization or cookie components", () => {
    const engine = new FingerprintEngine({ salt: "test" });
    const result = engine.generate(
      createRequestContext({
        headers: {
          "user-agent": "vitest",
          accept: "application/json",
          authorization: "Bearer secret",
          cookie: "session=secret"
        }
      })
    );

    expect(result.components).not.toContain("authorization");
    expect(result.components).not.toContain("cookie");
  });
});
