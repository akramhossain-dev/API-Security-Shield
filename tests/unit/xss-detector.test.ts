import { describe, expect, it } from "vitest";

import { XssDetector } from "../../src/index.js";
import { createRequestContext } from "../fixtures/request-context.js";

describe("XssDetector", () => {
  it("detects script tag payloads", () => {
    const detector = new XssDetector();
    const findings = detector.analyze(
      createRequestContext({
        body: {
          comment: "<script>alert(1)</script>"
        }
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.category).toBe("xss");
  });

  it("detects encoded dangerous URI payloads", () => {
    const detector = new XssDetector();
    const findings = detector.analyze(
      createRequestContext({
        query: {
          next: "javascript%3Aalert(1)"
        }
      })
    );

    expect(findings[0]?.evidence?.patternId).toBe("xss.dangerous_uri");
  });

  it("ignores benign HTML-like text", () => {
    const detector = new XssDetector();
    const findings = detector.analyze(
      createRequestContext({
        body: {
          comment: "I wrote <b>hello</b> in the docs"
        }
      })
    );

    expect(findings).toEqual([]);
  });
});
