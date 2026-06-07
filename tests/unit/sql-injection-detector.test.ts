import { describe, expect, it } from "vitest";

import { SqlInjectionDetector } from "../../src/index.js";
import { createRequestContext } from "../fixtures/request-context.js";

describe("SqlInjectionDetector", () => {
  it("detects common SQL injection payloads", () => {
    const detector = new SqlInjectionDetector();
    const findings = detector.analyze(
      createRequestContext({
        query: {
          search: "' OR 1=1 --"
        }
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.category).toBe("sqli");
  });

  it("detects encoded union select payloads", () => {
    const detector = new SqlInjectionDetector();
    const findings = detector.analyze(
      createRequestContext({
        query: {
          q: "hello%20union%20select%20password%20from%20users"
        }
      })
    );

    expect(findings[0]?.evidence?.patternId).toBe("sqli.union_select");
  });

  it("ignores benign search strings", () => {
    const detector = new SqlInjectionDetector();
    const findings = detector.analyze(
      createRequestContext({
        query: {
          search: "select a plan for the union meeting"
        }
      })
    );

    expect(findings).toEqual([]);
  });
});
