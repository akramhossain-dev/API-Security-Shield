import { describe, expect, it } from "vitest";

import { securityShieldConfigSchema } from "../../src/config/index.js";

describe("repository foundation", () => {
  it("defines a zero-configuration security shield schema", () => {
    const config = securityShieldConfigSchema.parse({});

    expect(config.enabled).toBe(true);
    expect(config.environment).toBe("production");
  });
});
