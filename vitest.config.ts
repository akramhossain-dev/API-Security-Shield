import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"]
    },
    environment: "node",
    globals: true,
    include: ["tests/**/*.test.ts"],
    passWithNoTests: true
  },
  resolve: {
    alias: {
      "@api-security-shield/detectors": new URL("./packages/detectors/src/index.ts", import.meta.url).pathname,
      "@api-security-shield/rate-limit": new URL("./packages/rate-limit/src/index.ts", import.meta.url).pathname,
      "@api-security-shield/redis": new URL("./packages/redis/src/index.ts", import.meta.url).pathname,
      "@api-security-shield/reputation": new URL("./packages/reputation/src/index.ts", import.meta.url).pathname,
      "@api-security-shield/plugins": new URL("./packages/plugins/src/index.ts", import.meta.url).pathname,
      "@api-security-shield/dashboard": new URL("./packages/dashboard/src/index.ts", import.meta.url).pathname
    }
  }
});
