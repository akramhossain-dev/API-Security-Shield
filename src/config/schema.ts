import { z } from "zod";

/**
 * Runtime configuration schema for API Security Shield.
 */
export const securityShieldConfigSchema = z.object({
  enabled: z.boolean().default(true),
  environment: z.enum(["development", "test", "production"]).default("production"),
  trustProxy: z.union([z.boolean(), z.array(z.string())]).optional(),
  threatEngine: z.union([z.boolean(), z.record(z.unknown())]).default(true),
  fingerprinting: z.union([z.boolean(), z.record(z.unknown())]).default(true),
  adaptiveRateLimit: z.union([z.boolean(), z.record(z.unknown())]).default(true),
  botDetection: z.union([z.boolean(), z.record(z.unknown())]).default(true),
  bruteForce: z.union([z.boolean(), z.record(z.unknown())]).default(true),
  sqli: z.union([z.boolean(), z.record(z.unknown())]).default(true),
  xss: z.union([z.boolean(), z.record(z.unknown())]).default(true),
  reputation: z.union([z.boolean(), z.record(z.unknown())]).default(true),
  logger: z.union([z.boolean(), z.record(z.unknown())]).default(true),
  redis: z.record(z.unknown()).optional(),
  dashboard: z.union([z.boolean(), z.record(z.unknown())]).optional(),
  webhooks: z.array(z.record(z.unknown())).optional(),
  plugins: z.array(z.unknown()).optional()
});

export type SecurityShieldConfigInput = z.input<typeof securityShieldConfigSchema>;
export type SecurityShieldConfig = z.output<typeof securityShieldConfigSchema>;
