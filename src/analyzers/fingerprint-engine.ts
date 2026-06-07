import { createHash } from "node:crypto";

import type { FingerprintResult, RequestContext } from "../types/index.js";

export interface FingerprintEngineOptions {
  readonly salt?: string;
}

/**
 * Basic deterministic fingerprint engine.
 */
export class FingerprintEngine {
  private readonly salt: string;

  /**
   * Creates a fingerprint engine.
   */
  public constructor(options: FingerprintEngineOptions = {}) {
    this.salt = options.salt ?? "api-security-shield";
  }

  /**
   * Generates strict and loose fingerprints for a request context.
   */
  public generate(context: RequestContext): FingerprintResult {
    const strictComponents = this.collectStrictComponents(context);
    const looseComponents = this.collectLooseComponents(context);

    return {
      strict: this.hash(strictComponents),
      loose: this.hash(looseComponents),
      components: strictComponents.map((component) => component.split("=")[0] ?? component)
    };
  }

  private collectStrictComponents(context: RequestContext): readonly string[] {
    return [
      `ip=${context.ip}`,
      `method=${context.method.toUpperCase()}`,
      `path=${context.path}`,
      `user-agent=${this.header(context, "user-agent")}`,
      `accept=${this.header(context, "accept")}`,
      `accept-language=${this.header(context, "accept-language")}`,
      `accept-encoding=${this.header(context, "accept-encoding")}`,
      `user=${context.auth?.userIdHash ?? ""}`,
      `account=${context.auth?.accountIdHash ?? ""}`,
      `api-key=${context.auth?.apiKeyHash ?? ""}`
    ];
  }

  private collectLooseComponents(context: RequestContext): readonly string[] {
    return [
      `ip=${context.ip}`,
      `user-agent-family=${this.normalizeUserAgent(this.header(context, "user-agent"))}`,
      `accept-language=${this.header(context, "accept-language")}`,
      `user=${context.auth?.userIdHash ?? ""}`,
      `account=${context.auth?.accountIdHash ?? ""}`
    ];
  }

  private header(context: RequestContext, name: string): string {
    const value = context.headers[name] ?? context.headers[name.toLowerCase()];

    if (Array.isArray(value)) {
      return value.join(",");
    }

    if (typeof value === "string") {
      return value;
    }

    return "";
  }

  private normalizeUserAgent(userAgent: string): string {
    return userAgent.toLowerCase().replace(/\d+(?:\.\d+)*/g, "x").slice(0, 120);
  }

  private hash(components: readonly string[]): string {
    return createHash("sha256").update(this.salt).update("\0").update(components.join("\0")).digest("hex");
  }
}
