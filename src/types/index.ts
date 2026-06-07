/**
 * Shared primitive and domain types for API Security Shield.
 */

export type ShieldEnvironment = "development" | "test" | "production";

export type ThreatCategory =
  | "sqli"
  | "xss"
  | "bot"
  | "brute_force"
  | "honeypot"
  | "reputation"
  | "rate_limit"
  | "geo"
  | "openapi"
  | "custom";

export type ThreatSeverity = "low" | "medium" | "high" | "critical";

export type ThreatLevel = "low" | "watch" | "warning" | "high" | "critical";

export type ShieldActionType = "allow" | "warn" | "throttle" | "challenge" | "block" | "ban";

export type RequestLocation =
  | "query"
  | "body"
  | "headers"
  | "params"
  | "path"
  | "ip"
  | "fingerprint";

export type JsonPrimitive = string | number | boolean | null;

export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];

export interface JsonObject {
  readonly [key: string]: JsonValue;
}

export interface RedactedEvidence {
  readonly location: RequestLocation;
  readonly sample?: string;
  readonly patternId?: string;
}

export interface AuthContext {
  readonly userIdHash?: string;
  readonly accountIdHash?: string;
  readonly apiKeyHash?: string;
  readonly roles?: readonly string[];
}

export interface FingerprintResult {
  readonly strict: string;
  readonly loose: string;
  readonly components: readonly string[];
}

export interface DetectorFinding {
  readonly id: string;
  readonly category: ThreatCategory;
  readonly severity: ThreatSeverity;
  readonly confidence: number;
  readonly score: number;
  readonly location?: RequestLocation;
  readonly evidence?: RedactedEvidence;
  readonly message: string;
}

export interface ThreatScore {
  readonly value: number;
  readonly level: ThreatLevel;
  readonly reasons: readonly string[];
  readonly findings: readonly DetectorFinding[];
}

export interface RequestContext {
  readonly requestId: string;
  readonly method: string;
  readonly path: string;
  readonly route?: string;
  readonly ip: string;
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly query: unknown;
  readonly body: unknown;
  readonly params: Readonly<Record<string, string>>;
  readonly fingerprint?: FingerprintResult;
  readonly auth?: AuthContext;
  readonly findings: readonly DetectorFinding[];
  readonly score?: ThreatScore;
}

export interface ShieldDecision {
  readonly action: ShieldActionType;
  readonly score: ThreatScore;
  readonly statusCode?: number;
  readonly reason: string;
}

export interface ActionResult {
  readonly handled: boolean;
  readonly statusCode?: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: JsonValue;
}

export interface StorageHealth {
  readonly ok: boolean;
  readonly latencyMs?: number;
  readonly message?: string;
}
