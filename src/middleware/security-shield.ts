import { randomUUID } from "node:crypto";
import proxyAddr from "proxy-addr";

import type { NextFunction, Request, RequestHandler, Response } from "express";

import { FingerprintEngine, type FingerprintEngineOptions } from "../analyzers/fingerprint-engine.js";
import { securityShieldConfigSchema, type SecurityShieldConfigInput } from "../config/index.js";
import { SqlInjectionDetector, type SqlInjectionDetectorOptions } from "../detectors/sql-injection-detector.js";
import { XssDetector, type XssDetectorOptions } from "../detectors/xss-detector.js";
import { ConsoleLoggerAdapter, type ConsoleLoggerOptions } from "../events/console-logger.adapter.js";
import { EventBus } from "../events/event-bus.js";
import type { AbstractDetector, AbstractStorage } from "../interfaces/contracts.js";
import { BasicThreatEngine, type BasicThreatEngineOptions } from "../scorers/basic-threat-engine.js";
import { MemoryStorageAdapter } from "../storage/memory-storage.adapter.js";
import type { RequestContext } from "../types/index.js";
import {
  BruteForceProtection,
  type BruteForceProtectionOptions
} from "../../packages/detectors/src/brute-force/index.js";
import {
  AdaptiveRateLimiter,
  type AdaptiveRateLimiterOptions
} from "../../packages/rate-limit/src/index.js";
import { RedisStorageAdapter, type RedisStorageOptions } from "../../packages/redis/src/index.js";
import { IpReputationService, type IpReputationOptions } from "../../packages/reputation/src/index.js";
import {
  BotDetector,
  UserAgentStrategy,
  HeaderConsistencyStrategy,
  type BotDetectorOptions
} from "../../packages/detectors/src/bot/index.js";
import { PluginRegistry, PluginRuntime } from "../../packages/plugins/src/index.js";

export type SecurityShieldMiddlewareOptions = SecurityShieldConfigInput & {
  readonly eventBus?: EventBus;
  readonly loggerOptions?: ConsoleLoggerOptions;
  readonly storage?: AbstractStorage;
  readonly detectors?: readonly AbstractDetector[];
  readonly fingerprintOptions?: FingerprintEngineOptions;
  readonly threatEngineOptions?: Omit<BasicThreatEngineOptions, "detectors" | "eventBus">;
  readonly sqliOptions?: SqlInjectionDetectorOptions;
  readonly xssOptions?: XssDetectorOptions;
  readonly redisStorageOptions?: RedisStorageOptions;
  readonly rateLimiter?: AdaptiveRateLimiter;
  readonly rateLimiterOptions?: Omit<AdaptiveRateLimiterOptions, "storage" | "eventBus">;
  readonly ipReputation?: IpReputationService;
  readonly ipReputationOptions?: Omit<IpReputationOptions, "storage" | "eventBus">;
  readonly bruteForceProtection?: BruteForceProtection;
  readonly bruteForceOptions?: Omit<BruteForceProtectionOptions, "storage" | "eventBus">;
  readonly botDetector?: BotDetector;
  readonly botDetectionOptions?: BotDetectorOptions;
  readonly pluginRegistry?: PluginRegistry;
  readonly pluginRuntime?: PluginRuntime;
};

/**
 * Creates Express middleware for Phase 1 API security analysis.
 */
export function securityShield(options: SecurityShieldMiddlewareOptions = {}): RequestHandler {
  const config = securityShieldConfigSchema.parse(options);
  const eventBus = options.eventBus ?? new EventBus();
  const storage = options.storage ?? createStorage(options);
  const logger = new ConsoleLoggerAdapter(options.loggerOptions);
  const fingerprintEngine = new FingerprintEngine(options.fingerprintOptions);
  const detectors = options.detectors ?? [
    new SqlInjectionDetector(options.sqliOptions),
    new XssDetector(options.xssOptions)
  ];
  const threatEngine = new BasicThreatEngine({
    ...options.threatEngineOptions,
    detectors,
    eventBus
  });
  const ipReputation =
    options.ipReputation ??
    new IpReputationService({
      ...options.ipReputationOptions,
      storage,
      eventBus
    });
  const bruteForceProtection =
    options.bruteForceProtection ??
    new BruteForceProtection({
      ...options.bruteForceOptions,
      storage,
      eventBus
    });
  const rateLimiter =
    options.rateLimiter ??
    new AdaptiveRateLimiter({
      ...options.rateLimiterOptions,
      storage,
      eventBus
    });

  const botDetector =
    options.botDetector ??
    new BotDetector(eventBus, options.botDetectionOptions);

  if (!options.botDetector) {
    botDetector.use(new UserAgentStrategy()).use(new HeaderConsistencyStrategy());
  }

  const pluginRegistry = options.pluginRegistry ?? new PluginRegistry();
  const pluginRuntime = options.pluginRuntime ?? new PluginRuntime(eventBus, pluginRegistry);

  if (options.plugins) {
    for (const plugin of options.plugins) {
      pluginRuntime.load(plugin as any).catch((error) => {
        void eventBus.emitSafe({
          id: `plugin-load-error-${Date.now()}`,
          type: "plugin.error",
          timestamp: new Date().toISOString(),
          requestId: "init",
          severity: "error",
          data: {
            message: error instanceof Error ? error.message : "Failed to load plugin during initialization"
          }
        });
      });
    }
  }

  eventBus.on("request.received", (event) => logger.handle(event));
  eventBus.on("request.analyzed", (event) => logger.handle(event));
  eventBus.on("threat.detected", (event) => logger.handle(event));
  eventBus.on("threat.scored", (event) => logger.handle(event));
  eventBus.on("action.enforced", (event) => logger.handle(event));
  eventBus.on("rate_limit.triggered", (event) => logger.handle(event));
  eventBus.on("brute_force.detected", (event) => logger.handle(event));
  eventBus.on("ip.blacklisted", (event) => logger.handle(event));
  eventBus.on("security.alert", (event) => logger.handle(event));
  eventBus.on("plugin.error", (event) => logger.handle(event));
  eventBus.on("storage.error", (event) => logger.handle(event));

  return async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    if (!config.enabled) {
      next();
      return;
    }

    const requestId = resolveRequestId(request);
    const baseContext = buildRequestContext(request, requestId, config.trustProxy);

    try {
      const fingerprint = fingerprintEngine.generate(baseContext);
      const context: RequestContext = { ...baseContext, fingerprint };

      void eventBus.emitSafe({
        id: `${requestId}:received`,
        type: "request.received",
        timestamp: new Date().toISOString(),
        requestId,
        severity: "info",
        data: {
          method: context.method,
          path: context.path,
          ip: context.ip,
          fingerprint: fingerprint.loose
        }
      });

      await trackFingerprint(storage, fingerprint.strict);

      const reputation = await ipReputation.assess(context);
      if (!reputation.allowed) {
        sendBlocked(response, 403, "ip_blocked", "IP address blocked by API Security Shield", requestId, reputation.score);
        return;
      }

      const bruteForceCheck = await bruteForceProtection.check(context);
      if (!bruteForceCheck.allowed) {
        sendBlocked(
          response,
          429,
          "brute_force_detected",
          "Too many login attempts",
          requestId,
          75,
          bruteForceCheck.retryAfterSeconds
        );
        return;
      }

      response.on("finish", () => {
        if (response.statusCode === 401 || response.statusCode === 403) {
          void bruteForceProtection.recordAttempt(context).catch(() => {});
        } else if (response.statusCode === 200 || response.statusCode === 201 || response.statusCode === 204) {
          void bruteForceProtection.recordSuccess(context).catch(() => {});
        }
      });

      if (config.botDetection) {
        const botResult = await botDetector.analyze(request, requestId);
        if (botResult.isBot) {
          sendBlocked(
            response,
            403,
            "bot_detected",
            "Automated request blocked by API Security Shield",
            requestId,
            Math.round(botResult.confidence * 100)
          );
          return;
        }
      }

      await pluginRuntime.runAnalysisHooks(request, context);

      const result = await threatEngine.analyze(context);

      if (result.findings.length > 0) {
        await ipReputation.recordThreat(context, result.score, result.findings);
      }

      const rateLimit = await rateLimiter.evaluate(result.context, result.score);
      if (!rateLimit.allowed) {
        sendBlocked(
          response,
          429,
          "rate_limit_triggered",
          "Request rate limit exceeded",
          requestId,
          rateLimiter.toDecision(rateLimit).score.value,
          rateLimit.retryAfterSeconds
        );
        return;
      }

      void eventBus.emitSafe({
        id: `${requestId}:analyzed`,
        type: "request.analyzed",
        timestamp: new Date().toISOString(),
        requestId,
        severity: result.decision.action === "block" ? "warn" : "info",
        data: {
          method: context.method,
          path: context.path,
          score: result.score.value,
          action: result.decision.action,
          fingerprint: fingerprint.loose
        }
      });

      if (result.decision.action === "block") {
        response.status(result.decision.statusCode ?? 403).json({
          error: "request_blocked",
          message: "Request blocked by API Security Shield",
          requestId,
          score: result.score.value,
          level: result.score.level
        });
        return;
      }

      next();
    } catch (error) {
      void eventBus.emitSafe({
        id: `${requestId}:middleware-error`,
        type: "plugin.error",
        timestamp: new Date().toISOString(),
        requestId,
        severity: "error",
        data: {
          message: error instanceof Error ? error.message : "Unknown middleware error"
        }
      });
      next(error);
    }
  };
}

function createStorage(options: SecurityShieldMiddlewareOptions): AbstractStorage {
  if (options.redisStorageOptions) {
    return new RedisStorageAdapter(options.redisStorageOptions);
  }

  if (isRedisConfig(options.redis)) {
    return new RedisStorageAdapter(options.redis);
  }

  return new MemoryStorageAdapter();
}

function isRedisConfig(value: unknown): value is RedisStorageOptions {
  return typeof value === "object" && value !== null;
}

function resolveClientIp(request: Request, trustProxy?: boolean | string[]): string {
  const socketIp = request.socket.remoteAddress ?? "unknown";
  if (!trustProxy) {
    return request.ip ?? socketIp;
  }

  const trust = typeof trustProxy === "boolean"
    ? () => trustProxy
    : (addr: string) => trustProxy.includes(addr);

  const ip = proxyAddr(request, trust);
  return ip || request.ip || socketIp;
}

function buildRequestContext(request: Request, requestId: string, trustProxy?: boolean | string[]): RequestContext {
  return {
    requestId,
    method: request.method,
    path: request.path,
    route: typeof request.route?.path === "string" ? request.route.path : undefined,
    ip: resolveClientIp(request, trustProxy),
    headers: normalizeHeaders(request.headers),
    query: request.query,
    body: request.body,
    params: request.params,
    findings: []
  };
}

function normalizeHeaders(headers: Request["headers"]): Readonly<Record<string, string | readonly string[] | undefined>> {
  const normalized: Record<string, string | readonly string[] | undefined> = {};

  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = value;
  }

  return normalized;
}

function resolveRequestId(request: Request): string {
  const header = request.headers["x-request-id"];
  const value = Array.isArray(header) ? header[0] : header;
  return value && value.trim().length > 0 ? value : cryptoRandomId();
}

function cryptoRandomId(): string {
  return randomUUID();
}

async function trackFingerprint(storage: AbstractStorage, fingerprint: string): Promise<void> {
  const firstSeenKey = `fingerprint:${fingerprint}:first-seen`;
  const countKey = `fingerprint:${fingerprint}:count`;

  if ((await storage.get<string>(firstSeenKey)) === null) {
    await storage.set(firstSeenKey, new Date().toISOString(), 60 * 60 * 24);
  }

  await storage.increment(countKey, 60 * 60 * 24);
}

function sendBlocked(
  response: Response,
  statusCode: number,
  error: string,
  message: string,
  requestId: string,
  score: number,
  retryAfterSeconds?: number
): void {
  if (retryAfterSeconds !== undefined) {
    response.setHeader("Retry-After", String(retryAfterSeconds));
  }

  response.status(statusCode).json({
    error,
    message,
    requestId,
    score
  });
}
