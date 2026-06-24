import type { EventBus } from "../../../../src/events/event-bus.js";
import type { AbstractStorage } from "../../../../src/interfaces/contracts.js";
import { MemoryStorageAdapter } from "../../../../src/storage/index.js";
import type { DetectorFinding, RequestContext, ThreatScore } from "../../../../src/types/index.js";

export interface IpReputationOptions {
  readonly storage?: AbstractStorage;
  readonly eventBus?: EventBus;
  readonly historyTtlSeconds?: number;
  readonly blacklistTtlSeconds?: number;
  readonly blacklistScore?: number;
  readonly scoreDecay?: number;
}

export interface IpReputationRecord {
  readonly ip: string;
  readonly score: number;
  readonly firstSeen: string;
  readonly lastSeen: string;
  readonly requests: number;
  readonly threats: number;
}

export interface IpReputationResult {
  readonly ip: string;
  readonly score: number;
  readonly allowed: boolean;
  readonly whitelisted: boolean;
  readonly blacklisted: boolean;
  readonly reason: string;
}

/**
 * Tracks IP behavior, reputation score, and allow/block state.
 */
export class IpReputationService {
  private readonly storage: AbstractStorage;
  private readonly eventBus?: EventBus;
  private readonly historyTtlSeconds: number;
  private readonly blacklistTtlSeconds: number;
  private readonly blacklistScore: number;
  private readonly scoreDecay: number;

  /**
   * Creates an IP reputation service.
   */
  public constructor(options: IpReputationOptions = {}) {
    this.storage = options.storage ?? new MemoryStorageAdapter();
    this.eventBus = options.eventBus;
    this.historyTtlSeconds = options.historyTtlSeconds ?? 60 * 60 * 24 * 30;
    this.blacklistTtlSeconds = options.blacklistTtlSeconds ?? 60 * 60 * 24;
    this.blacklistScore = options.blacklistScore ?? 100;
    this.scoreDecay = options.scoreDecay ?? 0.98;
  }

  /**
   * Assesses whether an IP is currently allowed.
   */
  public async assess(context: RequestContext): Promise<IpReputationResult> {
    const ip = this.normalizeIp(context.ip);
    const [whitelisted, blacklisted, record] = await this.storage.mget<any>([
      this.allowKey(ip),
      this.blockKey(ip),
      this.recordKey(ip)
    ]);

    const updatedRecord = await this.touchRecord(ip, record);

    if (whitelisted === true) {
      return this.result(ip, 0, true, true, false, "ip whitelisted");
    }

    if (blacklisted === true) {
      return this.result(ip, updatedRecord.score, false, false, true, "ip blacklisted");
    }

    return this.result(ip, updatedRecord.score, true, false, false, "ip allowed");
  }

  /**
   * Records threat activity and blacklists IPs that exceed the threshold.
   */
  public async recordThreat(
    context: RequestContext,
    score: ThreatScore,
    findings: readonly DetectorFinding[]
  ): Promise<IpReputationRecord> {
    const ip = this.normalizeIp(context.ip);
    const [current, whitelisted] = await Promise.all([
      this.getRecord(ip),
      this.storage.get<boolean>(this.allowKey(ip))
    ]);
    const nextScore = Math.min(200, Math.round(current.score * this.scoreDecay + score.value + findings.length * 5));
    const next: IpReputationRecord = {
      ...current,
      score: nextScore,
      lastSeen: new Date().toISOString(),
      threats: current.threats + findings.length
    };

    await this.storage.set(this.recordKey(ip), next, this.historyTtlSeconds);

    if (next.score >= this.blacklistScore && whitelisted !== true) {
      await this.blacklist(ip, "reputation score exceeded threshold", this.blacklistTtlSeconds, context.requestId);
    }

    return next;
  }

  /**
   * Adds an IP to the whitelist.
   */
  public async whitelist(ip: string, ttlSeconds = this.historyTtlSeconds): Promise<void> {
    await this.storage.set(this.allowKey(this.normalizeIp(ip)), true, ttlSeconds);
    await this.storage.delete(this.blockKey(this.normalizeIp(ip)));
  }

  /**
   * Adds an IP to the blacklist.
   */
  public async blacklist(
    ip: string,
    reason: string,
    ttlSeconds = this.blacklistTtlSeconds,
    requestId?: string
  ): Promise<void> {
    const normalized = this.normalizeIp(ip);
    await this.storage.set(this.blockKey(normalized), true, ttlSeconds);

    void this.eventBus?.emitSafe({
      id: `${requestId ?? normalized}:ip-blacklisted`,
      type: "ip.blacklisted",
      timestamp: new Date().toISOString(),
      requestId,
      severity: "critical",
      data: {
        ip: normalized,
        reason,
        ttlSeconds
      }
    });

    void this.eventBus?.emitSafe({
      id: `${requestId ?? normalized}:security-alert`,
      type: "security.alert",
      timestamp: new Date().toISOString(),
      requestId,
      severity: "critical",
      data: {
        category: "ip_reputation",
        ip: normalized,
        reason
      }
    });
  }

  private async touchRecord(ip: string, current: IpReputationRecord | null): Promise<IpReputationRecord> {
    const now = new Date().toISOString();
    const next: IpReputationRecord = {
      ip: current?.ip ?? ip,
      score: current?.score ?? 0,
      firstSeen: current?.firstSeen || now,
      lastSeen: now,
      requests: (current?.requests ?? 0) + 1,
      threats: current?.threats ?? 0
    };

    await this.storage.set(this.recordKey(ip), next, this.historyTtlSeconds);
    return next;
  }

  private async touch(ip: string): Promise<IpReputationRecord> {
    const current = await this.getRecord(ip);
    const now = new Date().toISOString();
    const next: IpReputationRecord = {
      ...current,
      firstSeen: current.firstSeen || now,
      lastSeen: now,
      requests: current.requests + 1
    };

    await this.storage.set(this.recordKey(ip), next, this.historyTtlSeconds);
    return next;
  }

  private async getRecord(ip: string): Promise<IpReputationRecord> {
    return (
      (await this.storage.get<IpReputationRecord>(this.recordKey(ip))) ?? {
        ip,
        score: 0,
        firstSeen: "",
        lastSeen: "",
        requests: 0,
        threats: 0
      }
    );
  }

  private result(
    ip: string,
    score: number,
    allowed: boolean,
    whitelisted: boolean,
    blacklisted: boolean,
    reason: string
  ): IpReputationResult {
    return {
      ip,
      score,
      allowed,
      whitelisted,
      blacklisted,
      reason
    };
  }

  private normalizeIp(ip: string): string {
    return ip.replace(/[^a-zA-Z0-9_.:-]/g, "_").slice(0, 120);
  }

  private recordKey(ip: string): string {
    return `ip-reputation:record:${ip}`;
  }

  private allowKey(ip: string): string {
    return `ip-reputation:allow:${ip}`;
  }

  private blockKey(ip: string): string {
    return `ip-reputation:block:${ip}`;
  }
}
