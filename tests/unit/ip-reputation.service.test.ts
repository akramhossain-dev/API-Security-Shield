import { describe, expect, it } from "vitest";

import { EventBus, IpReputationService, MemoryStorageAdapter, type SecurityEvent } from "../../src/index.js";
import { createRequestContext } from "../fixtures/request-context.js";

describe("IpReputationService", () => {
  it("tracks request history and allows clean IPs", async () => {
    const service = new IpReputationService({ storage: new MemoryStorageAdapter() });
    const result = await service.assess(createRequestContext());

    expect(result.allowed).toBe(true);
    expect(result.score).toBe(0);
  });

  it("blacklists IPs when reputation score exceeds threshold", async () => {
    const events: SecurityEvent[] = [];
    const eventBus = new EventBus();
    eventBus.on("ip.blacklisted", (event) => {
      events.push(event);
    });
    const service = new IpReputationService({
      storage: new MemoryStorageAdapter(),
      eventBus,
      blacklistScore: 50
    });
    const context = createRequestContext();

    await service.recordThreat(context, {
      value: 75,
      level: "high",
      reasons: ["sqli"],
      findings: []
    }, []);
    const result = await service.assess(context);

    expect(result.allowed).toBe(false);
    expect(result.blacklisted).toBe(true);
    expect(events).toHaveLength(1);
  });

  it("allows whitelisted IPs even after blacklist state exists", async () => {
    const service = new IpReputationService({ storage: new MemoryStorageAdapter() });
    const context = createRequestContext();

    await service.blacklist(context.ip, "manual");
    await service.whitelist(context.ip);

    const result = await service.assess(context);
    expect(result.allowed).toBe(true);
    expect(result.whitelisted).toBe(true);
  });
});
