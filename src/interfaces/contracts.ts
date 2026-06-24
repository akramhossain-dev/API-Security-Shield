import type {
  ActionResult,
  DetectorFinding,
  RequestContext,
  ShieldDecision,
  StorageHealth
} from "../types/index.js";
import type { SecurityEvent, SecurityEventType } from "../events/index.js";

/**
 * Contract for request detectors that produce security findings.
 */
export abstract class AbstractDetector {
  /**
   * Creates a detector contract.
   */
  public constructor(
    public readonly name: string,
    public readonly category: string,
    public readonly priority: number = 100
  ) {}

  /**
   * Analyzes a request context and returns detector findings.
   */
  public abstract analyze(
    context: RequestContext
  ): Promise<readonly DetectorFinding[]> | readonly DetectorFinding[];
}

/**
 * Contract for custom enforcement actions.
 */
export abstract class AbstractAction {
  /**
   * Creates an action contract.
   */
  public constructor(public readonly name: string) {}

  /**
   * Executes an action after the shield resolves a decision.
   */
  public abstract execute(
    context: RequestContext,
    decision: ShieldDecision
  ): Promise<ActionResult> | ActionResult;
}

/**
 * Contract for scoring rules that can adjust a threat decision.
 */
export abstract class AbstractScoringRule {
  /**
   * Creates a scoring rule contract.
   */
  public constructor(public readonly name: string) {}

  /**
   * Calculates a score contribution for the request context.
   */
  public abstract score(context: RequestContext): Promise<number> | number;
}

/**
 * Contract for platform storage adapters.
 */
export abstract class AbstractStorage {
  /**
   * Creates a storage adapter contract.
   */
  public constructor(public readonly name: string) {}

  /**
   * Reads a value from storage.
   */
  public abstract get<T>(key: string): Promise<T | null>;

  /**
   * Reads multiple values from storage.
   */
  public async mget<T>(keys: readonly string[]): Promise<readonly (T | null)[]> {
    return Promise.all(keys.map((key) => this.get<T>(key)));
  }

  /**
   * Writes a value to storage.
   */
  public abstract set<T>(key: string, value: T, ttlSeconds?: number): Promise<void>;

  /**
   * Increments a numeric value in storage.
   */
  public abstract increment(key: string, ttlSeconds: number): Promise<number>;

  /**
   * Deletes a value from storage.
   */
  public abstract delete(key: string): Promise<void>;

  /**
   * Reports storage health.
   */
  public abstract health(): Promise<StorageHealth>;
}

/**
 * Contract for plugins that extend the platform.
 */
export abstract class AbstractPlugin {
  /**
   * Creates a plugin contract.
   */
  public constructor(
    public readonly name: string,
    public readonly version: string
  ) {}

  /**
   * Registers plugin capabilities with the host context.
   */
  public abstract register(context: PluginContext): void | Promise<void>;
}

export interface PluginContext {
  /**
   * Adds a detector to the detector pipeline.
   */
  addDetector(detector: AbstractDetector): void;

  /**
   * Adds a custom action to the action registry.
   */
  addAction(action: AbstractAction): void;

  /**
   * Adds a custom scoring rule to the scoring pipeline.
   */
  addScoringRule(rule: AbstractScoringRule): void;

  /**
   * Subscribes to a platform event.
   */
  on(event: SecurityEventType, handler: (event: SecurityEvent) => void | Promise<void>): void;
}
