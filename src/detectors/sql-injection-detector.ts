import { AbstractDetector } from "../interfaces/contracts.js";
import type { DetectorFinding, RequestContext } from "../types/index.js";
import {
  collectScannedValues,
  decodeSafely,
  evidenceSample,
  type DetectorScanOptions
} from "./scan-utils.js";

interface SqlInjectionPattern {
  readonly id: string;
  readonly pattern: RegExp;
  readonly score: number;
  readonly confidence: number;
  readonly severity: DetectorFinding["severity"];
  readonly message: string;
}

export interface SqlInjectionDetectorOptions extends DetectorScanOptions {
  readonly patterns?: readonly SqlInjectionPattern[];
}

const defaultPatterns: readonly SqlInjectionPattern[] = [
  {
    id: "sqli.union_select",
    pattern: /\bunion\s+(?:all\s+)?select\b/i,
    score: 75,
    confidence: 0.92,
    severity: "critical",
    message: "Possible SQL injection union-select payload detected"
  },
  {
    id: "sqli.tautology",
    pattern: /(?:'|"|\b)\s*(?:or|and)\s+(?:'?\w+'?\s*=\s*'?\w+'?|\d+\s*=\s*\d+)/i,
    score: 70,
    confidence: 0.82,
    severity: "high",
    message: "Possible SQL injection tautology detected"
  },
  {
    id: "sqli.stacked_query",
    pattern: /;\s*(?:select|insert|update|delete|drop|alter|create|truncate)\b/i,
    score: 75,
    confidence: 0.88,
    severity: "critical",
    message: "Possible SQL injection stacked query detected"
  },
  {
    id: "sqli.comment_sequence",
    pattern: /(?:--|#|\/\*)\s*(?:$|\w)/i,
    score: 25,
    confidence: 0.72,
    severity: "medium",
    message: "Possible SQL injection comment sequence detected"
  },
  {
    id: "sqli.time_delay",
    pattern: /\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
    score: 80,
    confidence: 0.9,
    severity: "critical",
    message: "Possible SQL injection time-delay payload detected"
  },
  {
    id: "sqli.metadata_table",
    pattern: /\b(?:information_schema|sysobjects|pg_catalog|sqlite_master)\b/i,
    score: 30,
    confidence: 0.8,
    severity: "high",
    message: "Possible SQL metadata table probing detected"
  },
  {
    id: "sqli.dangerous_procedure",
    pattern: /\b(?:xp_cmdshell|sp_executesql|load_file|into\s+outfile)\b/i,
    score: 85,
    confidence: 0.95,
    severity: "critical",
    message: "Possible dangerous SQL procedure usage detected"
  }
];

/**
 * Detects common SQL injection payloads in bounded request fields.
 */
export class SqlInjectionDetector extends AbstractDetector {
  private readonly options: DetectorScanOptions;
  private readonly patterns: readonly SqlInjectionPattern[];

  /**
   * Creates a SQL injection detector.
   */
  public constructor(options: SqlInjectionDetectorOptions = {}) {
    super("sql-injection", "sqli", 20);
    this.options = options;
    this.patterns = options.patterns ?? defaultPatterns;
  }

  /**
   * Analyzes request values for SQL injection patterns.
   */
  public analyze(context: RequestContext): readonly DetectorFinding[] {
    const findings: DetectorFinding[] = [];

    for (const scanned of collectScannedValues(context, this.options)) {
      const normalized = decodeSafely(scanned.value);

      for (const pattern of this.patterns) {
        if (!pattern.pattern.test(normalized)) {
          continue;
        }

        findings.push({
          id: `${pattern.id}:${scanned.path}`,
          category: "sqli",
          severity: pattern.severity,
          confidence: pattern.confidence,
          score: pattern.score,
          location: scanned.location,
          evidence: {
            location: scanned.location,
            sample: evidenceSample(scanned.value),
            patternId: pattern.id
          },
          message: pattern.message
        });
        break;
      }
    }

    return findings;
  }
}
