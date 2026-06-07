import { AbstractDetector } from "../interfaces/contracts.js";
import type { DetectorFinding, RequestContext } from "../types/index.js";
import {
  collectScannedValues,
  decodeSafely,
  evidenceSample,
  type DetectorScanOptions
} from "./scan-utils.js";

interface XssPattern {
  readonly id: string;
  readonly pattern: RegExp;
  readonly score: number;
  readonly confidence: number;
  readonly severity: DetectorFinding["severity"];
  readonly message: string;
}

export interface XssDetectorOptions extends DetectorScanOptions {
  readonly patterns?: readonly XssPattern[];
}

const defaultPatterns: readonly XssPattern[] = [
  {
    id: "xss.script_tag",
    pattern: /<\s*script\b/i,
    score: 75,
    confidence: 0.95,
    severity: "critical",
    message: "Possible XSS script tag detected"
  },
  {
    id: "xss.event_handler",
    pattern: /\bon[a-z]{3,}\s*=/i,
    score: 70,
    confidence: 0.86,
    severity: "high",
    message: "Possible XSS inline event handler detected"
  },
  {
    id: "xss.dangerous_uri",
    pattern: /\b(?:javascript|data|vbscript):/i,
    score: 70,
    confidence: 0.84,
    severity: "high",
    message: "Possible XSS dangerous URI scheme detected"
  },
  {
    id: "xss.embedded_object",
    pattern: /<\s*(?:iframe|object|embed|link|meta)\b/i,
    score: 70,
    confidence: 0.84,
    severity: "high",
    message: "Possible XSS embedded object payload detected"
  },
  {
    id: "xss.svg_execution",
    pattern: /<\s*svg\b[\s\S]{0,300}\b(?:onload|animate|script)\b/i,
    score: 80,
    confidence: 0.88,
    severity: "critical",
    message: "Possible XSS SVG execution payload detected"
  },
  {
    id: "xss.execution_sink",
    pattern: /\b(?:eval|setTimeout|setInterval|Function)\s*\(/i,
    score: 25,
    confidence: 0.68,
    severity: "medium",
    message: "Possible XSS browser execution sink detected"
  }
];

/**
 * Detects common cross-site scripting payloads in bounded request fields.
 */
export class XssDetector extends AbstractDetector {
  private readonly options: DetectorScanOptions;
  private readonly patterns: readonly XssPattern[];

  /**
   * Creates an XSS detector.
   */
  public constructor(options: XssDetectorOptions = {}) {
    super("xss", "xss", 30);
    this.options = options;
    this.patterns = options.patterns ?? defaultPatterns;
  }

  /**
   * Analyzes request values for XSS patterns.
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
          category: "xss",
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
