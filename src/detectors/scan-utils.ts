import type { RequestContext, RequestLocation } from "../types/index.js";

export interface DetectorScanOptions {
  readonly maxDepth?: number;
  readonly maxValues?: number;
  readonly maxStringLength?: number;
  readonly headers?: readonly string[];
}

export interface ScannedValue {
  readonly location: RequestLocation;
  readonly path: string;
  readonly value: string;
}

interface ScanState {
  count: number;
}

const defaultHeaders = ["user-agent", "referer", "origin"];

/**
 * Collects bounded string values from request locations detectors are allowed to inspect.
 */
export function collectScannedValues(
  context: RequestContext,
  options: DetectorScanOptions = {}
): readonly ScannedValue[] {
  const maxDepth = options.maxDepth ?? 4;
  const maxValues = options.maxValues ?? 200;
  const maxStringLength = options.maxStringLength ?? 4096;
  const state: ScanState = { count: 0 };
  const values: ScannedValue[] = [];

  appendValue(values, state, maxValues, {
    location: "path",
    path: "path",
    value: context.path.slice(0, maxStringLength)
  });

  scanUnknown(values, state, context.params, "params", "params", 0, maxDepth, maxValues, maxStringLength);
  scanUnknown(values, state, context.query, "query", "query", 0, maxDepth, maxValues, maxStringLength);
  scanUnknown(values, state, context.body, "body", "body", 0, maxDepth, maxValues, maxStringLength);

  for (const header of options.headers ?? defaultHeaders) {
    const raw = context.headers[header.toLowerCase()] ?? context.headers[header];
    const joined = Array.isArray(raw) ? raw.join(",") : raw;

    if (joined) {
      appendValue(values, state, maxValues, {
        location: "headers",
        path: `headers.${header}`,
        value: String(joined).slice(0, maxStringLength)
      });
    }
  }

  return values;
}

/**
 * Produces a short redacted evidence sample.
 */
export function evidenceSample(value: string): string {
  return value.replace(/\s+/g, " ").slice(0, 160);
}

/**
 * Safely URL-decodes a value a bounded number of times.
 */
export function decodeSafely(value: string, attempts = 2): string {
  let decoded = value;

  for (let index = 0; index < attempts; index += 1) {
    try {
      const next = decodeURIComponent(decoded.replace(/\+/g, " "));
      if (next === decoded) {
        break;
      }
      decoded = next;
    } catch {
      break;
    }
  }

  return decoded;
}

function scanUnknown(
  values: ScannedValue[],
  state: ScanState,
  input: unknown,
  location: RequestLocation,
  path: string,
  depth: number,
  maxDepth: number,
  maxValues: number,
  maxStringLength: number
): void {
  if (state.count >= maxValues || depth > maxDepth || input === null || input === undefined) {
    return;
  }

  if (typeof input === "string" || typeof input === "number" || typeof input === "boolean") {
    appendValue(values, state, maxValues, {
      location,
      path,
      value: String(input).slice(0, maxStringLength)
    });
    return;
  }

  if (Array.isArray(input)) {
    for (const [index, item] of input.entries()) {
      scanUnknown(
        values,
        state,
        item,
        location,
        `${path}[${index}]`,
        depth + 1,
        maxDepth,
        maxValues,
        maxStringLength
      );
    }
    return;
  }

  if (typeof input === "object") {
    for (const [key, item] of Object.entries(input as Record<string, unknown>)) {
      scanUnknown(
        values,
        state,
        item,
        location,
        `${path}.${key}`,
        depth + 1,
        maxDepth,
        maxValues,
        maxStringLength
      );
    }
  }
}

function appendValue(
  values: ScannedValue[],
  state: ScanState,
  maxValues: number,
  value: ScannedValue
): void {
  if (state.count >= maxValues || value.value.length === 0) {
    return;
  }

  values.push(value);
  state.count += 1;
}
