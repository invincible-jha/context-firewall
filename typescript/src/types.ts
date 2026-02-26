// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @module types
 * Shared type definitions for context-firewall.
 * All public API shapes are defined here and re-exported from index.ts.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Sensitivity levels
// ---------------------------------------------------------------------------

/**
 * Sensitivity level of a domain.
 * Higher sensitivity means stricter crossing rules apply by default.
 */
export type SensitivityLevel = "low" | "medium" | "high" | "critical";

export const SensitivityLevelSchema = z.enum([
  "low",
  "medium",
  "high",
  "critical",
]);

// ---------------------------------------------------------------------------
// Direction
// ---------------------------------------------------------------------------

/**
 * Direction of a boundary rule.
 * - `one-way`: data may only flow from `fromDomain` to `toDomain`.
 * - `bidirectional`: the rule applies in both directions.
 */
export type BoundaryDirection = "one-way" | "bidirectional";

export const BoundaryDirectionSchema = z.enum(["one-way", "bidirectional"]);

// ---------------------------------------------------------------------------
// Data payload
// ---------------------------------------------------------------------------

/**
 * The data payload that the firewall inspects.
 * May contain any combination of text, structured keys, or tags.
 * Using `Record<string, unknown>` keeps the API flexible while preserving
 * strict typing at the boundary.
 */
export type DataPayload = Readonly<Record<string, unknown>>;

export const DataPayloadSchema = z.record(z.string(), z.unknown());

// ---------------------------------------------------------------------------
// Data classification result
// ---------------------------------------------------------------------------

/**
 * The output of a `DataClassifier.classify` call.
 */
export interface DataClassification {
  /** The domain that best matches the data payload. */
  readonly domain: string;
  /** The data type(s) detected within the payload (e.g. "medical", "financial"). */
  readonly detectedTypes: ReadonlyArray<string>;
  /** The keywords that triggered this classification, for auditability. */
  readonly matchedKeywords: ReadonlyArray<string>;
  /** Confidence expressed as a ratio 0–1 based on keyword hit density. */
  readonly confidence: number;
}

export const DataClassificationSchema = z.object({
  domain: z.string().min(1),
  detectedTypes: z.array(z.string()),
  matchedKeywords: z.array(z.string()),
  confidence: z.number().min(0).max(1),
});

// ---------------------------------------------------------------------------
// Firewall decision
// ---------------------------------------------------------------------------

/**
 * The result returned by `ContextFirewall.check`.
 */
export interface FirewallDecision {
  /** Whether the data crossing is permitted. */
  readonly allowed: boolean;
  /** Human-readable explanation for the decision. */
  readonly reason: string;
  /** The name of the boundary rule that was applied, if any. */
  readonly appliedRuleName: string | null;
  /** Data types that were blocked, if any. */
  readonly blockedDataTypes: ReadonlyArray<string>;
  /** The classification result that informed the decision. */
  readonly classification: DataClassification;
  /** Timestamp of the decision (ISO 8601). */
  readonly decidedAt: string;
}

export const FirewallDecisionSchema = z.object({
  allowed: z.boolean(),
  reason: z.string(),
  appliedRuleName: z.string().nullable(),
  blockedDataTypes: z.array(z.string()),
  classification: DataClassificationSchema,
  decidedAt: z.string(),
});

// ---------------------------------------------------------------------------
// Keyword rule (used by DataClassifier)
// ---------------------------------------------------------------------------

/**
 * A single keyword rule mapping a set of keywords to a domain and data type.
 */
export interface KeywordRule {
  /** Unique identifier for this rule. */
  readonly id: string;
  /** The domain this keyword set belongs to. */
  readonly domain: string;
  /** The data type category (e.g. "medical", "banking"). */
  readonly dataType: string;
  /** Keywords to match (case-insensitive, whole-word preferred). */
  readonly keywords: ReadonlyArray<string>;
}

export const KeywordRuleSchema = z.object({
  id: z.string().min(1),
  domain: z.string().min(1),
  dataType: z.string().min(1),
  keywords: z.array(z.string().min(1)).min(1),
});

// ---------------------------------------------------------------------------
// Inspection result
// ---------------------------------------------------------------------------

/**
 * The result of a `DataInspector.inspect` call.
 * Provides detailed violation information for operator logging.
 */
export interface InspectionResult {
  /** Whether the data passed inspection (no violations found). */
  readonly passed: boolean;
  /** List of violations found during inspection. */
  readonly violations: ReadonlyArray<InspectionViolation>;
  /** The boundary rule used for inspection. */
  readonly ruleName: string;
}

/**
 * A single inspection violation.
 */
export interface InspectionViolation {
  /** The data type that caused the violation. */
  readonly dataType: string;
  /** Whether the violation came from the blocked list or missing allowed list. */
  readonly reason: "explicitly-blocked" | "not-in-allowlist";
  /** The matching keywords that surfaced this data type. */
  readonly matchedKeywords: ReadonlyArray<string>;
}

export const InspectionViolationSchema = z.object({
  dataType: z.string(),
  reason: z.enum(["explicitly-blocked", "not-in-allowlist"]),
  matchedKeywords: z.array(z.string()),
});

export const InspectionResultSchema = z.object({
  passed: z.boolean(),
  violations: z.array(InspectionViolationSchema),
  ruleName: z.string(),
});
