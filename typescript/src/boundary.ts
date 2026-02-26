// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @module boundary
 * BoundaryRule definitions for context-firewall.
 *
 * A BoundaryRule specifies which data types may or may not cross between
 * two domains. Rules are evaluated by DataInspector before any crossing
 * is permitted.
 */

import { z } from "zod";
import {
  BoundaryDirection,
  BoundaryDirectionSchema,
  DataClassification,
} from "./types.js";

// ---------------------------------------------------------------------------
// BoundaryRule interface
// ---------------------------------------------------------------------------

/**
 * Defines the crossing rules between two domains.
 *
 * @example
 * ```typescript
 * const healthToWork: BoundaryRule = {
 *   name: "health->work",
 *   fromDomain: "health",
 *   toDomain: "work",
 *   direction: "one-way",
 *   allowedDataTypes: [],
 *   blockedDataTypes: ["medical", "prescription", "diagnosis", "mental-health"],
 *   evaluate(classification) {
 *     return classification.detectedTypes.every(
 *       (t) => !this.blockedDataTypes.includes(t)
 *     );
 *   },
 * };
 * ```
 */
export interface BoundaryRule {
  /** Unique identifier for this rule, used in `FirewallDecision.appliedRuleName`. */
  readonly name: string;
  /** The originating domain. */
  readonly fromDomain: string;
  /** The destination domain. */
  readonly toDomain: string;
  /**
   * Direction of the rule.
   * - `one-way`: enforced only from `fromDomain` to `toDomain`.
   * - `bidirectional`: enforced in both directions.
   */
  readonly direction: BoundaryDirection;
  /**
   * Data types explicitly allowed to cross.
   * An empty array means "no explicit allowlist — use blockedDataTypes only".
   */
  readonly allowedDataTypes: ReadonlyArray<string>;
  /**
   * Data types that are never permitted to cross, regardless of other rules.
   */
  readonly blockedDataTypes: ReadonlyArray<string>;
  /**
   * Evaluate whether a given classification is permitted to cross.
   *
   * @param classification - The classification of the data being inspected
   * @returns `true` if crossing is allowed, `false` if it must be blocked
   */
  evaluate(classification: DataClassification): boolean;
}

// ---------------------------------------------------------------------------
// Zod schema for the serialisable portion of a BoundaryRule
// ---------------------------------------------------------------------------

export const BoundaryRuleConfigSchema = z.object({
  name: z.string().min(1),
  fromDomain: z.string().min(1),
  toDomain: z.string().min(1),
  direction: BoundaryDirectionSchema,
  allowedDataTypes: z.array(z.string()),
  blockedDataTypes: z.array(z.string()),
});

export type BoundaryRuleConfig = z.infer<typeof BoundaryRuleConfigSchema>;

// ---------------------------------------------------------------------------
// Factory: create a standard BoundaryRule from config
// ---------------------------------------------------------------------------

/**
 * Build a `BoundaryRule` from a plain config object.
 * The `evaluate` method enforces the following logic:
 *
 * 1. If `blockedDataTypes` is non-empty, any detected type in that list blocks the crossing.
 * 2. If `allowedDataTypes` is non-empty, only types in that list are permitted; any
 *    detected type not on the allowlist blocks the crossing.
 * 3. If both lists are empty, the crossing is allowed (open rule).
 *
 * @param config - Serialisable rule configuration
 * @returns A fully formed `BoundaryRule`
 */
export function createBoundaryRule(config: BoundaryRuleConfig): BoundaryRule {
  const validated = BoundaryRuleConfigSchema.parse(config);

  return {
    name: validated.name,
    fromDomain: validated.fromDomain,
    toDomain: validated.toDomain,
    direction: validated.direction,
    allowedDataTypes: validated.allowedDataTypes,
    blockedDataTypes: validated.blockedDataTypes,

    evaluate(classification: DataClassification): boolean {
      for (const detectedType of classification.detectedTypes) {
        // Blocked list takes priority
        if (this.blockedDataTypes.includes(detectedType)) {
          return false;
        }
        // Allowlist enforcement: if an allowlist exists, type must be on it
        if (
          this.allowedDataTypes.length > 0 &&
          !this.allowedDataTypes.includes(detectedType)
        ) {
          return false;
        }
      }
      return true;
    },
  };
}

// ---------------------------------------------------------------------------
// Default built-in boundary rules
// ---------------------------------------------------------------------------

/**
 * health -> work: no medical data crosses into professional context.
 */
export const HEALTH_TO_WORK_RULE: BoundaryRule = createBoundaryRule({
  name: "health->work",
  fromDomain: "health",
  toDomain: "work",
  direction: "one-way",
  allowedDataTypes: [],
  blockedDataTypes: [
    "medical",
    "prescription",
    "diagnosis",
    "mental-health",
    "clinical",
    "laboratory",
  ],
});

/**
 * financial -> work: no financial account or tax data crosses into work context.
 */
export const FINANCIAL_TO_WORK_RULE: BoundaryRule = createBoundaryRule({
  name: "financial->work",
  fromDomain: "financial",
  toDomain: "work",
  direction: "one-way",
  allowedDataTypes: [],
  blockedDataTypes: [
    "banking",
    "credit-card",
    "tax",
    "investment",
    "insurance-financial",
    "salary",
  ],
});

/**
 * health -> personal: medical data may not cross into personal domain by default.
 * Rationale: keeps HIPAA-regulated data isolated even within the user's own contexts.
 */
export const HEALTH_TO_PERSONAL_RULE: BoundaryRule = createBoundaryRule({
  name: "health->personal",
  fromDomain: "health",
  toDomain: "personal",
  direction: "one-way",
  allowedDataTypes: [],
  blockedDataTypes: [
    "medical",
    "prescription",
    "diagnosis",
    "mental-health",
    "clinical",
    "laboratory",
  ],
});

/**
 * financial -> personal: core financial account data may not flow into personal context.
 */
export const FINANCIAL_TO_PERSONAL_RULE: BoundaryRule = createBoundaryRule({
  name: "financial->personal",
  fromDomain: "financial",
  toDomain: "personal",
  direction: "one-way",
  allowedDataTypes: [],
  blockedDataTypes: [
    "banking",
    "credit-card",
    "tax",
    "investment",
    "salary",
  ],
});

/**
 * personal -> work: personal and family data must not enter the work domain.
 */
export const PERSONAL_TO_WORK_RULE: BoundaryRule = createBoundaryRule({
  name: "personal->work",
  fromDomain: "personal",
  toDomain: "work",
  direction: "one-way",
  allowedDataTypes: [],
  blockedDataTypes: [
    "family",
    "relationship",
    "home-address",
    "personal-contact",
  ],
});

/**
 * The complete set of default built-in boundary rules.
 * Registered automatically by `ContextFirewall` unless `skipDefaultBoundaries: true`.
 */
export const DEFAULT_BOUNDARY_RULES: ReadonlyArray<BoundaryRule> = [
  HEALTH_TO_WORK_RULE,
  FINANCIAL_TO_WORK_RULE,
  HEALTH_TO_PERSONAL_RULE,
  FINANCIAL_TO_PERSONAL_RULE,
  PERSONAL_TO_WORK_RULE,
];

// ---------------------------------------------------------------------------
// Boundary registry
// ---------------------------------------------------------------------------

/**
 * A map of boundary rules keyed by `"fromDomain->toDomain"` lookup strings.
 * Both `one-way` and `bidirectional` rules are indexed in both directions
 * when applicable.
 */
export type BoundaryRegistry = ReadonlyMap<string, BoundaryRule>;

/**
 * Build a registry lookup key for a from/to domain pair.
 */
export function buildBoundaryKey(fromDomain: string, toDomain: string): string {
  return `${fromDomain}->${toDomain}`;
}

/**
 * Build a `BoundaryRegistry` from an array of `BoundaryRule` objects.
 * For `bidirectional` rules, entries are created in both directions.
 *
 * @param rules - Boundary rules to index
 * @returns Immutable Map keyed by `"from->to"` strings
 * @throws {Error} If two rules share the same directional key
 */
export function buildBoundaryRegistry(
  rules: ReadonlyArray<BoundaryRule>
): BoundaryRegistry {
  const registry = new Map<string, BoundaryRule>();

  for (const rule of rules) {
    const forwardKey = buildBoundaryKey(rule.fromDomain, rule.toDomain);

    if (registry.has(forwardKey)) {
      throw new Error(
        `Boundary rule conflict: a rule for '${forwardKey}' is already registered. ` +
          `Rule names: existing='${registry.get(forwardKey)!.name}', new='${rule.name}'.`
      );
    }
    registry.set(forwardKey, rule);

    if (rule.direction === "bidirectional") {
      const reverseKey = buildBoundaryKey(rule.toDomain, rule.fromDomain);
      if (registry.has(reverseKey)) {
        throw new Error(
          `Boundary rule conflict: bidirectional rule '${rule.name}' would overwrite ` +
            `existing rule for '${reverseKey}'.`
        );
      }
      registry.set(reverseKey, rule);
    }
  }

  return registry;
}
