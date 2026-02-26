// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @module inspector
 * DataInspector — validates data against boundary rules before crossing.
 *
 * The inspector takes a `DataClassification` and a `BoundaryRule` and produces
 * a detailed `InspectionResult` listing any violations.
 * It is called internally by `ContextFirewall.check` and can also be called
 * directly for diagnostic purposes.
 */

import { BoundaryRule } from "./boundary.js";
import {
  DataClassification,
  InspectionResult,
  InspectionViolation,
} from "./types.js";

// ---------------------------------------------------------------------------
// DataInspector class
// ---------------------------------------------------------------------------

/**
 * Validates a `DataClassification` result against a `BoundaryRule`.
 *
 * The inspector evaluates each detected data type against:
 * 1. The blocked list — any match is a violation.
 * 2. The allowed list — if non-empty, a type not on the list is a violation.
 *
 * The inspector does not make the final allow/deny decision — that remains with
 * `ContextFirewall.check`. The inspector's role is to provide structured
 * violation detail for logging, auditing, and decision support.
 */
export class DataInspector {
  /**
   * Inspect a classification result against a boundary rule.
   *
   * @param classification - The result of `DataClassifier.classify`
   * @param rule - The boundary rule governing the crossing
   * @returns A structured `InspectionResult` with pass/fail status and violations
   */
  inspect(
    classification: DataClassification,
    rule: BoundaryRule
  ): InspectionResult {
    const violations: InspectionViolation[] = [];

    for (const detectedType of classification.detectedTypes) {
      const keywordsForType = this.keywordsForType(
        classification,
        detectedType
      );

      // 1. Blocked list check
      if (rule.blockedDataTypes.includes(detectedType)) {
        violations.push({
          dataType: detectedType,
          reason: "explicitly-blocked",
          matchedKeywords: keywordsForType,
        });
        continue; // No need to check allowlist if already blocked
      }

      // 2. Allowlist check (only applies when allowlist is non-empty)
      if (
        rule.allowedDataTypes.length > 0 &&
        !rule.allowedDataTypes.includes(detectedType)
      ) {
        violations.push({
          dataType: detectedType,
          reason: "not-in-allowlist",
          matchedKeywords: keywordsForType,
        });
      }
    }

    return {
      passed: violations.length === 0,
      violations,
      ruleName: rule.name,
    };
  }

  /**
   * Determine whether the crossing of a specific data type is permitted
   * under the given rule, without full inspection context.
   * Useful for quick pre-checks in hot paths.
   *
   * @param dataType - The data type to check
   * @param rule - The boundary rule to evaluate against
   * @returns `true` if the data type is permitted to cross
   */
  isDataTypePermitted(dataType: string, rule: BoundaryRule): boolean {
    if (rule.blockedDataTypes.includes(dataType)) {
      return false;
    }
    if (
      rule.allowedDataTypes.length > 0 &&
      !rule.allowedDataTypes.includes(dataType)
    ) {
      return false;
    }
    return true;
  }

  /**
   * Summarise the blocked data types found in an `InspectionResult`.
   * Convenience method for `ContextFirewall.check` to populate
   * `FirewallDecision.blockedDataTypes`.
   *
   * @param result - The inspection result to summarise
   * @returns Array of data type strings that were blocked
   */
  extractBlockedTypes(result: InspectionResult): ReadonlyArray<string> {
    return result.violations.map((v) => v.dataType);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Map a detected data type back to the keywords that triggered it.
   * Since the classifier aggregates all keywords into one list, this
   * heuristic returns all matched keywords — a more precise mapping would
   * require the classifier to expose per-type keyword hits.
   *
   * This is acceptable: keyword evidence is surfaced for auditability,
   * not as a security gate.
   */
  private keywordsForType(
    classification: DataClassification,
    _dataType: string
  ): ReadonlyArray<string> {
    // The classification holds all matched keywords across all detected types.
    // We return the full set for audit purposes (the _dataType parameter is
    // reserved for future per-type keyword tracking).
    return classification.matchedKeywords;
  }
}
