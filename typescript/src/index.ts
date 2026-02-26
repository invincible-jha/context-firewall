// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @module @aumos/context-firewall
 * Domain isolation for AI agents.
 *
 * Prevents data leaking between work, personal, health, and financial contexts
 * using purely keyword-based, deterministic classification.
 *
 * FIRE LINE: No ML, no LLM, no auto-discovery. See FIRE_LINE.md.
 *
 * @example
 * ```typescript
 * import { ContextFirewall } from "@aumos/context-firewall";
 *
 * const firewall = new ContextFirewall();
 * const decision = firewall.check(
 *   { text: "My insulin dosage is 10 units" },
 *   "health",
 *   "work"
 * );
 * // decision.allowed === false
 * ```
 */

// Main class
export { ContextFirewall } from "./firewall.js";
export type { ContextFirewallOptions } from "./firewall.js";

// Domain definitions
export {
  DEFAULT_DOMAINS,
  FINANCIAL_DOMAIN,
  HEALTH_DOMAIN,
  PERSONAL_DOMAIN,
  WORK_DOMAIN,
  buildDomainRegistry,
  mergeDomainRegistries,
} from "./domain.js";
export type { Domain, DomainRegistry } from "./domain.js";

// Boundary rules
export {
  DEFAULT_BOUNDARY_RULES,
  FINANCIAL_TO_PERSONAL_RULE,
  FINANCIAL_TO_WORK_RULE,
  HEALTH_TO_PERSONAL_RULE,
  HEALTH_TO_WORK_RULE,
  PERSONAL_TO_WORK_RULE,
  buildBoundaryKey,
  buildBoundaryRegistry,
  createBoundaryRule,
} from "./boundary.js";
export type {
  BoundaryRegistry,
  BoundaryRule,
  BoundaryRuleConfig,
} from "./boundary.js";

// Classifier
export { DataClassifier } from "./classifier.js";
export type { DataClassifierOptions } from "./classifier.js";

// Inspector
export { DataInspector } from "./inspector.js";

// Types
export type {
  BoundaryDirection,
  DataClassification,
  DataPayload,
  FirewallDecision,
  InspectionResult,
  InspectionViolation,
  KeywordRule,
  SensitivityLevel,
} from "./types.js";

// Zod schemas (for consumers who want runtime validation)
export {
  BoundaryDirectionSchema,
  DataClassificationSchema,
  DataPayloadSchema,
  FirewallDecisionSchema,
  InspectionResultSchema,
  InspectionViolationSchema,
  KeywordRuleSchema,
  SensitivityLevelSchema,
} from "./types.js";
export { BoundaryRuleConfigSchema, DomainSchema } from "./boundary.js";
