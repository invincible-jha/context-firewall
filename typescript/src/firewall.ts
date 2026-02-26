// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @module firewall
 * ContextFirewall — the main orchestrator for context-firewall.
 *
 * Brings together domain registry, boundary rules, keyword classification,
 * and pre-crossing inspection into a single, coherent API surface.
 */

import {
  BoundaryRegistry,
  BoundaryRule,
  DEFAULT_BOUNDARY_RULES,
  buildBoundaryKey,
  buildBoundaryRegistry,
} from "./boundary.js";
import { DataClassifier, DataClassifierOptions } from "./classifier.js";
import {
  DEFAULT_DOMAINS,
  Domain,
  DomainRegistry,
  buildDomainRegistry,
  mergeDomainRegistries,
} from "./domain.js";
import { DataInspector } from "./inspector.js";
import { DataPayload, FirewallDecision } from "./types.js";

// ---------------------------------------------------------------------------
// ContextFirewall options
// ---------------------------------------------------------------------------

/**
 * Options for constructing a `ContextFirewall` instance.
 */
export interface ContextFirewallOptions {
  /**
   * When `true`, the four built-in domains (work, personal, health, financial)
   * are NOT registered. You must add all domains manually via `addDomain`.
   * @default false
   */
  readonly skipDefaultDomains?: boolean;
  /**
   * When `true`, the built-in boundary rules are NOT registered.
   * You must add all rules manually via `addBoundary`.
   * @default false
   */
  readonly skipDefaultBoundaries?: boolean;
  /**
   * Options forwarded to the `DataClassifier` constructor.
   */
  readonly classifierOptions?: DataClassifierOptions;
}

// ---------------------------------------------------------------------------
// ContextFirewall class
// ---------------------------------------------------------------------------

/**
 * The main context-firewall class.
 *
 * Orchestrates domain isolation by:
 * 1. Classifying incoming data with a keyword-based `DataClassifier`.
 * 2. Looking up the applicable `BoundaryRule` for the requested crossing.
 * 3. Delegating detailed inspection to `DataInspector`.
 * 4. Returning a structured `FirewallDecision`.
 *
 * @example
 * ```typescript
 * import { ContextFirewall } from "@aumos/context-firewall";
 *
 * const firewall = new ContextFirewall();
 *
 * const decision = firewall.check(
 *   { text: "Patient blood pressure 120/80" },
 *   "health",
 *   "work"
 * );
 *
 * console.log(decision.allowed);          // false
 * console.log(decision.blockedDataTypes); // ["medical", "diagnosis"]
 * ```
 */
export class ContextFirewall {
  private domainRegistry: Map<string, Domain>;
  private boundaryRules: Map<string, BoundaryRule>;
  private readonly classifier: DataClassifier;
  private readonly inspector: DataInspector;

  constructor(options: ContextFirewallOptions = {}) {
    const {
      skipDefaultDomains = false,
      skipDefaultBoundaries = false,
      classifierOptions = {},
    } = options;

    // Build domain registry
    const initialDomains = skipDefaultDomains ? [] : DEFAULT_DOMAINS;
    const builtRegistry = buildDomainRegistry(initialDomains);
    this.domainRegistry = new Map(builtRegistry);

    // Build boundary registry
    const initialRules = skipDefaultBoundaries ? [] : DEFAULT_BOUNDARY_RULES;
    const builtBoundaries = buildBoundaryRegistry(initialRules);
    this.boundaryRules = new Map(builtBoundaries);

    this.classifier = new DataClassifier(classifierOptions);
    this.inspector = new DataInspector();
  }

  // ---------------------------------------------------------------------------
  // Core API
  // ---------------------------------------------------------------------------

  /**
   * Check whether `data` is permitted to cross from `fromDomain` to `toDomain`.
   *
   * Steps:
   * 1. Validate both domain names are registered.
   * 2. Classify the data with the keyword-based classifier.
   * 3. Look up the boundary rule for this domain pair.
   * 4. If no rule exists, allow the crossing (open boundary).
   * 5. Inspect the classification against the rule.
   * 6. Return a `FirewallDecision` with full audit detail.
   *
   * @param data - The data payload to evaluate
   * @param fromDomain - The name of the originating domain
   * @param toDomain - The name of the destination domain
   * @returns A `FirewallDecision` describing the outcome
   * @throws {Error} If `fromDomain` or `toDomain` is not registered
   */
  check(
    data: DataPayload,
    fromDomain: string,
    toDomain: string
  ): FirewallDecision {
    this.assertDomainRegistered(fromDomain);
    this.assertDomainRegistered(toDomain);

    // Same-domain crossings are always allowed
    if (fromDomain === toDomain) {
      const classification = this.classifier.classify(data);
      return this.buildDecision({
        allowed: true,
        reason: `Same-domain transfer within '${fromDomain}' is always permitted.`,
        appliedRuleName: null,
        blockedDataTypes: [],
        classification,
      });
    }

    const classification = this.classifier.classify(data);
    const boundaryKey = buildBoundaryKey(fromDomain, toDomain);
    const rule = this.boundaryRules.get(boundaryKey);

    // No rule registered for this crossing — open boundary
    if (rule === undefined) {
      return this.buildDecision({
        allowed: true,
        reason: `No boundary rule is configured for '${fromDomain}' -> '${toDomain}'. Crossing is permitted by default.`,
        appliedRuleName: null,
        blockedDataTypes: [],
        classification,
      });
    }

    // Inspect the classification against the rule
    const inspectionResult = this.inspector.inspect(classification, rule);
    const blockedDataTypes = this.inspector.extractBlockedTypes(inspectionResult);

    if (inspectionResult.passed) {
      return this.buildDecision({
        allowed: true,
        reason: `Boundary rule '${rule.name}' permits this crossing. No blocked data types detected.`,
        appliedRuleName: rule.name,
        blockedDataTypes: [],
        classification,
      });
    }

    const violationSummary = inspectionResult.violations
      .map((v) => `'${v.dataType}' (${v.reason})`)
      .join(", ");

    return this.buildDecision({
      allowed: false,
      reason: `Boundary rule '${rule.name}' blocks this crossing. Violations: ${violationSummary}.`,
      appliedRuleName: rule.name,
      blockedDataTypes: Array.from(blockedDataTypes),
      classification,
    });
  }

  /**
   * Classify `data` using the keyword-based classifier and return the
   * most likely domain name.
   *
   * This is a convenience wrapper around `DataClassifier.classify`.
   * The result does NOT modify firewall state or trigger any rule evaluation.
   *
   * @param data - The data payload to classify
   * @returns The name of the most likely domain (or the fallback domain)
   */
  classify(data: DataPayload): string {
    return this.classifier.classify(data).domain;
  }

  // ---------------------------------------------------------------------------
  // Domain management
  // ---------------------------------------------------------------------------

  /**
   * Register a new domain with the firewall.
   * Domains must have unique names.
   *
   * @param domain - The domain to register
   * @throws {Error} If a domain with the same name is already registered
   */
  addDomain(domain: Domain): void {
    const newRegistry = buildDomainRegistry([domain]);
    const merged = mergeDomainRegistries(
      this.domainRegistry as DomainRegistry,
      newRegistry
    );
    this.domainRegistry = new Map(merged);
  }

  /**
   * Retrieve a registered domain by name.
   *
   * @param name - Domain name to look up
   * @returns The domain, or `undefined` if not registered
   */
  getDomain(name: string): Domain | undefined {
    return this.domainRegistry.get(name);
  }

  /**
   * List all registered domain names.
   */
  listDomains(): ReadonlyArray<string> {
    return Array.from(this.domainRegistry.keys());
  }

  // ---------------------------------------------------------------------------
  // Boundary management
  // ---------------------------------------------------------------------------

  /**
   * Register a new boundary rule.
   * For `bidirectional` rules, entries are created in both directions.
   *
   * @param rule - The boundary rule to register
   * @throws {Error} If a rule for the same directional pair already exists
   */
  addBoundary(rule: BoundaryRule): void {
    const newRegistry = buildBoundaryRegistry([rule]);
    for (const [key, boundaryRule] of newRegistry) {
      if (this.boundaryRules.has(key)) {
        throw new Error(
          `A boundary rule for '${key}' is already registered. ` +
            `Existing rule: '${this.boundaryRules.get(key)!.name}'.`
        );
      }
      this.boundaryRules.set(key, boundaryRule);
    }
  }

  /**
   * Retrieve the boundary rule for a given domain pair, if any.
   *
   * @param fromDomain - Originating domain
   * @param toDomain - Destination domain
   * @returns The boundary rule, or `undefined` if no rule is configured
   */
  getBoundary(fromDomain: string, toDomain: string): BoundaryRule | undefined {
    return this.boundaryRules.get(buildBoundaryKey(fromDomain, toDomain));
  }

  /**
   * List all registered boundary rule names.
   */
  listBoundaries(): ReadonlyArray<string> {
    const seen = new Set<string>();
    const names: string[] = [];
    for (const rule of this.boundaryRules.values()) {
      if (!seen.has(rule.name)) {
        seen.add(rule.name);
        names.push(rule.name);
      }
    }
    return names;
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private assertDomainRegistered(name: string): void {
    if (!this.domainRegistry.has(name)) {
      throw new Error(
        `Domain '${name}' is not registered. ` +
          `Call addDomain() first or use one of the built-in domains: ` +
          `${Array.from(this.domainRegistry.keys()).join(", ")}.`
      );
    }
  }

  private buildDecision(params: {
    allowed: boolean;
    reason: string;
    appliedRuleName: string | null;
    blockedDataTypes: ReadonlyArray<string>;
    classification: ReturnType<DataClassifier["classify"]>;
  }): FirewallDecision {
    return {
      allowed: params.allowed,
      reason: params.reason,
      appliedRuleName: params.appliedRuleName,
      blockedDataTypes: params.blockedDataTypes,
      classification: params.classification,
      decidedAt: new Date().toISOString(),
    };
  }
}
