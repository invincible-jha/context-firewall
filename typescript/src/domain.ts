// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @module domain
 * Domain definitions for context-firewall.
 *
 * A Domain describes an isolation boundary within an agent's operating context.
 * Domains are static — configured by the operator, never auto-discovered.
 * Classification must not infer domain membership from data content using ML or LLM.
 */

import { z } from "zod";
import { SensitivityLevel, SensitivityLevelSchema } from "./types.js";

// ---------------------------------------------------------------------------
// Domain interface
// ---------------------------------------------------------------------------

/**
 * Describes an isolation domain that the firewall enforces.
 *
 * @example
 * ```typescript
 * const medicalDomain: Domain = {
 *   name: "health",
 *   description: "Medical, mental health, and prescription data",
 *   sensitivity: "critical",
 *   metadata: { owner: "patient" },
 * };
 * ```
 */
export interface Domain {
  /** Unique identifier for this domain. Used in boundary rule references. */
  readonly name: string;
  /** Human-readable description of the domain's scope. */
  readonly description: string;
  /** Sensitivity level — drives default blocking behaviour. */
  readonly sensitivity: SensitivityLevel;
  /** Optional operator-defined metadata (e.g. regulatory tags). */
  readonly metadata?: Readonly<Record<string, string>>;
}

export const DomainSchema = z.object({
  name: z.string().min(1).regex(/^[a-z][a-z0-9_-]*$/, {
    message:
      "Domain name must be lowercase alphanumeric with hyphens or underscores",
  }),
  description: z.string().min(1),
  sensitivity: SensitivityLevelSchema,
  metadata: z.record(z.string(), z.string()).optional(),
});

// ---------------------------------------------------------------------------
// Default built-in domains
// ---------------------------------------------------------------------------

/**
 * Built-in domain: professional work context.
 * Includes emails, calendars, project data, and business communications.
 * Sensitivity is medium — structured data may cross into personal with explicit rules.
 */
export const WORK_DOMAIN: Domain = {
  name: "work",
  description:
    "Professional communications, tasks, projects, and business data",
  sensitivity: "medium",
  metadata: {
    category: "professional",
    regulatoryScope: "none",
  },
};

/**
 * Built-in domain: personal life context.
 * Includes family, home, relationships, hobbies, and non-medical personal data.
 * Sensitivity is high — significant PII may be present.
 */
export const PERSONAL_DOMAIN: Domain = {
  name: "personal",
  description:
    "Personal relationships, home, lifestyle, and non-medical private data",
  sensitivity: "high",
  metadata: {
    category: "personal",
    regulatoryScope: "gdpr-personal",
  },
};

/**
 * Built-in domain: health and medical context.
 * Includes medical records, prescriptions, diagnoses, mental health data.
 * Sensitivity is critical — subject to HIPAA, GDPR special categories.
 */
export const HEALTH_DOMAIN: Domain = {
  name: "health",
  description:
    "Medical records, prescriptions, diagnoses, and mental health data",
  sensitivity: "critical",
  metadata: {
    category: "health",
    regulatoryScope: "hipaa,gdpr-special",
  },
};

/**
 * Built-in domain: financial context.
 * Includes banking, taxes, investments, credit, and insurance financials.
 * Sensitivity is critical — subject to PCI-DSS, GLBA, GDPR financial categories.
 */
export const FINANCIAL_DOMAIN: Domain = {
  name: "financial",
  description:
    "Banking, taxes, investments, credit, insurance, and financial planning",
  sensitivity: "critical",
  metadata: {
    category: "financial",
    regulatoryScope: "pci-dss,glba,gdpr-financial",
  },
};

/**
 * The complete set of default built-in domains.
 * These are registered automatically by `ContextFirewall` unless
 * `skipDefaultDomains: true` is passed to the constructor.
 */
export const DEFAULT_DOMAINS: ReadonlyArray<Domain> = [
  WORK_DOMAIN,
  PERSONAL_DOMAIN,
  HEALTH_DOMAIN,
  FINANCIAL_DOMAIN,
];

// ---------------------------------------------------------------------------
// Domain registry helpers
// ---------------------------------------------------------------------------

/**
 * A read-only view of a registered domain map, keyed by domain name.
 */
export type DomainRegistry = ReadonlyMap<string, Domain>;

/**
 * Build a `DomainRegistry` from an array of `Domain` objects.
 * Duplicate names cause an error at registration time.
 *
 * @param domains - Domains to register
 * @returns A new immutable Map keyed by domain name
 * @throws {Error} If a duplicate domain name is provided
 */
export function buildDomainRegistry(
  domains: ReadonlyArray<Domain>
): DomainRegistry {
  const registry = new Map<string, Domain>();
  for (const domain of domains) {
    const validated = DomainSchema.parse(domain);
    if (registry.has(validated.name)) {
      throw new Error(
        `Domain '${validated.name}' is already registered. Domain names must be unique.`
      );
    }
    registry.set(validated.name, validated);
  }
  return registry;
}

/**
 * Merge two domain registries, with `overrides` taking precedence.
 * Returns a new registry — never mutates inputs.
 */
export function mergeDomainRegistries(
  base: DomainRegistry,
  overrides: DomainRegistry
): DomainRegistry {
  const merged = new Map<string, Domain>(base);
  for (const [name, domain] of overrides) {
    merged.set(name, domain);
  }
  return merged;
}
