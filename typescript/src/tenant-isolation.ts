// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @module tenant-isolation
 * Tenant-aware domain isolation for multi-tenant agent deployments.
 *
 * Provides static, policy-driven access control between tenants. Cross-tenant
 * access is DENIED by default. All access decisions are recorded in an audit
 * log for compliance visibility.
 *
 * FIRE LINE: Domain boundaries are static policy only. No adaptive behaviour,
 * no cross-domain inference, no ML-based classification.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Classification levels
// ---------------------------------------------------------------------------

/** Static classification levels for tenant data. */
export type DataClassificationLevel =
  | "public"
  | "internal"
  | "confidential"
  | "restricted";

export const DataClassificationLevelSchema = z.enum([
  "public",
  "internal",
  "confidential",
  "restricted",
]);

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/** Operator-provided configuration for a tenant. */
export interface TenantConfig {
  readonly tenantId: string;
  readonly displayName: string;
  readonly allowedDomains: ReadonlyArray<string>;
  readonly dataClassification: DataClassificationLevel;
  readonly allowedCrossTenantTargets: ReadonlyArray<string>;
}

export const TenantConfigSchema = z.object({
  tenantId: z.string().min(1),
  displayName: z.string().min(1),
  allowedDomains: z.array(z.string()),
  dataClassification: DataClassificationLevelSchema,
  allowedCrossTenantTargets: z.array(z.string()),
});

/** Runtime context describing the currently active tenant. */
export interface TenantContext {
  readonly tenantId: string;
  readonly allowedDomains: ReadonlyArray<string>;
  readonly dataClassification: DataClassificationLevel;
}

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/** Result of a tenant domain access check. */
export interface AccessDecision {
  readonly allowed: boolean;
  readonly tenantId: string;
  readonly targetDomain: string;
  readonly action: string;
  readonly reason: string;
  readonly decidedAt: string;
}

/** Result of a cross-tenant access validation. */
export interface CrossTenantResult {
  readonly allowed: boolean;
  readonly sourceTenant: string;
  readonly targetTenant: string;
  readonly reason: string;
  readonly decidedAt: string;
}

/** Immutable record of an access decision for audit logging. */
export interface AuditEntry {
  readonly timestamp: string;
  readonly decisionType: "domain_access" | "cross_tenant";
  readonly tenantId: string;
  readonly target: string;
  readonly action: string;
  readonly allowed: boolean;
  readonly reason: string;
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/**
 * Manages tenant registration and enforces static isolation policies.
 *
 * Cross-tenant access is DENIED by default. A tenant may only access
 * domains listed in its configuration. All decisions are logged to an
 * internal audit trail accessible via `getAuditLog`.
 *
 * @example
 * ```typescript
 * const manager = new TenantIsolationManager();
 * manager.registerTenant("acme", {
 *   tenantId: "acme",
 *   displayName: "Acme Corp",
 *   allowedDomains: ["work", "financial"],
 *   dataClassification: "confidential",
 *   allowedCrossTenantTargets: [],
 * });
 *
 * const decision = manager.checkAccess("acme", "work", "read");
 * console.log(decision.allowed); // true
 * ```
 */
export class TenantIsolationManager {
  private readonly tenants: Map<string, TenantConfig> = new Map();
  private readonly auditLog: AuditEntry[] = [];

  // ----------------------------------------------------------------
  // Registration
  // ----------------------------------------------------------------

  /**
   * Register a tenant with the isolation manager.
   *
   * @param tenantId - Unique tenant identifier (must match `config.tenantId`)
   * @param config - Static configuration for the tenant
   * @throws {Error} If the tenant is already registered or IDs mismatch
   */
  registerTenant(tenantId: string, config: TenantConfig): void {
    const validated = TenantConfigSchema.parse(config);
    if (tenantId !== validated.tenantId) {
      throw new Error(
        `Tenant ID mismatch: argument is '${tenantId}' but ` +
          `config.tenantId is '${validated.tenantId}'.`
      );
    }
    if (this.tenants.has(tenantId)) {
      throw new Error(
        `Tenant '${tenantId}' is already registered. ` +
          `Unregister it first or use a different ID.`
      );
    }
    this.tenants.set(tenantId, validated);
  }

  /**
   * Remove a tenant from the manager.
   *
   * @param tenantId - The tenant to remove
   * @returns True if the tenant was found and removed, false otherwise
   */
  unregisterTenant(tenantId: string): boolean {
    return this.tenants.delete(tenantId);
  }

  /**
   * Return the config for a tenant, or undefined if not registered.
   */
  getTenant(tenantId: string): TenantConfig | undefined {
    return this.tenants.get(tenantId);
  }

  /**
   * List all registered tenant IDs.
   */
  listTenants(): ReadonlyArray<string> {
    return Array.from(this.tenants.keys());
  }

  // ----------------------------------------------------------------
  // Access checks
  // ----------------------------------------------------------------

  /**
   * Check whether a tenant is allowed to perform an action on a target domain.
   *
   * The check is purely based on the tenant's static configuration:
   * the domain must be listed in `allowedDomains`.
   *
   * @param tenantId - The tenant requesting access
   * @param targetDomain - The domain being accessed
   * @param action - A label for the action (e.g. "read", "write")
   * @returns An `AccessDecision` describing the outcome
   */
  checkAccess(
    tenantId: string,
    targetDomain: string,
    action: string
  ): AccessDecision {
    const now = new Date().toISOString();
    const config = this.tenants.get(tenantId);

    if (config === undefined) {
      const decision: AccessDecision = {
        allowed: false,
        tenantId,
        targetDomain,
        action,
        reason: `Tenant '${tenantId}' is not registered.`,
        decidedAt: now,
      };
      this.recordAudit(
        "domain_access",
        tenantId,
        targetDomain,
        action,
        false,
        decision.reason
      );
      return decision;
    }

    const allowed = config.allowedDomains.includes(targetDomain);
    const reason = allowed
      ? `Tenant '${tenantId}' is allowed access to domain '${targetDomain}' per static configuration.`
      : `Tenant '${tenantId}' is not allowed access to domain '${targetDomain}'. ` +
        `Allowed domains: [${config.allowedDomains.join(", ")}].`;

    const decision: AccessDecision = {
      allowed,
      tenantId,
      targetDomain,
      action,
      reason,
      decidedAt: now,
    };

    this.recordAudit(
      "domain_access",
      tenantId,
      targetDomain,
      action,
      allowed,
      reason
    );
    return decision;
  }

  /**
   * Validate whether cross-tenant access from `source` to `target` is allowed.
   *
   * Cross-tenant access is DENIED by default. It is only permitted when
   * the source tenant's `allowedCrossTenantTargets` list explicitly
   * includes the target tenant ID.
   *
   * @param source - The initiating tenant ID
   * @param target - The target tenant ID
   * @returns A `CrossTenantResult` describing the outcome
   */
  validateCrossTenant(source: string, target: string): CrossTenantResult {
    const now = new Date().toISOString();

    if (source === target) {
      const result: CrossTenantResult = {
        allowed: true,
        sourceTenant: source,
        targetTenant: target,
        reason: "Same-tenant access is always permitted.",
        decidedAt: now,
      };
      this.recordAudit(
        "cross_tenant",
        source,
        target,
        "cross_tenant_access",
        true,
        result.reason
      );
      return result;
    }

    const sourceConfig = this.tenants.get(source);
    if (sourceConfig === undefined) {
      const result: CrossTenantResult = {
        allowed: false,
        sourceTenant: source,
        targetTenant: target,
        reason: `Source tenant '${source}' is not registered.`,
        decidedAt: now,
      };
      this.recordAudit(
        "cross_tenant",
        source,
        target,
        "cross_tenant_access",
        false,
        result.reason
      );
      return result;
    }

    if (!this.tenants.has(target)) {
      const result: CrossTenantResult = {
        allowed: false,
        sourceTenant: source,
        targetTenant: target,
        reason: `Target tenant '${target}' is not registered.`,
        decidedAt: now,
      };
      this.recordAudit(
        "cross_tenant",
        source,
        target,
        "cross_tenant_access",
        false,
        result.reason
      );
      return result;
    }

    const allowed = sourceConfig.allowedCrossTenantTargets.includes(target);
    const reason = allowed
      ? `Tenant '${source}' has explicit cross-tenant access to '${target}' in its static configuration.`
      : `Cross-tenant access from '${source}' to '${target}' is denied. ` +
        `Not listed in allowedCrossTenantTargets.`;

    const result: CrossTenantResult = {
      allowed,
      sourceTenant: source,
      targetTenant: target,
      reason,
      decidedAt: now,
    };

    this.recordAudit(
      "cross_tenant",
      source,
      target,
      "cross_tenant_access",
      allowed,
      reason
    );
    return result;
  }

  // ----------------------------------------------------------------
  // Audit log
  // ----------------------------------------------------------------

  /** Return a copy of the full audit log. */
  getAuditLog(): ReadonlyArray<AuditEntry> {
    return [...this.auditLog];
  }

  /** Return audit entries for a specific tenant. */
  getTenantAuditLog(tenantId: string): ReadonlyArray<AuditEntry> {
    return this.auditLog.filter((entry) => entry.tenantId === tenantId);
  }

  private recordAudit(
    decisionType: "domain_access" | "cross_tenant",
    tenantId: string,
    target: string,
    action: string,
    allowed: boolean,
    reason: string
  ): void {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      decisionType,
      tenantId,
      target,
      action,
      allowed,
      reason,
    };
    this.auditLog.push(entry);
  }
}
