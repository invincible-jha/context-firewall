# Multi-Tenant Agent Isolation

## Overview

The tenant isolation module provides static, policy-driven access control
for multi-tenant AI agent deployments. It enforces two fundamental rules:

1. **Domain access** -- A tenant may only operate within domains explicitly
   listed in its configuration.
2. **Cross-tenant access** -- Access between tenants is DENIED by default
   and must be explicitly whitelisted.

All access decisions are recorded in an append-only audit log.

## Threat Model

### Risks Addressed

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Cross-tenant data leakage | Agent operating on behalf of Tenant A reads data belonging to Tenant B | Domain and cross-tenant access checks enforce static boundaries |
| Privilege escalation | Agent gains access to a domain not intended for its tenant | Allowed domains are statically configured; no runtime escalation path |
| Audit gap | Access decisions are not logged, making breach investigation impossible | Every check appends an immutable audit entry |
| Implicit trust | Tenants share resources without explicit authorization | Cross-tenant access is denied by default; explicit allowlisting required |

### Out of Scope

- Network-level isolation (handled by infrastructure)
- Authentication and identity verification (handled by the auth layer)
- Data encryption at rest or in transit

## Configuration Examples

### Python

```python
from context_firewall.tenant_isolation import (
    DataClassificationLevel,
    TenantConfig,
    TenantIsolationManager,
)

manager = TenantIsolationManager()

# Register tenants with static policies
acme_config = TenantConfig(
    tenant_id="acme",
    display_name="Acme Corp",
    allowed_domains=["work", "financial"],
    data_classification=DataClassificationLevel.CONFIDENTIAL,
    allowed_cross_tenant_targets=["globex"],  # Can share with Globex
)
manager.register_tenant("acme", acme_config)

globex_config = TenantConfig(
    tenant_id="globex",
    display_name="Globex Inc",
    allowed_domains=["work"],
    data_classification=DataClassificationLevel.RESTRICTED,
    allowed_cross_tenant_targets=[],  # No cross-tenant access
)
manager.register_tenant("globex", globex_config)

# Check domain access
decision = manager.check_access("acme", "work", "read")
assert decision.allowed  # True -- "work" is in Acme's allowed domains

decision = manager.check_access("acme", "health", "read")
assert not decision.allowed  # False -- "health" not in allowed domains

# Check cross-tenant access
result = manager.validate_cross_tenant("acme", "globex")
assert result.allowed  # True -- Globex is in Acme's cross-tenant list

result = manager.validate_cross_tenant("globex", "acme")
assert not result.allowed  # False -- Acme is NOT in Globex's list
```

### TypeScript

```typescript
import { TenantIsolationManager } from "@aumos/context-firewall";

const manager = new TenantIsolationManager();

manager.registerTenant("acme", {
  tenantId: "acme",
  displayName: "Acme Corp",
  allowedDomains: ["work", "financial"],
  dataClassification: "confidential",
  allowedCrossTenantTargets: ["globex"],
});

manager.registerTenant("globex", {
  tenantId: "globex",
  displayName: "Globex Inc",
  allowedDomains: ["work"],
  dataClassification: "restricted",
  allowedCrossTenantTargets: [],
});

const decision = manager.checkAccess("acme", "work", "read");
console.log(decision.allowed); // true

const crossResult = manager.validateCrossTenant("acme", "globex");
console.log(crossResult.allowed); // true
```

## Cross-Tenant Access Policies

### Default Deny

Cross-tenant access is denied unless the source tenant's
`allowed_cross_tenant_targets` (Python) or `allowedCrossTenantTargets`
(TypeScript) explicitly lists the target tenant ID.

### Unidirectional

Cross-tenant permissions are unidirectional. If Tenant A allows access
to Tenant B, that does NOT grant Tenant B access to Tenant A. Both
tenants must explicitly list each other for bidirectional sharing.

### Same-Tenant

Access within the same tenant is always permitted without additional
checks.

## Audit Log

Every access decision -- whether allowed or denied -- appends an
immutable `AuditEntry` to the manager's internal log. Entries include:

- Timestamp (UTC)
- Decision type (`domain_access` or `cross_tenant`)
- Tenant ID
- Target (domain name or tenant ID)
- Action label
- Allowed/denied outcome
- Human-readable reason

Retrieve the log via `get_audit_log()` (Python) or `getAuditLog()`
(TypeScript). Filter by tenant with `get_tenant_audit_log(tenant_id)` or
`getTenantAuditLog(tenantId)`.
