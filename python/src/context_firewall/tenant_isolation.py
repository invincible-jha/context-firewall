# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
Tenant-aware domain isolation for multi-tenant agent deployments.

Provides static, policy-driven access control between tenants. Cross-tenant
access is DENIED by default. All access decisions are recorded in an audit
log for compliance visibility.

FIRE LINE: Domain boundaries are static policy only. No adaptive behaviour,
no cross-domain inference, no ML-based classification.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

__all__ = [
    "DataClassificationLevel",
    "TenantConfig",
    "TenantContext",
    "AccessDecision",
    "CrossTenantResult",
    "AuditEntry",
    "TenantIsolationManager",
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Classification levels
# ---------------------------------------------------------------------------


class DataClassificationLevel(str, Enum):
    """Static classification levels for tenant data."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# ---------------------------------------------------------------------------
# Configuration models
# ---------------------------------------------------------------------------


class TenantConfig(BaseModel):
    """Operator-provided configuration for a tenant."""

    tenant_id: str = Field(description="Unique identifier for this tenant.")
    display_name: str = Field(description="Human-readable tenant name.")
    allowed_domains: list[str] = Field(
        default_factory=list,
        description="Domains this tenant may access (e.g. 'work', 'health').",
    )
    data_classification: DataClassificationLevel = Field(
        default=DataClassificationLevel.CONFIDENTIAL,
        description="Default classification level for tenant data.",
    )
    allowed_cross_tenant_targets: list[str] = Field(
        default_factory=list,
        description=(
            "Tenant IDs that this tenant is explicitly allowed to share data with. "
            "Empty means no cross-tenant access."
        ),
    )

    model_config = {"frozen": True}


class TenantContext(BaseModel):
    """Runtime context describing the currently active tenant."""

    tenant_id: str = Field(description="Unique identifier for the active tenant.")
    allowed_domains: list[str] = Field(
        description="Domains the tenant may operate within."
    )
    data_classification: DataClassificationLevel = Field(
        description="Classification level governing data handling."
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Decision models
# ---------------------------------------------------------------------------


class AccessDecision(BaseModel):
    """Result of a tenant domain access check."""

    allowed: bool = Field(description="Whether the access is permitted.")
    tenant_id: str = Field(description="The tenant requesting access.")
    target_domain: str = Field(description="The domain being accessed.")
    action: str = Field(description="The action being performed.")
    reason: str = Field(description="Human-readable explanation.")
    decided_at: datetime = Field(description="UTC timestamp of the decision.")

    model_config = {"frozen": True}


class CrossTenantResult(BaseModel):
    """Result of a cross-tenant access validation."""

    allowed: bool = Field(description="Whether cross-tenant access is permitted.")
    source_tenant: str = Field(description="The tenant initiating the request.")
    target_tenant: str = Field(description="The tenant being accessed.")
    reason: str = Field(description="Human-readable explanation.")
    decided_at: datetime = Field(description="UTC timestamp of the decision.")

    model_config = {"frozen": True}


class AuditEntry(BaseModel):
    """Immutable record of an access decision for audit logging."""

    timestamp: datetime = Field(description="When the decision was made (UTC).")
    decision_type: Literal["domain_access", "cross_tenant"] = Field(
        description="Category of the access check."
    )
    tenant_id: str = Field(description="Primary tenant involved.")
    target: str = Field(
        description="Target domain or tenant ID that was evaluated."
    )
    action: str = Field(description="Requested action.")
    allowed: bool = Field(description="Whether access was granted.")
    reason: str = Field(description="Explanation for the decision.")

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class TenantIsolationManager:
    """
    Manages tenant registration and enforces static isolation policies.

    Cross-tenant access is DENIED by default. A tenant may only access
    domains listed in its configuration. All decisions are logged to an
    internal audit trail accessible via ``get_audit_log``.

    Example::

        manager = TenantIsolationManager()
        config = TenantConfig(
            tenant_id="acme",
            display_name="Acme Corp",
            allowed_domains=["work", "financial"],
            data_classification=DataClassificationLevel.CONFIDENTIAL,
        )
        manager.register_tenant("acme", config)

        decision = manager.check_access("acme", "work", "read")
        assert decision.allowed
    """

    def __init__(self) -> None:
        self._tenants: dict[str, TenantConfig] = {}
        self._audit_log: list[AuditEntry] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_tenant(self, tenant_id: str, config: TenantConfig) -> None:
        """
        Register a tenant with the isolation manager.

        :param tenant_id: Unique tenant identifier (must match ``config.tenant_id``).
        :param config: Static configuration for the tenant.
        :raises ValueError: If the tenant is already registered or IDs mismatch.
        """
        if tenant_id != config.tenant_id:
            raise ValueError(
                f"Tenant ID mismatch: argument is '{tenant_id}' but "
                f"config.tenant_id is '{config.tenant_id}'."
            )
        if tenant_id in self._tenants:
            raise ValueError(
                f"Tenant '{tenant_id}' is already registered. "
                "Unregister it first or use a different ID."
            )
        self._tenants[tenant_id] = config
        logger.info("Registered tenant '%s' (%s).", tenant_id, config.display_name)

    def unregister_tenant(self, tenant_id: str) -> bool:
        """
        Remove a tenant from the manager.

        :param tenant_id: The tenant to remove.
        :returns: True if the tenant was found and removed, False otherwise.
        """
        removed = self._tenants.pop(tenant_id, None)
        if removed is not None:
            logger.info("Unregistered tenant '%s'.", tenant_id)
            return True
        return False

    def get_tenant(self, tenant_id: str) -> TenantConfig | None:
        """Return the config for *tenant_id*, or None if not registered."""
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> list[str]:
        """List all registered tenant IDs."""
        return list(self._tenants.keys())

    # ------------------------------------------------------------------
    # Access checks
    # ------------------------------------------------------------------

    def check_access(
        self, tenant_id: str, target_domain: str, action: str
    ) -> AccessDecision:
        """
        Check whether *tenant_id* is allowed to perform *action* on *target_domain*.

        The check is purely based on the tenant's static configuration:
        the domain must be listed in ``allowed_domains``.

        :param tenant_id: The tenant requesting access.
        :param target_domain: The domain being accessed.
        :param action: A label for the action (e.g. "read", "write").
        :returns: An :class:`AccessDecision` describing the outcome.
        """
        now = datetime.now(UTC)
        config = self._tenants.get(tenant_id)

        if config is None:
            decision = AccessDecision(
                allowed=False,
                tenant_id=tenant_id,
                target_domain=target_domain,
                action=action,
                reason=f"Tenant '{tenant_id}' is not registered.",
                decided_at=now,
            )
            self._record_audit("domain_access", tenant_id, target_domain, action, False, decision.reason)
            return decision

        if target_domain in config.allowed_domains:
            decision = AccessDecision(
                allowed=True,
                tenant_id=tenant_id,
                target_domain=target_domain,
                action=action,
                reason=(
                    f"Tenant '{tenant_id}' is allowed access to domain "
                    f"'{target_domain}' per static configuration."
                ),
                decided_at=now,
            )
        else:
            decision = AccessDecision(
                allowed=False,
                tenant_id=tenant_id,
                target_domain=target_domain,
                action=action,
                reason=(
                    f"Tenant '{tenant_id}' is not allowed access to domain "
                    f"'{target_domain}'. Allowed domains: {config.allowed_domains}."
                ),
                decided_at=now,
            )

        self._record_audit(
            "domain_access", tenant_id, target_domain, action,
            decision.allowed, decision.reason,
        )
        return decision

    def validate_cross_tenant(
        self, source: str, target: str
    ) -> CrossTenantResult:
        """
        Validate whether cross-tenant access from *source* to *target* is allowed.

        Cross-tenant access is DENIED by default. It is only permitted when
        the source tenant's ``allowed_cross_tenant_targets`` list explicitly
        includes the target tenant ID.

        :param source: The initiating tenant ID.
        :param target: The target tenant ID.
        :returns: A :class:`CrossTenantResult` describing the outcome.
        """
        now = datetime.now(UTC)

        if source == target:
            result = CrossTenantResult(
                allowed=True,
                source_tenant=source,
                target_tenant=target,
                reason="Same-tenant access is always permitted.",
                decided_at=now,
            )
            self._record_audit(
                "cross_tenant", source, target, "cross_tenant_access",
                True, result.reason,
            )
            return result

        source_config = self._tenants.get(source)
        if source_config is None:
            result = CrossTenantResult(
                allowed=False,
                source_tenant=source,
                target_tenant=target,
                reason=f"Source tenant '{source}' is not registered.",
                decided_at=now,
            )
            self._record_audit(
                "cross_tenant", source, target, "cross_tenant_access",
                False, result.reason,
            )
            return result

        if target not in self._tenants:
            result = CrossTenantResult(
                allowed=False,
                source_tenant=source,
                target_tenant=target,
                reason=f"Target tenant '{target}' is not registered.",
                decided_at=now,
            )
            self._record_audit(
                "cross_tenant", source, target, "cross_tenant_access",
                False, result.reason,
            )
            return result

        if target in source_config.allowed_cross_tenant_targets:
            result = CrossTenantResult(
                allowed=True,
                source_tenant=source,
                target_tenant=target,
                reason=(
                    f"Tenant '{source}' has explicit cross-tenant access "
                    f"to '{target}' in its static configuration."
                ),
                decided_at=now,
            )
        else:
            result = CrossTenantResult(
                allowed=False,
                source_tenant=source,
                target_tenant=target,
                reason=(
                    f"Cross-tenant access from '{source}' to '{target}' "
                    f"is denied. Not listed in allowed_cross_tenant_targets."
                ),
                decided_at=now,
            )

        self._record_audit(
            "cross_tenant", source, target, "cross_tenant_access",
            result.allowed, result.reason,
        )
        return result

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def get_audit_log(self) -> list[AuditEntry]:
        """Return a copy of the full audit log."""
        return list(self._audit_log)

    def get_tenant_audit_log(self, tenant_id: str) -> list[AuditEntry]:
        """Return audit entries for a specific tenant."""
        return [entry for entry in self._audit_log if entry.tenant_id == tenant_id]

    def _record_audit(
        self,
        decision_type: Literal["domain_access", "cross_tenant"],
        tenant_id: str,
        target: str,
        action: str,
        allowed: bool,
        reason: str,
    ) -> None:
        """Append an immutable audit entry to the internal log."""
        entry = AuditEntry(
            timestamp=datetime.now(UTC),
            decision_type=decision_type,
            tenant_id=tenant_id,
            target=target,
            action=action,
            allowed=allowed,
            reason=reason,
        )
        self._audit_log.append(entry)
        logger.debug(
            "Audit: %s | tenant=%s | target=%s | action=%s | allowed=%s",
            decision_type,
            tenant_id,
            target,
            action,
            allowed,
        )
