# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
SOX compliance profile for context-firewall.

Implements segregation of duties and audit trail completeness checks
per the Sarbanes-Oxley Act (SOX) Sections 302, 404. All evaluations
are static policy checks -- no ML, no LLM, no adaptive behaviour.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from .gdpr import ComplianceResult

__all__ = [
    "FinancialAction",
    "AgentRole",
    "SOXProfile",
]


# ---------------------------------------------------------------------------
# Financial actions
# ---------------------------------------------------------------------------


class FinancialAction(str, Enum):
    """Financial transaction categories subject to SOX controls."""

    APPROVE = "approve"
    EXECUTE = "execute"
    RECONCILE = "reconcile"
    REPORT = "report"


# ---------------------------------------------------------------------------
# Agent roles
# ---------------------------------------------------------------------------


class AgentRole(str, Enum):
    """Roles that agents or users may hold in financial workflows."""

    APPROVER = "approver"
    EXECUTOR = "executor"
    RECONCILER = "reconciler"
    REPORTER = "reporter"
    AUDITOR = "auditor"


# ---------------------------------------------------------------------------
# Static duty separation policy
# ---------------------------------------------------------------------------

# Maps each role to the actions it is allowed to perform.
# The key constraint: no single role may both approve AND execute.
_DEFAULT_DUTY_MAP: dict[AgentRole, set[FinancialAction]] = {
    AgentRole.APPROVER: {FinancialAction.APPROVE},
    AgentRole.EXECUTOR: {FinancialAction.EXECUTE},
    AgentRole.RECONCILER: {FinancialAction.RECONCILE},
    AgentRole.REPORTER: {FinancialAction.REPORT},
    AgentRole.AUDITOR: {FinancialAction.REPORT, FinancialAction.RECONCILE},
}

# Actions that must never be performed by the same role
_CONFLICTING_ACTIONS: list[tuple[FinancialAction, FinancialAction]] = [
    (FinancialAction.APPROVE, FinancialAction.EXECUTE),
    (FinancialAction.EXECUTE, FinancialAction.RECONCILE),
    (FinancialAction.APPROVE, FinancialAction.RECONCILE),
]

# Required fields in an audit record for completeness checks
_REQUIRED_AUDIT_FIELDS: list[str] = [
    "transaction_id",
    "timestamp",
    "actor",
    "action",
    "amount",
    "status",
]


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


class SOXProfile:
    """
    SOX financial controls compliance profile.

    Enforces segregation of duties and validates audit trail completeness
    for financial transactions. All checks are deterministic and static-policy
    based.

    Example::

        profile = SOXProfile()

        # Approver can approve
        result = profile.check_segregation_of_duties("approver", "approve")
        assert result.compliant

        # Approver cannot execute (segregation of duties)
        result = profile.check_segregation_of_duties("approver", "execute")
        assert not result.compliant
    """

    def __init__(
        self,
        duty_map: dict[AgentRole, set[FinancialAction]] | None = None,
        required_audit_fields: list[str] | None = None,
    ) -> None:
        self._duty_map = (
            dict(duty_map) if duty_map is not None else dict(_DEFAULT_DUTY_MAP)
        )
        self._required_audit_fields = (
            list(required_audit_fields)
            if required_audit_fields is not None
            else list(_REQUIRED_AUDIT_FIELDS)
        )

    @property
    def name(self) -> str:
        """Profile identifier."""
        return "sox"

    def check_segregation_of_duties(
        self,
        agent_role: str,
        action: str,
    ) -> ComplianceResult:
        """
        Check whether *agent_role* is permitted to perform *action* under
        SOX segregation of duties requirements.

        No single role should be able to both initiate and approve a
        financial transaction.

        :param agent_role: The role of the agent or user (e.g. "approver").
        :param action: The financial action being attempted (e.g. "execute").
        :returns: A :class:`ComplianceResult` with the outcome.
        """
        now = datetime.now(UTC)

        # Validate role
        try:
            role_enum = AgentRole(agent_role)
        except ValueError:
            return ComplianceResult(
                compliant=False,
                profile=self.name,
                check_type="segregation_of_duties",
                reason=(
                    f"Agent role '{agent_role}' is not recognized. "
                    f"Valid roles: {[r.value for r in AgentRole]}."
                ),
                article_reference="SOX Section 404, COSO Framework",
                details={
                    "agent_role": agent_role,
                    "action": action,
                },
                checked_at=now,
            )

        # Validate action
        try:
            action_enum = FinancialAction(action)
        except ValueError:
            return ComplianceResult(
                compliant=False,
                profile=self.name,
                check_type="segregation_of_duties",
                reason=(
                    f"Financial action '{action}' is not recognized. "
                    f"Valid actions: {[a.value for a in FinancialAction]}."
                ),
                article_reference="SOX Section 404, COSO Framework",
                details={
                    "agent_role": agent_role,
                    "action": action,
                },
                checked_at=now,
            )

        allowed_actions = self._duty_map.get(role_enum, set())

        if action_enum in allowed_actions:
            return ComplianceResult(
                compliant=True,
                profile=self.name,
                check_type="segregation_of_duties",
                reason=(
                    f"Role '{agent_role}' is permitted to perform '{action}' "
                    f"per static duty separation policy."
                ),
                article_reference="SOX Section 404, COSO Framework",
                details={
                    "agent_role": agent_role,
                    "action": action,
                    "allowed_actions": sorted(a.value for a in allowed_actions),
                },
                checked_at=now,
            )

        # Check if the denial is specifically due to a conflict
        conflict_reason = self._find_conflict(role_enum, action_enum)

        return ComplianceResult(
            compliant=False,
            profile=self.name,
            check_type="segregation_of_duties",
            reason=(
                f"Role '{agent_role}' is NOT permitted to perform '{action}'. "
                f"Allowed actions for this role: "
                f"{sorted(a.value for a in allowed_actions)}."
                f"{conflict_reason}"
            ),
            article_reference="SOX Section 404, COSO Framework",
            details={
                "agent_role": agent_role,
                "action": action,
                "allowed_actions": sorted(a.value for a in allowed_actions),
            },
            checked_at=now,
        )

    def check_audit_trail_completeness(
        self,
        records: list[dict[str, object]],
    ) -> ComplianceResult:
        """
        Check whether a list of audit trail records contains all required
        fields per SOX Section 302/404 requirements.

        Each record must contain every field listed in the required audit
        fields configuration.

        :param records: List of audit records to validate.
        :returns: A :class:`ComplianceResult` with the outcome.
        """
        now = datetime.now(UTC)

        if not records:
            return ComplianceResult(
                compliant=False,
                profile=self.name,
                check_type="audit_trail_completeness",
                reason="No audit records provided. An empty audit trail is non-compliant.",
                article_reference="SOX Section 302, Section 404",
                details={
                    "record_count": 0,
                    "required_fields": self._required_audit_fields,
                },
                checked_at=now,
            )

        incomplete_records: list[dict[str, object]] = []

        for index, record in enumerate(records):
            record_keys = set(record.keys())
            missing = sorted(set(self._required_audit_fields) - record_keys)
            if missing:
                incomplete_records.append({
                    "record_index": index,
                    "missing_fields": missing,
                })

        if not incomplete_records:
            return ComplianceResult(
                compliant=True,
                profile=self.name,
                check_type="audit_trail_completeness",
                reason=(
                    f"All {len(records)} audit records contain the required fields. "
                    f"Audit trail is complete."
                ),
                article_reference="SOX Section 302, Section 404",
                details={
                    "record_count": len(records),
                    "required_fields": self._required_audit_fields,
                },
                checked_at=now,
            )

        return ComplianceResult(
            compliant=False,
            profile=self.name,
            check_type="audit_trail_completeness",
            reason=(
                f"{len(incomplete_records)} of {len(records)} audit records are "
                f"missing required fields. The audit trail is incomplete."
            ),
            article_reference="SOX Section 302, Section 404",
            details={
                "record_count": len(records),
                "required_fields": self._required_audit_fields,
                "incomplete_records": incomplete_records,
            },
            checked_at=now,
        )

    def _find_conflict(
        self, role: AgentRole, action: FinancialAction
    ) -> str:
        """Check if the denial is due to a specific duty conflict."""
        allowed_actions = self._duty_map.get(role, set())
        for action_a, action_b in _CONFLICTING_ACTIONS:
            if action == action_b and action_a in allowed_actions:
                return (
                    f" This role already has '{action_a.value}' permission, "
                    f"which conflicts with '{action_b.value}' under "
                    f"segregation of duties."
                )
            if action == action_a and action_b in allowed_actions:
                return (
                    f" This role already has '{action_b.value}' permission, "
                    f"which conflicts with '{action_a.value}' under "
                    f"segregation of duties."
                )
        return ""
