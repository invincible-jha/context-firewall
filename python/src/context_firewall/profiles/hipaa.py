# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
HIPAA compliance profile for context-firewall.

Implements PHI access controls and minimum necessary checks per the
Health Insurance Portability and Accountability Act (45 CFR Parts 160, 164).
All evaluations are static policy checks -- no ML, no LLM, no adaptive
behaviour.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from .gdpr import ComplianceResult

__all__ = [
    "PHICategory",
    "AccessorRole",
    "EntityType",
    "HIPAAProfile",
]


# ---------------------------------------------------------------------------
# PHI categories
# ---------------------------------------------------------------------------


class PHICategory(str, Enum):
    """Categories of Protected Health Information under HIPAA."""

    DEMOGRAPHICS = "demographics"
    MEDICAL_RECORDS = "medical_records"
    INSURANCE = "insurance"
    BILLING = "billing"


# ---------------------------------------------------------------------------
# Accessor roles
# ---------------------------------------------------------------------------


class AccessorRole(str, Enum):
    """Roles that may request access to PHI."""

    TREATING_PROVIDER = "treating_provider"
    BILLING_STAFF = "billing_staff"
    INSURANCE_REVIEWER = "insurance_reviewer"
    RESEARCHER = "researcher"
    PATIENT = "patient"
    ADMINISTRATOR = "administrator"


# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------


class EntityType(str, Enum):
    """HIPAA entity classification."""

    COVERED_ENTITY = "covered_entity"
    BUSINESS_ASSOCIATE = "business_associate"
    SUBCONTRACTOR = "subcontractor"


# ---------------------------------------------------------------------------
# Static access policy
# ---------------------------------------------------------------------------

# Maps (role, phi_category) to whether access is permitted.
# Operators may extend this by subclassing HIPAAProfile.
_DEFAULT_ACCESS_POLICY: dict[AccessorRole, set[PHICategory]] = {
    AccessorRole.TREATING_PROVIDER: {
        PHICategory.DEMOGRAPHICS,
        PHICategory.MEDICAL_RECORDS,
        PHICategory.INSURANCE,
        PHICategory.BILLING,
    },
    AccessorRole.BILLING_STAFF: {
        PHICategory.DEMOGRAPHICS,
        PHICategory.BILLING,
        PHICategory.INSURANCE,
    },
    AccessorRole.INSURANCE_REVIEWER: {
        PHICategory.DEMOGRAPHICS,
        PHICategory.INSURANCE,
    },
    AccessorRole.RESEARCHER: set(),  # Requires de-identification; no direct PHI
    AccessorRole.PATIENT: {
        PHICategory.DEMOGRAPHICS,
        PHICategory.MEDICAL_RECORDS,
        PHICategory.INSURANCE,
        PHICategory.BILLING,
    },
    AccessorRole.ADMINISTRATOR: {
        PHICategory.DEMOGRAPHICS,
    },
}

# Scope hierarchy for minimum necessary checks
_SCOPE_LEVELS: dict[str, int] = {
    "record_level": 1,
    "category_level": 2,
    "department_level": 3,
    "facility_level": 4,
    "organization_level": 5,
}


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


class HIPAAProfile:
    """
    HIPAA PHI protection compliance profile.

    Enforces role-based access to PHI categories and minimum necessary
    scope checks. Distinguishes between covered entities and business
    associates.

    All checks are deterministic and static-policy based.

    Example::

        profile = HIPAAProfile()

        result = profile.check_phi_access("treating_provider", "medical_records")
        assert result.compliant

        result = profile.check_phi_access("billing_staff", "medical_records")
        assert not result.compliant
    """

    def __init__(
        self,
        access_policy: dict[AccessorRole, set[PHICategory]] | None = None,
        entity_type: EntityType = EntityType.COVERED_ENTITY,
    ) -> None:
        self._access_policy = (
            dict(access_policy)
            if access_policy is not None
            else dict(_DEFAULT_ACCESS_POLICY)
        )
        self._entity_type = entity_type

    @property
    def name(self) -> str:
        """Profile identifier."""
        return "hipaa"

    @property
    def entity_type(self) -> EntityType:
        """The HIPAA entity type for this profile instance."""
        return self._entity_type

    def check_phi_access(
        self,
        accessor_role: str,
        phi_category: str,
    ) -> ComplianceResult:
        """
        Check whether *accessor_role* is permitted to access *phi_category*.

        Access is evaluated against the static access policy table. Business
        associates have additional restrictions noted in the result.

        :param accessor_role: Role requesting access (e.g. "treating_provider").
        :param phi_category: PHI category being accessed (e.g. "medical_records").
        :returns: A :class:`ComplianceResult` with the outcome.
        """
        now = datetime.now(UTC)

        # Validate role
        try:
            role_enum = AccessorRole(accessor_role)
        except ValueError:
            return ComplianceResult(
                compliant=False,
                profile=self.name,
                check_type="phi_access",
                reason=(
                    f"Accessor role '{accessor_role}' is not recognized. "
                    f"Valid roles: {[r.value for r in AccessorRole]}."
                ),
                article_reference="45 CFR 164.502(a), 164.514(d)",
                details={
                    "accessor_role": accessor_role,
                    "phi_category": phi_category,
                    "entity_type": self._entity_type.value,
                },
                checked_at=now,
            )

        # Validate PHI category
        try:
            category_enum = PHICategory(phi_category)
        except ValueError:
            return ComplianceResult(
                compliant=False,
                profile=self.name,
                check_type="phi_access",
                reason=(
                    f"PHI category '{phi_category}' is not recognized. "
                    f"Valid categories: {[c.value for c in PHICategory]}."
                ),
                article_reference="45 CFR 160.103",
                details={
                    "accessor_role": accessor_role,
                    "phi_category": phi_category,
                    "entity_type": self._entity_type.value,
                },
                checked_at=now,
            )

        allowed_categories = self._access_policy.get(role_enum, set())

        if category_enum in allowed_categories:
            ba_note = ""
            if self._entity_type == EntityType.BUSINESS_ASSOCIATE:
                ba_note = (
                    " Note: as a business associate, access must also be "
                    "covered by a valid BAA (Business Associate Agreement)."
                )
            return ComplianceResult(
                compliant=True,
                profile=self.name,
                check_type="phi_access",
                reason=(
                    f"Role '{accessor_role}' is permitted to access "
                    f"'{phi_category}' per static HIPAA access policy.{ba_note}"
                ),
                article_reference="45 CFR 164.502(a), 164.514(d)",
                details={
                    "accessor_role": accessor_role,
                    "phi_category": phi_category,
                    "entity_type": self._entity_type.value,
                    "allowed_categories": sorted(c.value for c in allowed_categories),
                },
                checked_at=now,
            )

        return ComplianceResult(
            compliant=False,
            profile=self.name,
            check_type="phi_access",
            reason=(
                f"Role '{accessor_role}' is NOT permitted to access "
                f"'{phi_category}'. Allowed categories for this role: "
                f"{sorted(c.value for c in allowed_categories)}."
            ),
            article_reference="45 CFR 164.502(a), 164.514(d)",
            details={
                "accessor_role": accessor_role,
                "phi_category": phi_category,
                "entity_type": self._entity_type.value,
                "allowed_categories": sorted(c.value for c in allowed_categories),
            },
            checked_at=now,
        )

    def check_minimum_necessary(
        self,
        requested_scope: str,
        required_scope: str,
    ) -> ComplianceResult:
        """
        Check whether *requested_scope* satisfies HIPAA's minimum necessary
        standard (45 CFR 164.502(b)).

        The requested scope must be at or below the required scope level.
        Scope levels from narrowest to broadest: record_level, category_level,
        department_level, facility_level, organization_level.

        :param requested_scope: The scope of PHI being requested.
        :param required_scope: The minimum scope needed for the task.
        :returns: A :class:`ComplianceResult` with the outcome.
        """
        now = datetime.now(UTC)

        requested_level = _SCOPE_LEVELS.get(requested_scope)
        required_level = _SCOPE_LEVELS.get(required_scope)

        if requested_level is None:
            return ComplianceResult(
                compliant=False,
                profile=self.name,
                check_type="minimum_necessary",
                reason=(
                    f"Requested scope '{requested_scope}' is not recognized. "
                    f"Valid scopes: {sorted(_SCOPE_LEVELS.keys())}."
                ),
                article_reference="45 CFR 164.502(b), 164.514(d)",
                details={
                    "requested_scope": requested_scope,
                    "required_scope": required_scope,
                },
                checked_at=now,
            )

        if required_level is None:
            return ComplianceResult(
                compliant=False,
                profile=self.name,
                check_type="minimum_necessary",
                reason=(
                    f"Required scope '{required_scope}' is not recognized. "
                    f"Valid scopes: {sorted(_SCOPE_LEVELS.keys())}."
                ),
                article_reference="45 CFR 164.502(b), 164.514(d)",
                details={
                    "requested_scope": requested_scope,
                    "required_scope": required_scope,
                },
                checked_at=now,
            )

        if requested_level <= required_level:
            return ComplianceResult(
                compliant=True,
                profile=self.name,
                check_type="minimum_necessary",
                reason=(
                    f"Requested scope '{requested_scope}' (level {requested_level}) "
                    f"is within or equal to required scope '{required_scope}' "
                    f"(level {required_level}). Minimum necessary satisfied."
                ),
                article_reference="45 CFR 164.502(b), 164.514(d)",
                details={
                    "requested_scope": requested_scope,
                    "required_scope": required_scope,
                    "requested_level": requested_level,
                    "required_level": required_level,
                },
                checked_at=now,
            )

        return ComplianceResult(
            compliant=False,
            profile=self.name,
            check_type="minimum_necessary",
            reason=(
                f"Requested scope '{requested_scope}' (level {requested_level}) "
                f"exceeds required scope '{required_scope}' "
                f"(level {required_level}). This violates the minimum necessary standard."
            ),
            article_reference="45 CFR 164.502(b), 164.514(d)",
            details={
                "requested_scope": requested_scope,
                "required_scope": required_scope,
                "requested_level": requested_level,
                "required_level": required_level,
            },
            checked_at=now,
        )
