# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
GDPR compliance profile for context-firewall.

Implements purpose limitation and data minimization checks per the
General Data Protection Regulation (EU 2016/679). All evaluations
are static policy checks against operator-defined rules -- no ML,
no LLM, no adaptive behaviour.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

__all__ = [
    "GDPRPurpose",
    "ComplianceResult",
    "GDPRProfile",
]


# ---------------------------------------------------------------------------
# Purpose categories (GDPR Article 6(1))
# ---------------------------------------------------------------------------


class GDPRPurpose(str, Enum):
    """Lawful bases for processing under GDPR Article 6(1)."""

    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTERESTS = "vital_interests"
    PUBLIC_TASK = "public_task"
    LEGITIMATE_INTERESTS = "legitimate_interests"


# ---------------------------------------------------------------------------
# Data categories
# ---------------------------------------------------------------------------

# Static mapping of data categories to permissible purposes.
# Operators may extend this by subclassing GDPRProfile.
_DEFAULT_PURPOSE_MAP: dict[str, set[GDPRPurpose]] = {
    "personal_identity": {
        GDPRPurpose.CONSENT,
        GDPRPurpose.CONTRACT,
        GDPRPurpose.LEGAL_OBLIGATION,
    },
    "contact_information": {
        GDPRPurpose.CONSENT,
        GDPRPurpose.CONTRACT,
        GDPRPurpose.LEGITIMATE_INTERESTS,
    },
    "financial_data": {
        GDPRPurpose.CONTRACT,
        GDPRPurpose.LEGAL_OBLIGATION,
    },
    "health_data": {
        GDPRPurpose.CONSENT,
        GDPRPurpose.VITAL_INTERESTS,
    },
    "biometric_data": {
        GDPRPurpose.CONSENT,
    },
    "location_data": {
        GDPRPurpose.CONSENT,
        GDPRPurpose.CONTRACT,
    },
    "browsing_history": {
        GDPRPurpose.CONSENT,
    },
    "employment_data": {
        GDPRPurpose.CONTRACT,
        GDPRPurpose.LEGAL_OBLIGATION,
        GDPRPurpose.LEGITIMATE_INTERESTS,
    },
    "communication_content": {
        GDPRPurpose.CONSENT,
        GDPRPurpose.CONTRACT,
    },
    "genetic_data": {
        GDPRPurpose.CONSENT,
        GDPRPurpose.VITAL_INTERESTS,
    },
}


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


class ComplianceResult(BaseModel):
    """Outcome of a compliance check."""

    compliant: bool = Field(description="Whether the check passed.")
    profile: str = Field(description="Name of the compliance profile.")
    check_type: str = Field(description="Type of check performed.")
    reason: str = Field(description="Human-readable explanation.")
    article_reference: str = Field(
        description="Regulatory article reference for audit trail."
    )
    details: dict[str, object] = Field(
        default_factory=dict,
        description="Additional structured details about the result.",
    )
    checked_at: datetime = Field(description="UTC timestamp of the check.")

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


class GDPRProfile:
    """
    GDPR purpose limitation and data minimization compliance profile.

    All checks are deterministic, static-policy evaluations. No ML,
    no LLM, no cross-domain inference.

    Example::

        profile = GDPRProfile()

        result = profile.check_purpose_limitation(
            data_category="health_data",
            processing_purpose="consent",
        )
        assert result.compliant  # health_data may be processed under consent

        result = profile.check_purpose_limitation(
            data_category="health_data",
            processing_purpose="legitimate_interests",
        )
        assert not result.compliant  # health_data may not use legitimate interests
    """

    def __init__(
        self,
        purpose_map: dict[str, set[GDPRPurpose]] | None = None,
    ) -> None:
        self._purpose_map = (
            dict(purpose_map) if purpose_map is not None else dict(_DEFAULT_PURPOSE_MAP)
        )

    @property
    def name(self) -> str:
        """Profile identifier."""
        return "gdpr"

    @property
    def supported_categories(self) -> list[str]:
        """List of data categories with configured purpose mappings."""
        return sorted(self._purpose_map.keys())

    def check_purpose_limitation(
        self,
        data_category: str,
        processing_purpose: str,
    ) -> ComplianceResult:
        """
        Check whether processing *data_category* under *processing_purpose* is
        compliant with GDPR Article 5(1)(b) purpose limitation.

        :param data_category: The category of personal data (e.g. "health_data").
        :param processing_purpose: The lawful basis for processing (e.g. "consent").
        :returns: A :class:`ComplianceResult` with the outcome.
        """
        now = datetime.now(UTC)
        allowed_purposes = self._purpose_map.get(data_category)

        if allowed_purposes is None:
            return ComplianceResult(
                compliant=False,
                profile=self.name,
                check_type="purpose_limitation",
                reason=(
                    f"Data category '{data_category}' is not recognized. "
                    f"Cannot determine permissible purposes."
                ),
                article_reference="GDPR Art. 5(1)(b), Art. 6(1)",
                details={
                    "data_category": data_category,
                    "processing_purpose": processing_purpose,
                },
                checked_at=now,
            )

        # Validate the purpose string maps to a known enum value
        try:
            purpose_enum = GDPRPurpose(processing_purpose)
        except ValueError:
            return ComplianceResult(
                compliant=False,
                profile=self.name,
                check_type="purpose_limitation",
                reason=(
                    f"Processing purpose '{processing_purpose}' is not a recognized "
                    f"GDPR lawful basis. Valid bases: {[p.value for p in GDPRPurpose]}."
                ),
                article_reference="GDPR Art. 6(1)",
                details={
                    "data_category": data_category,
                    "processing_purpose": processing_purpose,
                },
                checked_at=now,
            )

        if purpose_enum in allowed_purposes:
            return ComplianceResult(
                compliant=True,
                profile=self.name,
                check_type="purpose_limitation",
                reason=(
                    f"Processing '{data_category}' under '{processing_purpose}' "
                    f"is permitted per configured purpose map."
                ),
                article_reference="GDPR Art. 5(1)(b), Art. 6(1)",
                details={
                    "data_category": data_category,
                    "processing_purpose": processing_purpose,
                    "allowed_purposes": sorted(p.value for p in allowed_purposes),
                },
                checked_at=now,
            )

        return ComplianceResult(
            compliant=False,
            profile=self.name,
            check_type="purpose_limitation",
            reason=(
                f"Processing '{data_category}' under '{processing_purpose}' "
                f"is NOT permitted. Allowed purposes for this category: "
                f"{sorted(p.value for p in allowed_purposes)}."
            ),
            article_reference="GDPR Art. 5(1)(b), Art. 6(1)",
            details={
                "data_category": data_category,
                "processing_purpose": processing_purpose,
                "allowed_purposes": sorted(p.value for p in allowed_purposes),
            },
            checked_at=now,
        )

    def check_data_minimization(
        self,
        requested_fields: list[str],
        necessary_fields: list[str],
    ) -> ComplianceResult:
        """
        Check whether *requested_fields* satisfies the GDPR data minimization
        principle (Article 5(1)(c)).

        Processing is compliant when every requested field is also listed as
        necessary. Any requested field not in the necessary set is flagged as
        excessive.

        :param requested_fields: Fields the agent or service is requesting.
        :param necessary_fields: Fields deemed necessary for the stated purpose.
        :returns: A :class:`ComplianceResult` with the outcome.
        """
        now = datetime.now(UTC)
        requested_set = set(requested_fields)
        necessary_set = set(necessary_fields)

        excessive_fields = sorted(requested_set - necessary_set)

        if not excessive_fields:
            return ComplianceResult(
                compliant=True,
                profile=self.name,
                check_type="data_minimization",
                reason=(
                    "All requested fields are within the necessary set. "
                    "Data minimization principle is satisfied."
                ),
                article_reference="GDPR Art. 5(1)(c)",
                details={
                    "requested_fields": sorted(requested_set),
                    "necessary_fields": sorted(necessary_set),
                    "excessive_fields": [],
                },
                checked_at=now,
            )

        return ComplianceResult(
            compliant=False,
            profile=self.name,
            check_type="data_minimization",
            reason=(
                f"Requested fields exceed what is necessary. "
                f"Excessive fields: {excessive_fields}."
            ),
            article_reference="GDPR Art. 5(1)(c)",
            details={
                "requested_fields": sorted(requested_set),
                "necessary_fields": sorted(necessary_set),
                "excessive_fields": excessive_fields,
            },
            checked_at=now,
        )
