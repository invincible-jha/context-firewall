# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
Shared type definitions for context-firewall.

All public API shapes are defined here as Pydantic models and plain dataclasses,
then re-exported from __init__.py.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

__all__ = [
    "SensitivityLevel",
    "BoundaryDirection",
    "DataPayload",
    "DataClassification",
    "FirewallDecision",
    "KeywordRule",
    "InspectionViolation",
    "InspectionResult",
]

# ---------------------------------------------------------------------------
# Primitive type aliases
# ---------------------------------------------------------------------------

SensitivityLevel = Literal["low", "medium", "high", "critical"]
"""Sensitivity level of a domain. Higher means stricter crossing rules."""

BoundaryDirection = Literal["one-way", "bidirectional"]
"""
Direction of a boundary rule.
- ``one-way``: enforced only from ``from_domain`` to ``to_domain``.
- ``bidirectional``: enforced in both directions.
"""

DataPayload = dict[str, object]
"""The data payload the firewall inspects. Any JSON-serialisable structure."""

# ---------------------------------------------------------------------------
# Data classification result
# ---------------------------------------------------------------------------


class DataClassification(BaseModel):
    """Output of a :class:`~context_firewall.classifier.DataClassifier` call."""

    domain: str = Field(description="The domain that best matches the data payload.")
    detected_types: list[str] = Field(
        description="Data type categories detected within the payload."
    )
    matched_keywords: list[str] = Field(
        description="Keywords that triggered this classification, for auditability."
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence as a ratio 0–1 based on keyword hit density.",
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Firewall decision
# ---------------------------------------------------------------------------


class FirewallDecision(BaseModel):
    """Result returned by :meth:`~context_firewall.firewall.ContextFirewall.check`."""

    allowed: bool = Field(description="Whether the data crossing is permitted.")
    reason: str = Field(description="Human-readable explanation for the decision.")
    applied_rule_name: str | None = Field(
        description="Name of the boundary rule applied, if any."
    )
    blocked_data_types: list[str] = Field(
        description="Data types that were blocked, if any."
    )
    classification: DataClassification = Field(
        description="The classification result that informed the decision."
    )
    decided_at: datetime = Field(
        description="Timestamp of the decision (UTC)."
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Keyword rule
# ---------------------------------------------------------------------------


class KeywordRule(BaseModel):
    """A single keyword rule mapping keywords to a domain and data type."""

    id: str = Field(description="Unique identifier for this rule.")
    domain: str = Field(description="The domain this keyword set belongs to.")
    data_type: str = Field(description="The data type category, e.g. 'medical'.")
    keywords: list[str] = Field(
        min_length=1,
        description="Keywords to match (case-insensitive, whole-word preferred).",
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Inspection result
# ---------------------------------------------------------------------------


class InspectionViolation(BaseModel):
    """A single inspection violation found by :class:`~context_firewall.inspector.DataInspector`."""

    data_type: str = Field(description="The data type that caused the violation.")
    reason: Literal["explicitly-blocked", "not-in-allowlist"] = Field(
        description="Whether the type was on the blocked list or missing from the allowed list."
    )
    matched_keywords: list[str] = Field(
        description="Keywords that surfaced this data type."
    )

    model_config = {"frozen": True}


class InspectionResult(BaseModel):
    """Full output of a :meth:`~context_firewall.inspector.DataInspector.inspect` call."""

    passed: bool = Field(description="Whether the data passed inspection.")
    violations: list[InspectionViolation] = Field(
        description="List of violations found."
    )
    rule_name: str = Field(description="The boundary rule used for inspection.")

    model_config = {"frozen": True}
