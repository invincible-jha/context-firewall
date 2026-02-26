# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
BoundaryRule definitions for context-firewall.

A BoundaryRule specifies which data types may or may not cross between
two domains. Rules are evaluated by DataInspector before any crossing is permitted.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from pydantic import BaseModel, Field

from .types import BoundaryDirection, DataClassification

__all__ = [
    "BoundaryRule",
    "BoundaryRuleConfig",
    "StandardBoundaryRule",
    "create_boundary_rule",
    "HEALTH_TO_WORK_RULE",
    "FINANCIAL_TO_WORK_RULE",
    "HEALTH_TO_PERSONAL_RULE",
    "FINANCIAL_TO_PERSONAL_RULE",
    "PERSONAL_TO_WORK_RULE",
    "DEFAULT_BOUNDARY_RULES",
    "BoundaryRegistry",
    "build_boundary_key",
    "build_boundary_registry",
]

# ---------------------------------------------------------------------------
# BoundaryRule protocol
# ---------------------------------------------------------------------------


class BoundaryRule(Protocol):
    """
    Protocol describing a boundary rule between two domains.

    Implementors can subclass :class:`StandardBoundaryRule` or implement
    this protocol directly for custom evaluation logic.
    """

    @property
    def name(self) -> str:
        """Unique identifier for this rule."""
        ...

    @property
    def from_domain(self) -> str:
        """The originating domain."""
        ...

    @property
    def to_domain(self) -> str:
        """The destination domain."""
        ...

    @property
    def direction(self) -> BoundaryDirection:
        """Direction of the rule: ``one-way`` or ``bidirectional``."""
        ...

    @property
    def allowed_data_types(self) -> list[str]:
        """Data types explicitly allowed to cross. Empty means no allowlist."""
        ...

    @property
    def blocked_data_types(self) -> list[str]:
        """Data types that must never cross."""
        ...

    def evaluate(self, classification: DataClassification) -> bool:
        """
        Evaluate whether a classification is permitted to cross.

        :param classification: The classification of the data being inspected.
        :returns: ``True`` if crossing is allowed, ``False`` if blocked.
        """
        ...


# ---------------------------------------------------------------------------
# BoundaryRuleConfig — serialisable config model
# ---------------------------------------------------------------------------


class BoundaryRuleConfig(BaseModel):
    """Serialisable configuration for a standard boundary rule."""

    name: str = Field(description="Unique rule identifier.")
    from_domain: str = Field(description="Originating domain name.")
    to_domain: str = Field(description="Destination domain name.")
    direction: BoundaryDirection = Field(description="Rule direction.")
    allowed_data_types: list[str] = Field(
        default_factory=list,
        description="Explicitly allowed data types. Empty means no allowlist.",
    )
    blocked_data_types: list[str] = Field(
        default_factory=list,
        description="Data types that are never permitted to cross.",
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# StandardBoundaryRule — concrete implementation
# ---------------------------------------------------------------------------


class StandardBoundaryRule:
    """
    Standard implementation of :class:`BoundaryRule`.

    Evaluation logic:

    1. If ``blocked_data_types`` is non-empty, any detected type in that list blocks the crossing.
    2. If ``allowed_data_types`` is non-empty, only types on the list are permitted.
    3. If both lists are empty, the crossing is allowed (open rule).

    Example::

        rule = StandardBoundaryRule(BoundaryRuleConfig(
            name="health->work",
            from_domain="health",
            to_domain="work",
            direction="one-way",
            blocked_data_types=["medical", "prescription", "diagnosis"],
        ))
        rule.evaluate(classification)  # False if medical data detected
    """

    def __init__(self, config: BoundaryRuleConfig) -> None:
        self._config = config

    @property
    def name(self) -> str:
        return self._config.name

    @property
    def from_domain(self) -> str:
        return self._config.from_domain

    @property
    def to_domain(self) -> str:
        return self._config.to_domain

    @property
    def direction(self) -> BoundaryDirection:
        return self._config.direction

    @property
    def allowed_data_types(self) -> list[str]:
        return list(self._config.allowed_data_types)

    @property
    def blocked_data_types(self) -> list[str]:
        return list(self._config.blocked_data_types)

    def evaluate(self, classification: DataClassification) -> bool:
        """Evaluate whether the classification may cross this boundary."""
        blocked = set(self._config.blocked_data_types)
        allowed = set(self._config.allowed_data_types)

        for detected_type in classification.detected_types:
            if detected_type in blocked:
                return False
            if allowed and detected_type not in allowed:
                return False
        return True


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_boundary_rule(config: BoundaryRuleConfig) -> StandardBoundaryRule:
    """
    Build a :class:`StandardBoundaryRule` from a :class:`BoundaryRuleConfig`.

    :param config: Serialisable rule configuration.
    :returns: A fully formed rule ready for registration.
    """
    return StandardBoundaryRule(config)


# ---------------------------------------------------------------------------
# Default built-in boundary rules
# ---------------------------------------------------------------------------

HEALTH_TO_WORK_RULE = create_boundary_rule(
    BoundaryRuleConfig(
        name="health->work",
        from_domain="health",
        to_domain="work",
        direction="one-way",
        blocked_data_types=[
            "medical",
            "prescription",
            "diagnosis",
            "mental-health",
            "clinical",
            "laboratory",
        ],
    )
)
"""health -> work: no medical data crosses into professional context."""

FINANCIAL_TO_WORK_RULE = create_boundary_rule(
    BoundaryRuleConfig(
        name="financial->work",
        from_domain="financial",
        to_domain="work",
        direction="one-way",
        blocked_data_types=[
            "banking",
            "credit-card",
            "tax",
            "investment",
            "insurance-financial",
            "salary",
        ],
    )
)
"""financial -> work: no financial account or tax data crosses into work context."""

HEALTH_TO_PERSONAL_RULE = create_boundary_rule(
    BoundaryRuleConfig(
        name="health->personal",
        from_domain="health",
        to_domain="personal",
        direction="one-way",
        blocked_data_types=[
            "medical",
            "prescription",
            "diagnosis",
            "mental-health",
            "clinical",
            "laboratory",
        ],
    )
)
"""health -> personal: medical data may not cross into personal domain by default."""

FINANCIAL_TO_PERSONAL_RULE = create_boundary_rule(
    BoundaryRuleConfig(
        name="financial->personal",
        from_domain="financial",
        to_domain="personal",
        direction="one-way",
        blocked_data_types=[
            "banking",
            "credit-card",
            "tax",
            "investment",
            "salary",
        ],
    )
)
"""financial -> personal: core financial account data may not flow into personal context."""

PERSONAL_TO_WORK_RULE = create_boundary_rule(
    BoundaryRuleConfig(
        name="personal->work",
        from_domain="personal",
        to_domain="work",
        direction="one-way",
        blocked_data_types=[
            "family",
            "relationship",
            "home-address",
            "personal-contact",
        ],
    )
)
"""personal -> work: personal and family data must not enter the work domain."""

DEFAULT_BOUNDARY_RULES: tuple[StandardBoundaryRule, ...] = (
    HEALTH_TO_WORK_RULE,
    FINANCIAL_TO_WORK_RULE,
    HEALTH_TO_PERSONAL_RULE,
    FINANCIAL_TO_PERSONAL_RULE,
    PERSONAL_TO_WORK_RULE,
)
"""The complete set of default built-in boundary rules."""

# ---------------------------------------------------------------------------
# Boundary registry
# ---------------------------------------------------------------------------

BoundaryRegistry = dict[str, StandardBoundaryRule]
"""Mutable mapping from ``"from_domain->to_domain"`` keys to rules."""


def build_boundary_key(from_domain: str, to_domain: str) -> str:
    """Build the registry lookup key for a from/to domain pair."""
    return f"{from_domain}->{to_domain}"


def build_boundary_registry(
    rules: list[StandardBoundaryRule] | tuple[StandardBoundaryRule, ...],
) -> BoundaryRegistry:
    """
    Build a :data:`BoundaryRegistry` from a list of rules.
    For ``bidirectional`` rules, entries are created in both directions.

    :param rules: Boundary rules to index.
    :returns: Dict keyed by ``"from->to"`` strings.
    :raises ValueError: If two rules share the same directional key.
    """
    registry: BoundaryRegistry = {}
    for rule in rules:
        forward_key = build_boundary_key(rule.from_domain, rule.to_domain)
        if forward_key in registry:
            raise ValueError(
                f"Boundary rule conflict: a rule for '{forward_key}' is already registered. "
                f"Existing rule: '{registry[forward_key].name}', new rule: '{rule.name}'."
            )
        registry[forward_key] = rule

        if rule.direction == "bidirectional":
            reverse_key = build_boundary_key(rule.to_domain, rule.from_domain)
            if reverse_key in registry:
                raise ValueError(
                    f"Boundary rule conflict: bidirectional rule '{rule.name}' would overwrite "
                    f"existing rule for '{reverse_key}'."
                )
            registry[reverse_key] = rule

    return registry
