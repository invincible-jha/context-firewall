# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
Domain definitions for context-firewall.

A Domain describes an isolation boundary within an agent's operating context.
Domains are static — configured by the operator, never auto-discovered.
Classification must not infer domain membership from data content using ML or LLM.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator

from .types import SensitivityLevel

__all__ = [
    "Domain",
    "WORK_DOMAIN",
    "PERSONAL_DOMAIN",
    "HEALTH_DOMAIN",
    "FINANCIAL_DOMAIN",
    "DEFAULT_DOMAINS",
    "DomainRegistry",
    "build_domain_registry",
    "merge_domain_registries",
]

_DOMAIN_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*$")


class Domain(BaseModel):
    """
    Describes an isolation domain that the firewall enforces.

    Example::

        health_domain = Domain(
            name="health",
            description="Medical, mental health, and prescription data",
            sensitivity="critical",
            metadata={"regulatory_scope": "hipaa"},
        )
    """

    name: str = Field(
        description="Unique identifier for this domain. Used in boundary rule references."
    )
    description: str = Field(
        description="Human-readable description of the domain scope."
    )
    sensitivity: SensitivityLevel = Field(
        description="Sensitivity level — drives default blocking behaviour."
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Optional operator-defined metadata (e.g. regulatory tags).",
    )

    model_config = {"frozen": True}

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _DOMAIN_NAME_PATTERN.match(value):
            raise ValueError(
                f"Domain name '{value}' is invalid. "
                "Must be lowercase alphanumeric with hyphens or underscores, "
                "starting with a letter."
            )
        return value


# ---------------------------------------------------------------------------
# Default built-in domains
# ---------------------------------------------------------------------------

WORK_DOMAIN = Domain(
    name="work",
    description="Professional communications, tasks, projects, and business data",
    sensitivity="medium",
    metadata={"category": "professional", "regulatory_scope": "none"},
)
"""Built-in domain: professional work context. Sensitivity: medium."""

PERSONAL_DOMAIN = Domain(
    name="personal",
    description="Personal relationships, home, lifestyle, and non-medical private data",
    sensitivity="high",
    metadata={"category": "personal", "regulatory_scope": "gdpr-personal"},
)
"""Built-in domain: personal life context. Sensitivity: high."""

HEALTH_DOMAIN = Domain(
    name="health",
    description="Medical records, prescriptions, diagnoses, and mental health data",
    sensitivity="critical",
    metadata={"category": "health", "regulatory_scope": "hipaa,gdpr-special"},
)
"""Built-in domain: health and medical context. Sensitivity: critical."""

FINANCIAL_DOMAIN = Domain(
    name="financial",
    description="Banking, taxes, investments, credit, insurance, and financial planning",
    sensitivity="critical",
    metadata={"category": "financial", "regulatory_scope": "pci-dss,glba,gdpr-financial"},
)
"""Built-in domain: financial context. Sensitivity: critical."""

DEFAULT_DOMAINS: tuple[Domain, ...] = (
    WORK_DOMAIN,
    PERSONAL_DOMAIN,
    HEALTH_DOMAIN,
    FINANCIAL_DOMAIN,
)
"""The complete set of default built-in domains."""

# ---------------------------------------------------------------------------
# Domain registry
# ---------------------------------------------------------------------------

DomainRegistry = dict[str, Domain]
"""A mutable mapping from domain name to Domain."""


def build_domain_registry(domains: list[Domain]) -> DomainRegistry:
    """
    Build a :data:`DomainRegistry` from a list of :class:`Domain` objects.
    Duplicate names raise a :exc:`ValueError` at registration time.

    :param domains: List of domains to register.
    :returns: A dict keyed by domain name.
    :raises ValueError: If a duplicate domain name is found.
    """
    registry: DomainRegistry = {}
    for domain in domains:
        if domain.name in registry:
            raise ValueError(
                f"Domain '{domain.name}' is already registered. "
                "Domain names must be unique."
            )
        registry[domain.name] = domain
    return registry


def merge_domain_registries(
    base: DomainRegistry,
    overrides: DomainRegistry,
) -> DomainRegistry:
    """
    Merge two domain registries. Keys in *overrides* take precedence.
    Returns a new dict — never mutates the inputs.

    :param base: The base registry.
    :param overrides: Domains that override base entries.
    :returns: A new merged registry.
    """
    merged: DomainRegistry = {**base}
    merged.update(overrides)
    return merged
