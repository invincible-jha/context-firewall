# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
ContextFirewall — the main orchestrator for context-firewall.

Brings together domain registry, boundary rules, keyword classification,
and pre-crossing inspection into a single, coherent API surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from .boundary import (
    DEFAULT_BOUNDARY_RULES,
    BoundaryRegistry,
    StandardBoundaryRule,
    build_boundary_key,
    build_boundary_registry,
)
from .classifier import DataClassifier, DataClassifierOptions
from .domain import (
    DEFAULT_DOMAINS,
    Domain,
    DomainRegistry,
    build_domain_registry,
    merge_domain_registries,
)
from .inspector import DataInspector
from .types import DataClassification, DataPayload, FirewallDecision

__all__ = ["ContextFirewall", "ContextFirewallOptions"]


@dataclass(frozen=True)
class ContextFirewallOptions:
    """
    Options for constructing a :class:`ContextFirewall` instance.

    :param skip_default_domains: When ``True``, built-in domains are not registered.
    :param skip_default_boundaries: When ``True``, built-in boundary rules are not registered.
    :param classifier_options: Options forwarded to :class:`~context_firewall.classifier.DataClassifier`.
    """

    skip_default_domains: bool = False
    skip_default_boundaries: bool = False
    classifier_options: DataClassifierOptions = field(
        default_factory=DataClassifierOptions
    )


class ContextFirewall:
    """
    The main context-firewall class.

    Orchestrates domain isolation by:

    1. Classifying incoming data with a keyword-based :class:`~context_firewall.classifier.DataClassifier`.
    2. Looking up the applicable :class:`~context_firewall.boundary.StandardBoundaryRule` for the requested crossing.
    3. Delegating detailed inspection to :class:`~context_firewall.inspector.DataInspector`.
    4. Returning a structured :class:`~context_firewall.types.FirewallDecision`.

    Example::

        from context_firewall import ContextFirewall

        firewall = ContextFirewall()
        decision = firewall.check(
            data={"text": "Patient blood pressure 120/80"},
            from_domain="health",
            to_domain="work",
        )
        assert not decision.allowed
        assert "medical" in decision.blocked_data_types
    """

    def __init__(self, options: ContextFirewallOptions | None = None) -> None:
        opts = options or ContextFirewallOptions()

        initial_domains = list(DEFAULT_DOMAINS) if not opts.skip_default_domains else []
        self._domain_registry: DomainRegistry = build_domain_registry(initial_domains)

        initial_rules = list(DEFAULT_BOUNDARY_RULES) if not opts.skip_default_boundaries else []
        self._boundary_registry: BoundaryRegistry = build_boundary_registry(initial_rules)

        self._classifier = DataClassifier(opts.classifier_options)
        self._inspector = DataInspector()

    # -----------------------------------------------------------------------
    # Core API
    # -----------------------------------------------------------------------

    def check(
        self,
        data: DataPayload,
        from_domain: str,
        to_domain: str,
    ) -> FirewallDecision:
        """
        Check whether *data* is permitted to cross from *from_domain* to *to_domain*.

        Steps:

        1. Validate both domain names are registered.
        2. Classify the data with the keyword-based classifier.
        3. Look up the boundary rule for this domain pair.
        4. If no rule exists, allow the crossing (open boundary).
        5. Inspect the classification against the rule.
        6. Return a :class:`~context_firewall.types.FirewallDecision` with full audit detail.

        :param data: The data payload to evaluate.
        :param from_domain: The name of the originating domain.
        :param to_domain: The name of the destination domain.
        :returns: A :class:`~context_firewall.types.FirewallDecision` describing the outcome.
        :raises ValueError: If *from_domain* or *to_domain* is not registered.
        """
        self._assert_domain_registered(from_domain)
        self._assert_domain_registered(to_domain)

        # Same-domain crossings are always allowed
        if from_domain == to_domain:
            classification = self._classifier.classify(data)
            return self._build_decision(
                allowed=True,
                reason=f"Same-domain transfer within '{from_domain}' is always permitted.",
                applied_rule_name=None,
                blocked_data_types=[],
                classification=classification,
            )

        classification = self._classifier.classify(data)
        boundary_key = build_boundary_key(from_domain, to_domain)
        rule: StandardBoundaryRule | None = self._boundary_registry.get(boundary_key)

        # No rule registered — open boundary
        if rule is None:
            return self._build_decision(
                allowed=True,
                reason=(
                    f"No boundary rule is configured for '{from_domain}' -> '{to_domain}'. "
                    "Crossing is permitted by default."
                ),
                applied_rule_name=None,
                blocked_data_types=[],
                classification=classification,
            )

        inspection = self._inspector.inspect(classification, rule)
        blocked_types = self._inspector.extract_blocked_types(inspection)

        if inspection.passed:
            return self._build_decision(
                allowed=True,
                reason=(
                    f"Boundary rule '{rule.name}' permits this crossing. "
                    "No blocked data types detected."
                ),
                applied_rule_name=rule.name,
                blocked_data_types=[],
                classification=classification,
            )

        violation_summary = ", ".join(
            f"'{v.data_type}' ({v.reason})" for v in inspection.violations
        )
        return self._build_decision(
            allowed=False,
            reason=(
                f"Boundary rule '{rule.name}' blocks this crossing. "
                f"Violations: {violation_summary}."
            ),
            applied_rule_name=rule.name,
            blocked_data_types=blocked_types,
            classification=classification,
        )

    def classify(self, data: DataPayload) -> str:
        """
        Classify *data* using the keyword-based classifier and return the
        most likely domain name.

        This is a convenience wrapper around
        :meth:`~context_firewall.classifier.DataClassifier.classify`.
        It does NOT trigger any rule evaluation or modify firewall state.

        :param data: The data payload to classify.
        :returns: The name of the most likely domain (or the fallback domain).
        """
        return self._classifier.classify(data).domain

    # -----------------------------------------------------------------------
    # Domain management
    # -----------------------------------------------------------------------

    def add_domain(self, domain: Domain) -> None:
        """
        Register a new domain with the firewall.

        :param domain: The domain to register.
        :raises ValueError: If a domain with the same name is already registered.
        """
        new_registry = build_domain_registry([domain])
        self._domain_registry = merge_domain_registries(
            self._domain_registry, new_registry
        )

    def get_domain(self, name: str) -> Domain | None:
        """
        Retrieve a registered domain by name.

        :param name: Domain name to look up.
        :returns: The :class:`~context_firewall.domain.Domain`, or ``None`` if not registered.
        """
        return self._domain_registry.get(name)

    def list_domains(self) -> list[str]:
        """List all registered domain names."""
        return list(self._domain_registry.keys())

    # -----------------------------------------------------------------------
    # Boundary management
    # -----------------------------------------------------------------------

    def add_boundary(self, rule: StandardBoundaryRule) -> None:
        """
        Register a new boundary rule.
        For ``bidirectional`` rules, entries are created in both directions.

        :param rule: The boundary rule to register.
        :raises ValueError: If a rule for the same directional pair already exists.
        """
        new_registry = build_boundary_registry([rule])
        for key, boundary_rule in new_registry.items():
            if key in self._boundary_registry:
                existing = self._boundary_registry[key]
                raise ValueError(
                    f"A boundary rule for '{key}' is already registered. "
                    f"Existing rule: '{existing.name}'."
                )
            self._boundary_registry[key] = boundary_rule

    def get_boundary(
        self, from_domain: str, to_domain: str
    ) -> StandardBoundaryRule | None:
        """
        Retrieve the boundary rule for a given domain pair, if any.

        :param from_domain: Originating domain.
        :param to_domain: Destination domain.
        :returns: The rule, or ``None`` if no rule is configured.
        """
        return self._boundary_registry.get(build_boundary_key(from_domain, to_domain))

    def list_boundaries(self) -> list[str]:
        """List all registered boundary rule names (deduplicated)."""
        seen: set[str] = set()
        names: list[str] = []
        for rule in self._boundary_registry.values():
            if rule.name not in seen:
                seen.add(rule.name)
                names.append(rule.name)
        return names

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _assert_domain_registered(self, name: str) -> None:
        if name not in self._domain_registry:
            registered = ", ".join(self._domain_registry.keys())
            raise ValueError(
                f"Domain '{name}' is not registered. "
                f"Call add_domain() first or use one of the built-in domains: {registered}."
            )

    @staticmethod
    def _build_decision(
        *,
        allowed: bool,
        reason: str,
        applied_rule_name: str | None,
        blocked_data_types: list[str],
        classification: DataClassification,
    ) -> FirewallDecision:
        return FirewallDecision(
            allowed=allowed,
            reason=reason,
            applied_rule_name=applied_rule_name,
            blocked_data_types=blocked_data_types,
            classification=classification,
            decided_at=datetime.now(UTC),
        )
