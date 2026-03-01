# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Tests for context-firewall — domain classification, boundary enforcement,
inspection, and the ContextFirewall orchestrator.
"""

from __future__ import annotations

import pytest

from context_firewall.boundary import (
    BoundaryRuleConfig,
    StandardBoundaryRule,
    build_boundary_key,
    build_boundary_registry,
)
from context_firewall.classifier import DataClassifier, DataClassifierOptions
from context_firewall.domain import Domain, build_domain_registry
from context_firewall.firewall import ContextFirewall, ContextFirewallOptions
from context_firewall.inspector import DataInspector
from context_firewall.types import (
    DataClassification,
    FirewallDecision,
    InspectionResult,
    KeywordRule,
)


# ---------------------------------------------------------------------------
# TestDataClassifier
# ---------------------------------------------------------------------------


class TestDataClassifier:
    def test_classifies_health_payload(self) -> None:
        classifier = DataClassifier()
        result = classifier.classify({"text": "The patient needs a prescription refill"})
        assert result.domain == "health"
        assert len(result.detected_types) > 0

    def test_classifies_financial_payload(self) -> None:
        classifier = DataClassifier()
        result = classifier.classify({"note": "wire-transfer to savings account"})
        assert result.domain == "financial"

    def test_no_match_returns_fallback_domain(self) -> None:
        classifier = DataClassifier()
        result = classifier.classify({"text": "xyzzy foobar baz"})
        assert result.domain == "work"  # default fallback
        assert result.confidence == 0.0

    def test_custom_fallback_domain(self) -> None:
        opts = DataClassifierOptions(fallback_domain="personal")
        classifier = DataClassifier(opts)
        result = classifier.classify({"text": "unrelated content"})
        assert result.domain == "personal"

    def test_detected_types_contains_matched_category(self) -> None:
        classifier = DataClassifier()
        result = classifier.classify({"text": "diagnosis of diabetes"})
        assert "diagnosis" in result.detected_types

    def test_matched_keywords_not_empty_for_matching_payload(self) -> None:
        classifier = DataClassifier()
        result = classifier.classify({"text": "salary payroll bonus"})
        assert len(result.matched_keywords) > 0

    def test_confidence_is_between_0_and_1(self) -> None:
        classifier = DataClassifier()
        result = classifier.classify({"text": "doctor patient hospital"})
        assert 0.0 <= result.confidence <= 1.0

    def test_classification_is_deterministic(self) -> None:
        classifier = DataClassifier()
        payload = {"text": "tax-return IRS refund"}
        result1 = classifier.classify(payload)
        result2 = classifier.classify(payload)
        assert result1.domain == result2.domain
        assert result1.confidence == result2.confidence

    def test_replace_default_rules_uses_only_custom_rules(self) -> None:
        custom_rule = KeywordRule(
            id="custom-rule",
            domain="custom",
            data_type="custom-type",
            keywords=["xylophone", "quartz"],
        )
        opts = DataClassifierOptions(
            additional_rules=[custom_rule],
            replace_default_rules=True,
        )
        classifier = DataClassifier(opts)
        result = classifier.classify({"text": "xylophone quartz"})
        assert result.domain == "custom"

    def test_nested_payload_strings_are_extracted(self) -> None:
        classifier = DataClassifier()
        payload: dict[str, object] = {
            "outer": {"inner": "patient blood pressure 120/80"},
            "tags": ["medical", "routine"],
        }
        result = classifier.classify(payload)
        assert result.domain == "health"


# ---------------------------------------------------------------------------
# TestDataInspector
# ---------------------------------------------------------------------------


class TestDataInspector:
    def _make_classification(
        self,
        detected_types: list[str],
        matched_keywords: list[str] | None = None,
    ) -> DataClassification:
        return DataClassification(
            domain="health",
            detected_types=detected_types,
            matched_keywords=matched_keywords or [],
            confidence=0.8,
        )

    def _make_rule(
        self,
        blocked_types: list[str] | None = None,
        allowed_types: list[str] | None = None,
    ) -> StandardBoundaryRule:
        config = BoundaryRuleConfig(
            name="test-rule",
            from_domain="health",
            to_domain="work",
            direction="one-way",
            blocked_data_types=blocked_types or [],
            allowed_data_types=allowed_types or [],
        )
        return StandardBoundaryRule(config)

    def test_no_violations_when_types_are_allowed(self) -> None:
        inspector = DataInspector()
        classification = self._make_classification(["professional"])
        rule = self._make_rule()  # empty block and allow lists
        result = inspector.inspect(classification, rule)
        assert result.passed is True
        assert len(result.violations) == 0

    def test_explicitly_blocked_type_produces_violation(self) -> None:
        inspector = DataInspector()
        classification = self._make_classification(["medical"])
        rule = self._make_rule(blocked_types=["medical"])
        result = inspector.inspect(classification, rule)
        assert result.passed is False
        assert len(result.violations) == 1
        assert result.violations[0].reason == "explicitly-blocked"
        assert result.violations[0].data_type == "medical"

    def test_not_in_allowlist_produces_violation(self) -> None:
        inspector = DataInspector()
        classification = self._make_classification(["medical"])
        rule = self._make_rule(allowed_types=["professional"])
        result = inspector.inspect(classification, rule)
        assert result.passed is False
        violation = result.violations[0]
        assert violation.reason == "not-in-allowlist"

    def test_blocked_takes_priority_over_allowlist(self) -> None:
        inspector = DataInspector()
        classification = self._make_classification(["medical"])
        rule = self._make_rule(blocked_types=["medical"], allowed_types=["medical"])
        result = inspector.inspect(classification, rule)
        assert result.passed is False
        assert result.violations[0].reason == "explicitly-blocked"

    def test_extract_blocked_types_lists_violated_types(self) -> None:
        inspector = DataInspector()
        classification = self._make_classification(["medical", "prescription"])
        rule = self._make_rule(blocked_types=["medical", "prescription"])
        result = inspector.inspect(classification, rule)
        blocked = inspector.extract_blocked_types(result)
        assert "medical" in blocked
        assert "prescription" in blocked

    def test_is_data_type_permitted_for_open_rule(self) -> None:
        inspector = DataInspector()
        rule = self._make_rule()
        assert inspector.is_data_type_permitted("anything", rule) is True

    def test_is_data_type_permitted_blocked_returns_false(self) -> None:
        inspector = DataInspector()
        rule = self._make_rule(blocked_types=["banking"])
        assert inspector.is_data_type_permitted("banking", rule) is False

    def test_inspection_result_has_rule_name(self) -> None:
        inspector = DataInspector()
        classification = self._make_classification([])
        config = BoundaryRuleConfig(
            name="my-named-rule",
            from_domain="health",
            to_domain="work",
            direction="one-way",
        )
        rule = StandardBoundaryRule(config)
        result = inspector.inspect(classification, rule)
        assert result.rule_name == "my-named-rule"


# ---------------------------------------------------------------------------
# TestStandardBoundaryRule
# ---------------------------------------------------------------------------


class TestStandardBoundaryRule:
    def test_open_rule_allows_any_type(self) -> None:
        config = BoundaryRuleConfig(
            name="open",
            from_domain="work",
            to_domain="personal",
            direction="one-way",
        )
        rule = StandardBoundaryRule(config)
        classification = DataClassification(
            domain="work",
            detected_types=["professional", "work-communication"],
            matched_keywords=["meeting"],
            confidence=0.5,
        )
        assert rule.evaluate(classification) is True

    def test_blocked_type_returns_false(self) -> None:
        config = BoundaryRuleConfig(
            name="block-medical",
            from_domain="health",
            to_domain="work",
            direction="one-way",
            blocked_data_types=["medical"],
        )
        rule = StandardBoundaryRule(config)
        classification = DataClassification(
            domain="health",
            detected_types=["medical"],
            matched_keywords=["patient"],
            confidence=0.8,
        )
        assert rule.evaluate(classification) is False

    def test_allowlist_permits_matching_types(self) -> None:
        config = BoundaryRuleConfig(
            name="allow-professional-only",
            from_domain="work",
            to_domain="personal",
            direction="one-way",
            allowed_data_types=["professional"],
        )
        rule = StandardBoundaryRule(config)
        classification = DataClassification(
            domain="work",
            detected_types=["professional"],
            matched_keywords=["project"],
            confidence=0.5,
        )
        assert rule.evaluate(classification) is True

    def test_bidirectional_rule_has_correct_direction(self) -> None:
        config = BoundaryRuleConfig(
            name="bidirectional-test",
            from_domain="work",
            to_domain="personal",
            direction="bidirectional",
        )
        rule = StandardBoundaryRule(config)
        assert rule.direction == "bidirectional"

    def test_build_boundary_registry_raises_on_duplicate_key(self) -> None:
        config1 = BoundaryRuleConfig(
            name="rule1",
            from_domain="work",
            to_domain="personal",
            direction="one-way",
        )
        config2 = BoundaryRuleConfig(
            name="rule2",
            from_domain="work",
            to_domain="personal",
            direction="one-way",
        )
        rule1 = StandardBoundaryRule(config1)
        rule2 = StandardBoundaryRule(config2)
        with pytest.raises(ValueError, match="conflict"):
            build_boundary_registry([rule1, rule2])

    def test_build_boundary_key_format(self) -> None:
        key = build_boundary_key("health", "work")
        assert key == "health->work"


# ---------------------------------------------------------------------------
# TestDomain
# ---------------------------------------------------------------------------


class TestDomain:
    def test_valid_domain_construction(self) -> None:
        domain = Domain(
            name="custom",
            description="A custom test domain",
            sensitivity="medium",
        )
        assert domain.name == "custom"
        assert domain.sensitivity == "medium"

    def test_invalid_domain_name_raises_validation_error(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Domain(name="Invalid Name!", description="Bad name", sensitivity="low")

    def test_domain_name_must_start_with_letter(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Domain(name="1domain", description="Starts with digit", sensitivity="low")

    def test_domain_is_frozen(self) -> None:
        domain = Domain(name="test", description="test", sensitivity="low")
        with pytest.raises((TypeError, Exception)):
            domain.name = "changed"  # type: ignore[misc]

    def test_build_domain_registry_raises_on_duplicate_name(self) -> None:
        d1 = Domain(name="alpha", description="First", sensitivity="low")
        d2 = Domain(name="alpha", description="Duplicate", sensitivity="low")
        with pytest.raises(ValueError, match="already registered"):
            build_domain_registry([d1, d2])


# ---------------------------------------------------------------------------
# TestContextFirewall
# ---------------------------------------------------------------------------


class TestContextFirewall:
    def test_default_domains_are_registered(self, default_firewall: ContextFirewall) -> None:
        domains = default_firewall.list_domains()
        assert "work" in domains
        assert "personal" in domains
        assert "health" in domains
        assert "financial" in domains

    def test_unregistered_domain_raises_value_error(
        self, default_firewall: ContextFirewall
    ) -> None:
        with pytest.raises(ValueError, match="not registered"):
            default_firewall.check({"text": "test"}, "health", "nonexistent")

    def test_same_domain_crossing_always_allowed(
        self, default_firewall: ContextFirewall
    ) -> None:
        decision = default_firewall.check(
            {"text": "patient diagnosis"},
            "health",
            "health",
        )
        assert decision.allowed is True

    def test_health_to_work_blocks_medical_data(
        self, default_firewall: ContextFirewall
    ) -> None:
        decision = default_firewall.check(
            {"text": "patient needs medical treatment"},
            "health",
            "work",
        )
        assert decision.allowed is False
        assert len(decision.blocked_data_types) > 0

    def test_financial_to_work_blocks_banking_data(
        self, default_firewall: ContextFirewall
    ) -> None:
        decision = default_firewall.check(
            {"note": "bank account balance and wire-transfer"},
            "financial",
            "work",
        )
        assert decision.allowed is False

    def test_personal_to_work_blocks_family_data(
        self, default_firewall: ContextFirewall
    ) -> None:
        decision = default_firewall.check(
            {"text": "my wife and children are family"},
            "personal",
            "work",
        )
        assert decision.allowed is False

    def test_work_to_personal_has_no_default_rule(
        self, default_firewall: ContextFirewall
    ) -> None:
        # No default rule for work -> personal, so open boundary
        decision = default_firewall.check(
            {"text": "project meeting agenda"},
            "work",
            "personal",
        )
        assert decision.allowed is True
        assert decision.applied_rule_name is None

    def test_firewall_decision_has_classification(
        self, default_firewall: ContextFirewall
    ) -> None:
        decision = default_firewall.check(
            {"text": "doctor patient hospital"},
            "health",
            "work",
        )
        assert decision.classification is not None
        assert isinstance(decision.classification.confidence, float)

    def test_firewall_decision_is_frozen(
        self, default_firewall: ContextFirewall
    ) -> None:
        decision = default_firewall.check({"text": "test"}, "work", "personal")
        assert isinstance(decision, FirewallDecision)
        with pytest.raises((TypeError, Exception)):
            decision.allowed = True  # type: ignore[misc]

    def test_classify_convenience_method_returns_domain_name(
        self, default_firewall: ContextFirewall
    ) -> None:
        domain = default_firewall.classify({"text": "prescription medication dosage"})
        assert domain == "health"

    def test_add_domain_and_use_in_check(
        self, empty_firewall: ContextFirewall
    ) -> None:
        domain_a = Domain(name="zone-a", description="Zone A", sensitivity="low")
        domain_b = Domain(name="zone-b", description="Zone B", sensitivity="low")
        empty_firewall.add_domain(domain_a)
        empty_firewall.add_domain(domain_b)
        decision = empty_firewall.check({"text": "irrelevant"}, "zone-a", "zone-b")
        assert decision.allowed is True

    def test_add_boundary_blocks_crossing(
        self, empty_firewall: ContextFirewall
    ) -> None:
        zone_a = Domain(name="secure", description="Secure zone", sensitivity="critical")
        zone_b = Domain(name="public", description="Public zone", sensitivity="low")
        empty_firewall.add_domain(zone_a)
        empty_firewall.add_domain(zone_b)

        config = BoundaryRuleConfig(
            name="secure-to-public",
            from_domain="secure",
            to_domain="public",
            direction="one-way",
            blocked_data_types=["secret"],
        )
        rule = StandardBoundaryRule(config)
        empty_firewall.add_boundary(rule)

        # Payload with no secret types should pass
        decision = empty_firewall.check({"text": "normal business content"}, "secure", "public")
        assert decision.allowed is True

    def test_add_duplicate_boundary_raises_value_error(
        self, default_firewall: ContextFirewall
    ) -> None:
        config = BoundaryRuleConfig(
            name="duplicate-rule",
            from_domain="health",
            to_domain="work",
            direction="one-way",
        )
        rule = StandardBoundaryRule(config)
        with pytest.raises(ValueError, match="already registered"):
            default_firewall.add_boundary(rule)

    def test_get_domain_returns_none_for_unknown(
        self, default_firewall: ContextFirewall
    ) -> None:
        result = default_firewall.get_domain("nonexistent")
        assert result is None

    def test_get_domain_returns_domain_for_known(
        self, default_firewall: ContextFirewall
    ) -> None:
        domain = default_firewall.get_domain("health")
        assert domain is not None
        assert domain.name == "health"

    def test_list_boundaries_returns_rule_names(
        self, default_firewall: ContextFirewall
    ) -> None:
        boundaries = default_firewall.list_boundaries()
        assert "health->work" in boundaries
        assert "financial->work" in boundaries

    def test_skip_default_domains_produces_empty_registry(self) -> None:
        opts = ContextFirewallOptions(
            skip_default_domains=True,
            skip_default_boundaries=True,
        )
        firewall = ContextFirewall(options=opts)
        assert len(firewall.list_domains()) == 0

    def test_decision_decided_at_is_set(self, default_firewall: ContextFirewall) -> None:
        from datetime import datetime, timezone

        decision = default_firewall.check({"text": "test content"}, "work", "personal")
        assert decision.decided_at is not None
        assert decision.decided_at.tzinfo == timezone.utc

    def test_blocked_data_types_listed_in_decision(
        self, default_firewall: ContextFirewall
    ) -> None:
        decision = default_firewall.check(
            {"text": "prescription medication dosage tablet"},
            "health",
            "work",
        )
        assert not decision.allowed
        assert len(decision.blocked_data_types) > 0

    def test_applied_rule_name_present_when_rule_used(
        self, default_firewall: ContextFirewall
    ) -> None:
        decision = default_firewall.check(
            {"text": "patient doctor hospital"},
            "health",
            "work",
        )
        assert decision.applied_rule_name == "health->work"
