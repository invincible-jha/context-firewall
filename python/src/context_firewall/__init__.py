# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
context-firewall
================
Domain isolation for AI agents — prevent data leaking between work, personal,
health, and financial contexts using purely keyword-based, deterministic
classification.

FIRE LINE: No ML, no LLM, no auto-discovery. See FIRE_LINE.md.

Quick start::

    from context_firewall import ContextFirewall

    firewall = ContextFirewall()
    decision = firewall.check(
        data={"text": "My insulin dosage is 10 units"},
        from_domain="health",
        to_domain="work",
    )
    # decision.allowed is False
"""

from .boundary import (
    BoundaryRegistry,
    BoundaryRuleConfig,
    DEFAULT_BOUNDARY_RULES,
    FINANCIAL_TO_PERSONAL_RULE,
    FINANCIAL_TO_WORK_RULE,
    HEALTH_TO_PERSONAL_RULE,
    HEALTH_TO_WORK_RULE,
    PERSONAL_TO_WORK_RULE,
    StandardBoundaryRule,
    build_boundary_key,
    build_boundary_registry,
    create_boundary_rule,
)
from .classifier import DataClassifier, DataClassifierOptions, DEFAULT_KEYWORD_RULES
from .domain import (
    DEFAULT_DOMAINS,
    FINANCIAL_DOMAIN,
    HEALTH_DOMAIN,
    PERSONAL_DOMAIN,
    WORK_DOMAIN,
    Domain,
    DomainRegistry,
    build_domain_registry,
    merge_domain_registries,
)
from .firewall import ContextFirewall, ContextFirewallOptions
from .inspector import DataInspector
from .multilang import (
    InjectionMatch,
    InjectionResult,
    MultiLangFirewall,
    normalize_unicode,
    normalize_homoglyphs,
    preprocess,
    strip_zero_width,
)
from .types import (
    BoundaryDirection,
    DataClassification,
    DataPayload,
    FirewallDecision,
    InspectionResult,
    InspectionViolation,
    KeywordRule,
    SensitivityLevel,
)

__all__ = [
    # Main class
    "ContextFirewall",
    "ContextFirewallOptions",
    # Domain
    "Domain",
    "DomainRegistry",
    "WORK_DOMAIN",
    "PERSONAL_DOMAIN",
    "HEALTH_DOMAIN",
    "FINANCIAL_DOMAIN",
    "DEFAULT_DOMAINS",
    "build_domain_registry",
    "merge_domain_registries",
    # Boundary
    "StandardBoundaryRule",
    "BoundaryRuleConfig",
    "BoundaryRegistry",
    "HEALTH_TO_WORK_RULE",
    "FINANCIAL_TO_WORK_RULE",
    "HEALTH_TO_PERSONAL_RULE",
    "FINANCIAL_TO_PERSONAL_RULE",
    "PERSONAL_TO_WORK_RULE",
    "DEFAULT_BOUNDARY_RULES",
    "build_boundary_key",
    "build_boundary_registry",
    "create_boundary_rule",
    # Classifier
    "DataClassifier",
    "DataClassifierOptions",
    "DEFAULT_KEYWORD_RULES",
    # Inspector
    "DataInspector",
    # Multi-language injection detection
    "MultiLangFirewall",
    "InjectionMatch",
    "InjectionResult",
    "normalize_unicode",
    "normalize_homoglyphs",
    "preprocess",
    "strip_zero_width",
    # Types
    "SensitivityLevel",
    "BoundaryDirection",
    "DataPayload",
    "DataClassification",
    "FirewallDecision",
    "KeywordRule",
    "InspectionViolation",
    "InspectionResult",
]
