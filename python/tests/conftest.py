# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""Shared fixtures for context-firewall tests."""

from __future__ import annotations

import pytest

from context_firewall.boundary import BoundaryRuleConfig, StandardBoundaryRule
from context_firewall.classifier import DataClassifierOptions
from context_firewall.domain import Domain
from context_firewall.firewall import ContextFirewall, ContextFirewallOptions


@pytest.fixture
def default_firewall() -> ContextFirewall:
    """A ContextFirewall with all default domains and boundary rules."""
    return ContextFirewall()


@pytest.fixture
def empty_firewall() -> ContextFirewall:
    """A ContextFirewall with no default domains or boundary rules."""
    options = ContextFirewallOptions(
        skip_default_domains=True,
        skip_default_boundaries=True,
    )
    return ContextFirewall(options=options)


@pytest.fixture
def custom_work_domain() -> Domain:
    return Domain(
        name="custom-work",
        description="Custom work domain for testing",
        sensitivity="medium",
    )


@pytest.fixture
def strict_block_rule() -> StandardBoundaryRule:
    """A rule that blocks 'medical' data from crossing from health to work."""
    config = BoundaryRuleConfig(
        name="test-health-to-work",
        from_domain="health",
        to_domain="work",
        direction="one-way",
        blocked_data_types=["medical", "prescription"],
    )
    return StandardBoundaryRule(config)
