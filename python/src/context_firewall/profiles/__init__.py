# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
Compliance profiles for context-firewall.

Provides static, policy-driven compliance checks for GDPR, HIPAA, and SOX.
All profiles enforce rules through deterministic evaluation -- no ML,
no LLM, no adaptive behaviour.
"""

from .gdpr import ComplianceResult, GDPRProfile, GDPRPurpose
from .hipaa import AccessorRole, EntityType, HIPAAProfile, PHICategory
from .sox import AgentRole, FinancialAction, SOXProfile

__all__ = [
    # GDPR
    "GDPRProfile",
    "GDPRPurpose",
    "ComplianceResult",
    # HIPAA
    "HIPAAProfile",
    "PHICategory",
    "AccessorRole",
    "EntityType",
    # SOX
    "SOXProfile",
    "FinancialAction",
    "AgentRole",
]
