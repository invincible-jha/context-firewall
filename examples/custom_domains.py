# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
Custom domains example.

Demonstrates how to define operator-specific domains beyond the built-in
four, register custom boundary rules, and extend the keyword classifier.

Run with: python examples/custom_domains.py
"""

from __future__ import annotations

from context_firewall import (
    BoundaryRuleConfig,
    ContextFirewall,
    ContextFirewallOptions,
    DataClassifier,
    DataClassifierOptions,
    Domain,
    KeywordRule,
    StandardBoundaryRule,
    create_boundary_rule,
)


def build_legal_domain() -> Domain:
    """Define a custom 'legal' domain for law-firm usage."""
    return Domain(
        name="legal",
        description="Privileged legal communications, contracts, litigation documents",
        sensitivity="critical",
        metadata={
            "category": "legal",
            "regulatory_scope": "attorney-client-privilege",
        },
    )


def build_research_domain() -> Domain:
    """Define a custom 'research' domain for a biotech company."""
    return Domain(
        name="research",
        description="Internal R&D, proprietary trial data, unpublished findings",
        sensitivity="high",
        metadata={
            "category": "research",
            "regulatory_scope": "trade-secret",
        },
    )


def build_legal_to_work_rule() -> StandardBoundaryRule:
    """Block privileged legal content from entering the general work domain."""
    return create_boundary_rule(
        BoundaryRuleConfig(
            name="legal->work",
            from_domain="legal",
            to_domain="work",
            direction="one-way",
            blocked_data_types=["privileged-communication", "litigation"],
        )
    )


def build_research_to_work_rule() -> StandardBoundaryRule:
    """Only allow non-sensitive research summaries into the work domain."""
    return create_boundary_rule(
        BoundaryRuleConfig(
            name="research->work",
            from_domain="research",
            to_domain="work",
            direction="one-way",
            allowed_data_types=["research-summary"],
            blocked_data_types=[],
        )
    )


def build_custom_classifier_options() -> DataClassifierOptions:
    """Add keyword rules for the custom domains."""
    return DataClassifierOptions(
        additional_rules=[
            KeywordRule(
                id="legal-privileged",
                domain="legal",
                data_type="privileged-communication",
                keywords=[
                    "attorney-client", "privileged", "counsel", "subpoena",
                    "deposition", "affidavit", "injunction", "lawsuit",
                    "litigation", "plaintiff", "defendant", "discovery",
                ],
            ),
            KeywordRule(
                id="legal-contract",
                domain="legal",
                data_type="litigation",
                keywords=[
                    "indemnification", "liability", "breach-of-contract",
                    "settlement", "arbitration", "mediation", "jurisdiction",
                ],
            ),
            KeywordRule(
                id="research-raw",
                domain="research",
                data_type="research-raw",
                keywords=[
                    "trial-data", "assay", "proprietary-compound",
                    "unpublished", "confidential-results", "ip-protected",
                ],
            ),
            KeywordRule(
                id="research-summary",
                domain="research",
                data_type="research-summary",
                keywords=[
                    "research-summary", "abstract", "literature-review",
                    "published-paper", "conference-poster",
                ],
            ),
        ]
    )


def main() -> None:
    print("=== context-firewall: Custom Domains Example ===\n")

    # Build the firewall with custom classifier options
    firewall = ContextFirewall(
        options=ContextFirewallOptions(
            classifier_options=build_custom_classifier_options(),
        )
    )

    # Register custom domains
    firewall.add_domain(build_legal_domain())
    firewall.add_domain(build_research_domain())

    # Register custom boundary rules
    firewall.add_boundary(build_legal_to_work_rule())
    firewall.add_boundary(build_research_to_work_rule())

    print(f"Registered domains    : {firewall.list_domains()}")
    print(f"Registered boundaries : {firewall.list_boundaries()}\n")

    # -----------------------------------------------------------------------
    # Test legal -> work with privileged content
    # -----------------------------------------------------------------------
    print("--- Legal (privileged) -> Work ---")
    privileged_doc: dict[str, object] = {
        "subject": "Re: attorney-client communication — deposition strategy",
        "body": "Per our privileged discussion, the subpoena requires a response by Friday.",
    }
    decision = firewall.check(data=privileged_doc, from_domain="legal", to_domain="work")
    print(f"  Allowed  : {decision.allowed}")
    print(f"  Reason   : {decision.reason}")
    print(f"  Blocked  : {decision.blocked_data_types}")
    print()

    # -----------------------------------------------------------------------
    # Test research -> work with raw trial data (not on allowlist)
    # -----------------------------------------------------------------------
    print("--- Research (raw trial data) -> Work ---")
    raw_data: dict[str, object] = {
        "dataset": "Proprietary-compound trial-data from Phase II — ip-protected. Unpublished.",
    }
    decision = firewall.check(data=raw_data, from_domain="research", to_domain="work")
    print(f"  Allowed  : {decision.allowed}")
    print(f"  Reason   : {decision.reason}")
    print(f"  Blocked  : {decision.blocked_data_types}")
    print()

    # -----------------------------------------------------------------------
    # Test research -> work with an approved summary
    # -----------------------------------------------------------------------
    print("--- Research (summary) -> Work ---")
    summary: dict[str, object] = {
        "text": "Research-summary: our published-paper confirms efficacy in the literature-review.",
    }
    decision = firewall.check(data=summary, from_domain="research", to_domain="work")
    print(f"  Allowed  : {decision.allowed}")
    print(f"  Reason   : {decision.reason}")
    print()

    # -----------------------------------------------------------------------
    # Classify samples from the custom domains
    # -----------------------------------------------------------------------
    print("--- classify() on custom domain data ---")
    samples: list[dict[str, object]] = [
        {"text": "The court issued an injunction. Our counsel advises settlement."},
        {"text": "The assay confirms the proprietary-compound is ip-protected."},
    ]
    for sample in samples:
        domain = firewall.classify(sample)
        print(f"  '{list(sample.values())[0]!r:.70}...' -> {domain}")


if __name__ == "__main__":
    main()
