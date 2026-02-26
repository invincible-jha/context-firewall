# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
Basic isolation example.

Demonstrates the default four-domain setup and the built-in boundary rules.
Run with: python examples/basic_isolation.py
"""

from __future__ import annotations

from context_firewall import ContextFirewall


def main() -> None:
    firewall = ContextFirewall()

    print("=== context-firewall: Basic Isolation Example ===\n")
    print(f"Registered domains : {firewall.list_domains()}")
    print(f"Registered boundaries: {firewall.list_boundaries()}\n")

    # -----------------------------------------------------------------------
    # Scenario 1: Health data attempting to cross into work domain
    # -----------------------------------------------------------------------
    print("--- Scenario 1: Health -> Work ---")
    health_data: dict[str, object] = {
        "text": "Patient blood pressure reading is 140/90. Doctor prescribed medication."
    }
    decision = firewall.check(data=health_data, from_domain="health", to_domain="work")
    print(f"  Allowed  : {decision.allowed}")
    print(f"  Reason   : {decision.reason}")
    print(f"  Blocked  : {decision.blocked_data_types}")
    print(f"  Rule     : {decision.applied_rule_name}")
    print()

    # -----------------------------------------------------------------------
    # Scenario 2: Work data crossing to personal domain (no rule — open boundary)
    # -----------------------------------------------------------------------
    print("--- Scenario 2: Work -> Personal (no blocking rule configured) ---")
    work_data: dict[str, object] = {
        "subject": "Q3 project milestone review",
        "body": "Please review the deliverable before the deadline.",
    }
    decision = firewall.check(data=work_data, from_domain="work", to_domain="personal")
    print(f"  Allowed  : {decision.allowed}")
    print(f"  Reason   : {decision.reason}")
    print()

    # -----------------------------------------------------------------------
    # Scenario 3: Financial data crossing to work domain
    # -----------------------------------------------------------------------
    print("--- Scenario 3: Financial -> Work ---")
    financial_data: dict[str, object] = {
        "text": "Your bank account balance is $12,450. Recent wire-transfer of $2,000 processed."
    }
    decision = firewall.check(data=financial_data, from_domain="financial", to_domain="work")
    print(f"  Allowed  : {decision.allowed}")
    print(f"  Reason   : {decision.reason}")
    print(f"  Blocked  : {decision.blocked_data_types}")
    print()

    # -----------------------------------------------------------------------
    # Scenario 4: Personal data crossing to work domain
    # -----------------------------------------------------------------------
    print("--- Scenario 4: Personal -> Work ---")
    personal_data: dict[str, object] = {
        "note": "Remember to call mother. Family dinner on Sunday.",
    }
    decision = firewall.check(data=personal_data, from_domain="personal", to_domain="work")
    print(f"  Allowed  : {decision.allowed}")
    print(f"  Reason   : {decision.reason}")
    print(f"  Blocked  : {decision.blocked_data_types}")
    print()

    # -----------------------------------------------------------------------
    # Scenario 5: Same-domain (always allowed)
    # -----------------------------------------------------------------------
    print("--- Scenario 5: Health -> Health (same domain) ---")
    clinical_note: dict[str, object] = {
        "note": "Patient discharged after successful surgery. Follow-up in 2 weeks."
    }
    decision = firewall.check(data=clinical_note, from_domain="health", to_domain="health")
    print(f"  Allowed  : {decision.allowed}")
    print(f"  Reason   : {decision.reason}")
    print()

    # -----------------------------------------------------------------------
    # Scenario 6: Classify convenience method
    # -----------------------------------------------------------------------
    print("--- Scenario 6: classify() convenience ---")
    samples: list[dict[str, object]] = [
        {"text": "My prescription for insulin needs refilling."},
        {"text": "Please review the project proposal before our meeting."},
        {"text": "My IBAN for the wire-transfer is DE89..."},
        {"text": "Family reunion is next weekend at grandmother's house."},
    ]
    for sample in samples:
        domain = firewall.classify(sample)
        print(f"  '{list(sample.values())[0]!r:.60}...' -> {domain}")


if __name__ == "__main__":
    main()
