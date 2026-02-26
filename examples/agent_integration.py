# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
Agent integration example.

Demonstrates how an AI agent orchestrator might use context-firewall
as a data-routing guardrail before passing context to a tool or sub-agent.

This example is intentionally framework-agnostic — no LLM SDK is imported.
The firewall operates as a pure domain-isolation layer.

Run with: python examples/agent_integration.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from context_firewall import ContextFirewall, FirewallDecision

# ---------------------------------------------------------------------------
# Simulated agent message types
# ---------------------------------------------------------------------------

AgentRole = Literal["work-assistant", "personal-assistant", "health-assistant", "finance-assistant"]

ROLE_TO_DOMAIN: dict[AgentRole, str] = {
    "work-assistant": "work",
    "personal-assistant": "personal",
    "health-assistant": "health",
    "finance-assistant": "financial",
}


@dataclass
class AgentMessage:
    """A message produced by one agent, addressed to another."""

    source_role: AgentRole
    target_role: AgentRole
    payload: dict[str, object]


@dataclass
class RoutingOutcome:
    """The result of the firewall check, plus the original message for logging."""

    message: AgentMessage
    decision: FirewallDecision

    def log_summary(self) -> str:
        status = "ALLOW" if self.decision.allowed else "BLOCK"
        blocked = (
            f", blocked_types={self.decision.blocked_data_types}"
            if not self.decision.allowed
            else ""
        )
        return (
            f"[{status}] {self.message.source_role} -> {self.message.target_role}"
            f" | rule={self.decision.applied_rule_name}{blocked}"
            f" | reason={self.decision.reason}"
        )


# ---------------------------------------------------------------------------
# AgentRouter — wraps ContextFirewall for agent message routing
# ---------------------------------------------------------------------------


class AgentRouter:
    """
    Wraps :class:`~context_firewall.ContextFirewall` to provide agent-level
    message routing with domain isolation enforcement.

    Before any message is forwarded from one agent to another, the firewall
    checks whether the payload's classified data types are permitted to cross
    the domain boundary between the two agents.
    """

    def __init__(self) -> None:
        self._firewall = ContextFirewall()

    def route(self, message: AgentMessage) -> RoutingOutcome:
        """
        Evaluate whether *message* may be forwarded from source to target.

        :param message: The agent message to evaluate.
        :returns: A :class:`RoutingOutcome` with full audit detail.
        :raises ValueError: If either role maps to an unregistered domain.
        """
        from_domain = ROLE_TO_DOMAIN[message.source_role]
        to_domain = ROLE_TO_DOMAIN[message.target_role]

        decision = self._firewall.check(
            data=message.payload,
            from_domain=from_domain,
            to_domain=to_domain,
        )
        return RoutingOutcome(message=message, decision=decision)


# ---------------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------------


def main() -> None:
    print("=== context-firewall: Agent Integration Example ===\n")

    router = AgentRouter()

    # Messages to evaluate
    messages: list[AgentMessage] = [
        # 1. Health assistant tries to pass medical context to work assistant
        AgentMessage(
            source_role="health-assistant",
            target_role="work-assistant",
            payload={
                "context": (
                    "Patient was diagnosed with hypertension. "
                    "Current medication: antihypertensive tablet 10mg daily."
                )
            },
        ),
        # 2. Finance assistant tries to pass banking details to work assistant
        AgentMessage(
            source_role="finance-assistant",
            target_role="work-assistant",
            payload={
                "summary": (
                    "Wire-transfer of $50,000 from checking account confirmed. "
                    "Routing-number verified."
                )
            },
        ),
        # 3. Work assistant passes meeting notes to personal assistant (no blocking rule)
        AgentMessage(
            source_role="work-assistant",
            target_role="personal-assistant",
            payload={
                "reminder": (
                    "Quarterly review meeting on Friday. Agenda: project milestone updates."
                )
            },
        ),
        # 4. Personal assistant tries to pass family data to work assistant
        AgentMessage(
            source_role="personal-assistant",
            target_role="work-assistant",
            payload={
                "note": "Family dinner with spouse and children at grandmother's house."
            },
        ),
        # 5. Health assistant passing health data to itself (same domain — allowed)
        AgentMessage(
            source_role="health-assistant",
            target_role="health-assistant",
            payload={
                "update": "EHR updated: lab-result for cholesterol within normal range."
            },
        ),
        # 6. Finance assistant to personal assistant (salary data)
        AgentMessage(
            source_role="finance-assistant",
            target_role="personal-assistant",
            payload={
                "notification": "Your payslip is ready. Gross-pay: $8,500. Net-pay: $6,200."
            },
        ),
    ]

    for message in messages:
        outcome = router.route(message)
        print(outcome.log_summary())
        print()

    print("=== Routing complete ===")


if __name__ == "__main__":
    main()
