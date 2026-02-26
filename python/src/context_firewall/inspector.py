# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
DataInspector — validates data against boundary rules before crossing.

The inspector takes a DataClassification and a BoundaryRule and produces
a detailed InspectionResult listing any violations.
It is called internally by ContextFirewall.check and can also be called
directly for diagnostic purposes.
"""

from __future__ import annotations

from .boundary import StandardBoundaryRule
from .types import DataClassification, InspectionResult, InspectionViolation

__all__ = ["DataInspector"]


class DataInspector:
    """
    Validates a :class:`~context_firewall.types.DataClassification` result
    against a :class:`~context_firewall.boundary.StandardBoundaryRule`.

    The inspector evaluates each detected data type against:

    1. The blocked list — any match is a violation.
    2. The allowed list — if non-empty, a type not on the list is a violation.

    The inspector does not make the final allow/deny decision; that remains with
    :meth:`~context_firewall.firewall.ContextFirewall.check`. The inspector's
    role is to provide structured violation detail for logging and auditing.
    """

    def inspect(
        self,
        classification: DataClassification,
        rule: StandardBoundaryRule,
    ) -> InspectionResult:
        """
        Inspect a classification result against a boundary rule.

        :param classification: The result of :meth:`DataClassifier.classify`.
        :param rule: The boundary rule governing the crossing.
        :returns: A structured :class:`~context_firewall.types.InspectionResult`.
        """
        violations: list[InspectionViolation] = []
        blocked_set = set(rule.blocked_data_types)
        allowed_set = set(rule.allowed_data_types)

        for detected_type in classification.detected_types:
            keywords_for_type = list(classification.matched_keywords)

            # 1. Blocked list check (takes priority)
            if detected_type in blocked_set:
                violations.append(
                    InspectionViolation(
                        data_type=detected_type,
                        reason="explicitly-blocked",
                        matched_keywords=keywords_for_type,
                    )
                )
                continue  # No need to check allowlist

            # 2. Allowlist check (only when allowlist is non-empty)
            if allowed_set and detected_type not in allowed_set:
                violations.append(
                    InspectionViolation(
                        data_type=detected_type,
                        reason="not-in-allowlist",
                        matched_keywords=keywords_for_type,
                    )
                )

        return InspectionResult(
            passed=len(violations) == 0,
            violations=violations,
            rule_name=rule.name,
        )

    def is_data_type_permitted(
        self,
        data_type: str,
        rule: StandardBoundaryRule,
    ) -> bool:
        """
        Determine whether a specific data type is permitted under the given rule.
        Useful for quick pre-checks in hot paths.

        :param data_type: The data type to check.
        :param rule: The boundary rule to evaluate against.
        :returns: ``True`` if the data type is permitted to cross.
        """
        if data_type in rule.blocked_data_types:
            return False
        if rule.allowed_data_types and data_type not in rule.allowed_data_types:
            return False
        return True

    def extract_blocked_types(self, result: InspectionResult) -> list[str]:
        """
        Summarise the blocked data types found in an :class:`~context_firewall.types.InspectionResult`.

        :param result: The inspection result to summarise.
        :returns: List of data type strings that were blocked.
        """
        return [v.data_type for v in result.violations]
