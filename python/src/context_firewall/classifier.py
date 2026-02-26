# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation

"""
Keyword-based data classifier for context-firewall.

FIRE LINE: Classification uses KEYWORD MATCHING only.
No ML, no LLM, no embeddings, no external API calls.
The classifier is fully deterministic and reproducible without GPU resources.
"""

from __future__ import annotations

from .types import DataClassification, DataPayload, KeywordRule

__all__ = [
    "DataClassifier",
    "DataClassifierOptions",
    "DEFAULT_KEYWORD_RULES",
]

# ---------------------------------------------------------------------------
# Default keyword rules
# ---------------------------------------------------------------------------

DEFAULT_KEYWORD_RULES: tuple[KeywordRule, ...] = (
    # --- Health domain ---
    KeywordRule(
        id="health-medical-general",
        domain="health",
        data_type="medical",
        keywords=[
            "patient", "doctor", "physician", "hospital", "clinic",
            "medical", "medicine", "treatment", "symptoms", "symptom",
            "illness", "disease", "condition", "surgery", "procedure",
            "referral", "immunization", "vaccination",
        ],
    ),
    KeywordRule(
        id="health-prescription",
        domain="health",
        data_type="prescription",
        keywords=[
            "prescription", "medication", "dosage", "mg", "tablet",
            "capsule", "pharmacy", "pharmacist", "refill", "drug",
            "antibiotic", "insulin", "inhaler", "ointment",
        ],
    ),
    KeywordRule(
        id="health-diagnosis",
        domain="health",
        data_type="diagnosis",
        keywords=[
            "diagnosis", "diagnosed", "prognosis", "icd", "icd-10", "icd-11",
            "cancer", "diabetes", "hypertension", "asthma", "allergy",
            "chronic", "acute", "disorder", "syndrome", "infection",
        ],
    ),
    KeywordRule(
        id="health-mental-health",
        domain="health",
        data_type="mental-health",
        keywords=[
            "therapy", "therapist", "psychiatrist", "psychologist",
            "counseling", "mental-health", "depression", "anxiety",
            "bipolar", "adhd", "ptsd", "ocd", "schizophrenia", "psychosis",
            "antidepressant", "anxiolytic", "ssri",
        ],
    ),
    KeywordRule(
        id="health-laboratory",
        domain="health",
        data_type="laboratory",
        keywords=[
            "lab-result", "blood-test", "urine-test", "biopsy",
            "pathology", "mri", "ct-scan", "x-ray", "ultrasound",
            "ecg", "ekg", "cholesterol", "glucose", "hemoglobin",
            "white-blood-cell", "red-blood-cell", "creatinine",
        ],
    ),
    KeywordRule(
        id="health-clinical",
        domain="health",
        data_type="clinical",
        keywords=[
            "ehr", "emr", "fhir", "hl7", "clinical-note",
            "discharge-summary", "nursing", "nurse", "ward", "icu",
            "emergency-room", "urgent-care", "inpatient", "outpatient",
            "telemedicine", "telehealth",
        ],
    ),
    # --- Financial domain ---
    KeywordRule(
        id="financial-banking",
        domain="financial",
        data_type="banking",
        keywords=[
            "bank", "account-number", "routing-number", "iban", "swift",
            "wire-transfer", "deposit", "withdrawal", "overdraft",
            "savings", "checking", "balance", "transaction", "statement",
        ],
    ),
    KeywordRule(
        id="financial-credit-card",
        domain="financial",
        data_type="credit-card",
        keywords=[
            "credit-card", "debit-card", "card-number", "cvv", "expiry",
            "visa", "mastercard", "amex", "american-express", "discover",
            "payment-card", "cardholder",
        ],
    ),
    KeywordRule(
        id="financial-tax",
        domain="financial",
        data_type="tax",
        keywords=[
            "tax-return", "irs", "hmrc", "w-2", "1099", "ein", "tin",
            "ssn", "social-security", "deduction", "filing",
            "taxable-income", "refund", "audit", "capital-gains",
        ],
    ),
    KeywordRule(
        id="financial-investment",
        domain="financial",
        data_type="investment",
        keywords=[
            "portfolio", "stock", "equity", "bond", "etf", "mutual-fund",
            "brokerage", "dividend", "401k", "ira", "roth", "ticker",
            "securities", "cryptocurrency", "bitcoin", "ethereum",
        ],
    ),
    KeywordRule(
        id="financial-salary",
        domain="financial",
        data_type="salary",
        keywords=[
            "salary", "payroll", "payslip", "wage", "compensation",
            "bonus", "commission", "income", "net-pay", "gross-pay",
            "pension", "401k-contribution",
        ],
    ),
    # --- Personal domain ---
    KeywordRule(
        id="personal-family",
        domain="personal",
        data_type="family",
        keywords=[
            "family", "spouse", "partner", "husband", "wife", "child",
            "children", "son", "daughter", "parent", "mother", "father",
            "sibling", "brother", "sister", "grandparent", "grandchild",
            "relative",
        ],
    ),
    KeywordRule(
        id="personal-relationship",
        domain="personal",
        data_type="relationship",
        keywords=[
            "relationship", "romantic", "dating", "marriage", "divorce",
            "engaged", "breakup", "intimate", "personal-life",
            "friend", "friendship",
        ],
    ),
    KeywordRule(
        id="personal-home-address",
        domain="personal",
        data_type="home-address",
        keywords=[
            "home-address", "residential", "street-address", "zip-code",
            "postal-code", "neighborhood", "apartment", "house",
            "home-phone", "home-email",
        ],
    ),
    KeywordRule(
        id="personal-contact",
        domain="personal",
        data_type="personal-contact",
        keywords=[
            "personal-email", "cell-phone", "personal-phone",
            "home-contact", "next-of-kin", "emergency-contact",
        ],
    ),
    # --- Work domain ---
    KeywordRule(
        id="work-professional",
        domain="work",
        data_type="professional",
        keywords=[
            "meeting", "agenda", "deadline", "project", "deliverable",
            "stakeholder", "client", "vendor", "invoice", "contract",
            "proposal", "presentation", "report", "sprint", "milestone",
            "kpi", "okr", "quarterly", "annual-review",
        ],
    ),
    KeywordRule(
        id="work-communication",
        domain="work",
        data_type="work-communication",
        keywords=[
            "slack", "teams", "email-thread", "work-email", "corporate",
            "colleagues", "manager", "employee", "hr", "human-resources",
            "onboarding", "offboarding", "performance-review",
        ],
    ),
)


# ---------------------------------------------------------------------------
# Classifier options
# ---------------------------------------------------------------------------


class DataClassifierOptions:
    """
    Configuration options for :class:`DataClassifier`.

    :param additional_rules: Extra keyword rules merged with (or replacing) built-in defaults.
    :param replace_default_rules: When ``True``, built-in rules are discarded.
    :param fallback_domain: Domain returned when no keywords match. Default: ``"work"``.
    """

    def __init__(
        self,
        additional_rules: list[KeywordRule] | None = None,
        replace_default_rules: bool = False,
        fallback_domain: str = "work",
    ) -> None:
        self.additional_rules: list[KeywordRule] = additional_rules or []
        self.replace_default_rules: bool = replace_default_rules
        self.fallback_domain: str = fallback_domain


# ---------------------------------------------------------------------------
# DataClassifier class
# ---------------------------------------------------------------------------


class DataClassifier:
    """
    Keyword-based data classifier.

    Scans a :data:`~context_firewall.types.DataPayload` for known keywords and
    returns the domain and data type(s) that best match. Classification is:

    - **Deterministic**: same input always produces same output.
    - **Auditable**: matched keywords are reported in the result.
    - **Transparent**: no model weights, no external API calls.

    FIRE LINE: This class must never call an LLM or use embedding-based similarity.
    """

    def __init__(self, options: DataClassifierOptions | None = None) -> None:
        opts = options or DataClassifierOptions()
        if opts.replace_default_rules:
            self._rules: tuple[KeywordRule, ...] = tuple(opts.additional_rules)
        else:
            self._rules = DEFAULT_KEYWORD_RULES + tuple(opts.additional_rules)
        self._fallback_domain: str = opts.fallback_domain

    def classify(self, data: DataPayload) -> DataClassification:
        """
        Classify a data payload by scanning all string values for keyword matches.

        The winning domain is the one with the most keyword hits across all its rules.
        Confidence is the ratio of matched keywords to total unique keywords in the
        winning domain's rules, capped at 1.0.

        :param data: The data payload to classify.
        :returns: A :class:`~context_firewall.types.DataClassification` result.
        """
        text_content = self._extract_text_content(data)
        normalised = text_content.lower()

        domain_hits: dict[str, int] = {}
        detected_types: set[str] = set()
        all_matched_keywords: list[str] = []

        for rule in self._rules:
            rule_matches: list[str] = []
            for keyword in rule.keywords:
                if self._keyword_matches(normalised, keyword.lower()):
                    rule_matches.append(keyword)

            if rule_matches:
                domain_hits[rule.domain] = domain_hits.get(rule.domain, 0) + len(rule_matches)
                detected_types.add(rule.data_type)
                all_matched_keywords.extend(rule_matches)

        if not domain_hits:
            return DataClassification(
                domain=self._fallback_domain,
                detected_types=[],
                matched_keywords=[],
                confidence=0.0,
            )

        winning_domain = max(domain_hits, key=lambda d: domain_hits[d])
        highest_hits = domain_hits[winning_domain]
        winning_keyword_count = self._count_keywords_for_domain(winning_domain)
        confidence = min(
            1.0,
            highest_hits / winning_keyword_count if winning_keyword_count > 0 else 0.0,
        )

        return DataClassification(
            domain=winning_domain,
            detected_types=list(detected_types),
            matched_keywords=list(set(all_matched_keywords)),
            confidence=confidence,
        )

    def get_rules(self) -> tuple[KeywordRule, ...]:
        """Return all active keyword rules (built-in + custom)."""
        return self._rules

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _extract_text_content(self, data: DataPayload) -> str:
        parts: list[str] = []
        self._collect_strings(data, parts)
        return " ".join(parts)

    def _collect_strings(self, value: object, parts: list[str]) -> None:
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            for item in value:
                self._collect_strings(item, parts)
        elif isinstance(value, dict):
            for val in value.values():
                self._collect_strings(val, parts)
        # int, float, bool, None — skip

    def _keyword_matches(self, normalised_text: str, keyword: str) -> bool:
        """
        Check whether *keyword* appears in *normalised_text*.
        Also checks with hyphens replaced by spaces for compound terms.
        """
        if self._contains_whole_word(normalised_text, keyword):
            return True
        spaced = keyword.replace("-", " ")
        if spaced != keyword and self._contains_whole_word(normalised_text, spaced):
            return True
        return False

    @staticmethod
    def _contains_whole_word(text: str, term: str) -> bool:
        """
        Check that *term* appears in *text* as a whole word.
        Word characters are ``[a-z0-9\\-_]``.
        """
        idx = text.find(term)
        if idx == -1:
            return False

        before = text[idx - 1] if idx > 0 else " "
        after_idx = idx + len(term)
        after = text[after_idx] if after_idx < len(text) else " "

        def is_word_char(char: str) -> bool:
            return char.isalnum() or char in ("-", "_")

        return not is_word_char(before) and not is_word_char(after)

    def _count_keywords_for_domain(self, domain: str) -> int:
        keywords: set[str] = set()
        for rule in self._rules:
            if rule.domain == domain:
                keywords.update(kw.lower() for kw in rule.keywords)
        return len(keywords)
