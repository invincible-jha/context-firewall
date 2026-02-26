// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @module classifier
 * Keyword-based data classifier for context-firewall.
 *
 * FIRE LINE: Classification uses KEYWORD MATCHING only.
 * No ML, no LLM, no embeddings, no external API calls.
 * The classifier is fully deterministic and reproducible without GPU resources.
 */

import {
  DataClassification,
  DataPayload,
  KeywordRule,
  KeywordRuleSchema,
} from "./types.js";

// ---------------------------------------------------------------------------
// Default keyword rules
// ---------------------------------------------------------------------------

/**
 * Built-in keyword rules covering the four default domains.
 * Each rule maps a set of domain-specific keywords to a data type category.
 */
const DEFAULT_KEYWORD_RULES: ReadonlyArray<KeywordRule> = [
  // --- Health domain ---
  {
    id: "health-medical-general",
    domain: "health",
    dataType: "medical",
    keywords: [
      "patient",
      "doctor",
      "physician",
      "hospital",
      "clinic",
      "medical",
      "medicine",
      "treatment",
      "symptoms",
      "symptom",
      "illness",
      "disease",
      "condition",
      "surgery",
      "procedure",
      "referral",
      "appointment-health",
      "immunization",
      "vaccination",
    ],
  },
  {
    id: "health-prescription",
    domain: "health",
    dataType: "prescription",
    keywords: [
      "prescription",
      "medication",
      "dosage",
      "mg",
      "tablet",
      "capsule",
      "pharmacy",
      "pharmacist",
      "refill",
      "drug",
      "antibiotic",
      "insulin",
      "inhaler",
      "ointment",
    ],
  },
  {
    id: "health-diagnosis",
    domain: "health",
    dataType: "diagnosis",
    keywords: [
      "diagnosis",
      "diagnosed",
      "prognosis",
      "icd",
      "icd-10",
      "icd-11",
      "cancer",
      "diabetes",
      "hypertension",
      "asthma",
      "allergy",
      "chronic",
      "acute",
      "disorder",
      "syndrome",
      "infection",
    ],
  },
  {
    id: "health-mental-health",
    domain: "health",
    dataType: "mental-health",
    keywords: [
      "therapy",
      "therapist",
      "psychiatrist",
      "psychologist",
      "counseling",
      "mental-health",
      "depression",
      "anxiety",
      "bipolar",
      "adhd",
      "ptsd",
      "ocd",
      "schizophrenia",
      "psychosis",
      "antidepressant",
      "anxiolytic",
      "ssri",
      "session-therapy",
    ],
  },
  {
    id: "health-laboratory",
    domain: "health",
    dataType: "laboratory",
    keywords: [
      "lab-result",
      "blood-test",
      "urine-test",
      "biopsy",
      "pathology",
      "mri",
      "ct-scan",
      "x-ray",
      "ultrasound",
      "ecg",
      "ekg",
      "cholesterol",
      "glucose",
      "hemoglobin",
      "white-blood-cell",
      "red-blood-cell",
      "creatinine",
    ],
  },
  {
    id: "health-clinical",
    domain: "health",
    dataType: "clinical",
    keywords: [
      "ehr",
      "emr",
      "fhir",
      "hl7",
      "clinical-note",
      "discharge-summary",
      "nursing",
      "nurse",
      "ward",
      "icu",
      "emergency-room",
      "urgent-care",
      "inpatient",
      "outpatient",
      "telemedicine",
      "telehealth",
    ],
  },

  // --- Financial domain ---
  {
    id: "financial-banking",
    domain: "financial",
    dataType: "banking",
    keywords: [
      "bank",
      "account-number",
      "routing-number",
      "iban",
      "swift",
      "wire-transfer",
      "deposit",
      "withdrawal",
      "overdraft",
      "savings",
      "checking",
      "balance",
      "transaction",
      "statement",
    ],
  },
  {
    id: "financial-credit-card",
    domain: "financial",
    dataType: "credit-card",
    keywords: [
      "credit-card",
      "debit-card",
      "card-number",
      "cvv",
      "expiry",
      "visa",
      "mastercard",
      "amex",
      "american-express",
      "discover",
      "payment-card",
      "cardholder",
    ],
  },
  {
    id: "financial-tax",
    domain: "financial",
    dataType: "tax",
    keywords: [
      "tax-return",
      "irs",
      "hmrc",
      "w-2",
      "1099",
      "ein",
      "tin",
      "ssn",
      "social-security",
      "deduction",
      "filing",
      "taxable-income",
      "refund",
      "audit",
      "capital-gains",
    ],
  },
  {
    id: "financial-investment",
    domain: "financial",
    dataType: "investment",
    keywords: [
      "portfolio",
      "stock",
      "equity",
      "bond",
      "etf",
      "mutual-fund",
      "brokerage",
      "dividend",
      "401k",
      "ira",
      "roth",
      "ticker",
      "securities",
      "cryptocurrency",
      "bitcoin",
      "ethereum",
    ],
  },
  {
    id: "financial-salary",
    domain: "financial",
    dataType: "salary",
    keywords: [
      "salary",
      "payroll",
      "payslip",
      "wage",
      "compensation",
      "bonus",
      "commission",
      "income",
      "net-pay",
      "gross-pay",
      "pension",
      "401k-contribution",
    ],
  },

  // --- Personal domain ---
  {
    id: "personal-family",
    domain: "personal",
    dataType: "family",
    keywords: [
      "family",
      "spouse",
      "partner",
      "husband",
      "wife",
      "child",
      "children",
      "son",
      "daughter",
      "parent",
      "mother",
      "father",
      "sibling",
      "brother",
      "sister",
      "grandparent",
      "grandchild",
      "relative",
    ],
  },
  {
    id: "personal-relationship",
    domain: "personal",
    dataType: "relationship",
    keywords: [
      "relationship",
      "romantic",
      "dating",
      "marriage",
      "divorce",
      "engaged",
      "breakup",
      "intimate",
      "personal-life",
      "friend",
      "friendship",
    ],
  },
  {
    id: "personal-home-address",
    domain: "personal",
    dataType: "home-address",
    keywords: [
      "home-address",
      "residential",
      "street-address",
      "zip-code",
      "postal-code",
      "neighborhood",
      "apartment",
      "house",
      "home-phone",
      "home-email",
    ],
  },
  {
    id: "personal-contact",
    domain: "personal",
    dataType: "personal-contact",
    keywords: [
      "personal-email",
      "cell-phone",
      "personal-phone",
      "home-contact",
      "next-of-kin",
      "emergency-contact",
    ],
  },

  // --- Work domain ---
  {
    id: "work-professional",
    domain: "work",
    dataType: "professional",
    keywords: [
      "meeting",
      "agenda",
      "deadline",
      "project",
      "deliverable",
      "stakeholder",
      "client",
      "vendor",
      "invoice",
      "contract",
      "proposal",
      "presentation",
      "report",
      "sprint",
      "milestone",
      "kpi",
      "okr",
      "quarterly",
      "annual-review",
    ],
  },
  {
    id: "work-communication",
    domain: "work",
    dataType: "work-communication",
    keywords: [
      "slack",
      "teams",
      "email-thread",
      "work-email",
      "corporate",
      "colleagues",
      "manager",
      "employee",
      "hr",
      "human-resources",
      "onboarding",
      "offboarding",
      "performance-review",
    ],
  },
];

// ---------------------------------------------------------------------------
// Classifier options
// ---------------------------------------------------------------------------

/**
 * Configuration options for `DataClassifier`.
 */
export interface DataClassifierOptions {
  /**
   * Additional keyword rules to merge with (or replace) the built-in defaults.
   * If provided alongside `replaceDefaultRules: true`, only these rules are used.
   */
  readonly additionalRules?: ReadonlyArray<KeywordRule>;
  /**
   * When `true`, the built-in keyword rules are discarded and only
   * `additionalRules` are applied.
   * @default false
   */
  readonly replaceDefaultRules?: boolean;
  /**
   * The domain name to return when no keywords match.
   * @default "work"
   */
  readonly fallbackDomain?: string;
}

// ---------------------------------------------------------------------------
// DataClassifier class
// ---------------------------------------------------------------------------

/**
 * Keyword-based data classifier.
 *
 * Scans a `DataPayload` for known keywords and returns the domain and
 * data type(s) that best match. Classification is:
 * - Deterministic: same input always produces same output
 * - Auditable: matched keywords are reported in the result
 * - Transparent: no model weights, no external API calls
 *
 * FIRE LINE: This class must never call an LLM or use embedding-based similarity.
 */
export class DataClassifier {
  private readonly rules: ReadonlyArray<KeywordRule>;
  private readonly fallbackDomain: string;

  constructor(options: DataClassifierOptions = {}) {
    const {
      additionalRules = [],
      replaceDefaultRules = false,
      fallbackDomain = "work",
    } = options;

    // Validate all user-supplied rules
    const validatedAdditional = additionalRules.map((rule) =>
      KeywordRuleSchema.parse(rule)
    );

    this.rules = replaceDefaultRules
      ? validatedAdditional
      : [...DEFAULT_KEYWORD_RULES, ...validatedAdditional];

    this.fallbackDomain = fallbackDomain;
  }

  /**
   * Classify a `DataPayload` by scanning all string values for keyword matches.
   *
   * The winning domain is the one with the most keyword hits across all its rules.
   * Confidence is the ratio of matched keywords to total unique keywords checked,
   * capped at 1.0.
   *
   * @param data - The data payload to classify
   * @returns A `DataClassification` result with domain, detected types, matched keywords, and confidence
   */
  classify(data: DataPayload): DataClassification {
    const textContent = this.extractTextContent(data);
    const normalizedText = textContent.toLowerCase();

    // Accumulate hits per domain and per data type
    const domainHits = new Map<string, number>();
    const detectedTypeSet = new Set<string>();
    const allMatchedKeywords: string[] = [];

    for (const rule of this.rules) {
      const ruleMatches: string[] = [];

      for (const keyword of rule.keywords) {
        if (this.keywordMatches(normalizedText, keyword.toLowerCase())) {
          ruleMatches.push(keyword);
        }
      }

      if (ruleMatches.length > 0) {
        const currentHits = domainHits.get(rule.domain) ?? 0;
        domainHits.set(rule.domain, currentHits + ruleMatches.length);
        detectedTypeSet.add(rule.dataType);
        allMatchedKeywords.push(...ruleMatches);
      }
    }

    if (domainHits.size === 0) {
      return {
        domain: this.fallbackDomain,
        detectedTypes: [],
        matchedKeywords: [],
        confidence: 0,
      };
    }

    // Select the domain with the highest hit count
    let winningDomain = this.fallbackDomain;
    let highestHits = 0;

    for (const [domain, hits] of domainHits) {
      if (hits > highestHits) {
        highestHits = hits;
        winningDomain = domain;
      }
    }

    // Compute confidence: matched keywords / total keywords in winning domain's rules
    const winningDomainKeywordCount = this.countKeywordsForDomain(
      winningDomain
    );
    const confidence = Math.min(
      1,
      winningDomainKeywordCount > 0 ? highestHits / winningDomainKeywordCount : 0
    );

    return {
      domain: winningDomain,
      detectedTypes: Array.from(detectedTypeSet),
      matchedKeywords: Array.from(new Set(allMatchedKeywords)),
      confidence,
    };
  }

  /**
   * Return all active keyword rules (built-in + custom).
   */
  getRules(): ReadonlyArray<KeywordRule> {
    return this.rules;
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Extract all string values from a data payload, recursively flattening
   * nested objects and arrays. No ML is used here — pure string extraction.
   */
  private extractTextContent(data: DataPayload): string {
    const parts: string[] = [];
    this.collectStrings(data, parts);
    return parts.join(" ");
  }

  private collectStrings(value: unknown, parts: string[]): void {
    if (typeof value === "string") {
      parts.push(value);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        this.collectStrings(item, parts);
      }
    } else if (value !== null && typeof value === "object") {
      for (const val of Object.values(value as Record<string, unknown>)) {
        this.collectStrings(val, parts);
      }
    }
    // Numbers, booleans, null, undefined — skip
  }

  /**
   * Check whether a keyword appears in the normalised text.
   * Matches whole words and hyphenated compound terms.
   * Uses a simple word-boundary check without regex to stay lightweight.
   */
  private keywordMatches(normalizedText: string, keyword: string): boolean {
    // For compound keywords (e.g. "blood-test"), replace hyphens with spaces
    // and also check hyphenated form, so both "blood test" and "blood-test" match.
    const spaced = keyword.replace(/-/g, " ");
    return (
      this.containsWholeWord(normalizedText, keyword) ||
      (spaced !== keyword && this.containsWholeWord(normalizedText, spaced))
    );
  }

  /**
   * Check that a `term` appears in `text` as a whole word (not mid-word).
   * Word characters are `[a-z0-9]`. Hyphens are treated as word characters
   * for compound terms.
   */
  private containsWholeWord(text: string, term: string): boolean {
    const index = text.indexOf(term);
    if (index === -1) return false;

    const before = index > 0 ? text[index - 1] : " ";
    const after =
      index + term.length < text.length ? text[index + term.length] : " ";

    const isWordChar = (char: string): boolean =>
      /[a-z0-9\-_]/.test(char);

    return !isWordChar(before ?? "") && !isWordChar(after ?? "");
  }

  /**
   * Count the total number of unique keywords defined across all rules
   * for a given domain.
   */
  private countKeywordsForDomain(domain: string): number {
    const keywords = new Set<string>();
    for (const rule of this.rules) {
      if (rule.domain === domain) {
        for (const kw of rule.keywords) {
          keywords.add(kw.toLowerCase());
        }
      }
    }
    return keywords.size;
  }
}
