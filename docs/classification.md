# Classification

The `DataClassifier` scans a data payload for known keywords and maps the payload to a domain and a set of data type categories. Classification is the first step in every `ContextFirewall.check` call.

## FIRE LINE

**Classification uses keyword matching only.** No ML model, no LLM, no embedding similarity, no external API calls. The classifier is fully deterministic: the same payload always produces the same classification, regardless of environment or time.

See [FIRE_LINE.md](../FIRE_LINE.md) for the complete list of hard constraints.

## How It Works

1. All string values in the `DataPayload` are extracted and concatenated into a single text string (recursively through nested objects and arrays).
2. The normalised (lowercased) text is scanned against every `KeywordRule`.
3. Matching keywords are counted per domain. The domain with the most hits wins.
4. `confidence` is computed as `matched_keywords / total_keywords_in_winning_domain`, capped at 1.0.
5. All detected data types (from all matching rules, across all domains) are reported.

## Keyword Matching

- Case-insensitive.
- Whole-word boundary matching: `"diagnosis"` will not match inside `"misdiagnosis"`.
- Compound keywords support both hyphenated and spaced forms: `"blood-test"` matches `"blood-test"` and `"blood test"`.

## Cross-Domain Keyword Behaviour

When a payload contains keywords from multiple domains, **all matching data types are reported** in `detectedTypes`, but the **winning domain** is the one with the highest keyword hit count. The boundary rule for the requested crossing evaluates against the full `detectedTypes` list.

Example: `"work meeting about health insurance"` — the word `insurance` may trigger a financial rule, but `meeting` triggers more work rules. The winning domain is `work`. However, if the rule for `work->personal` blocks `insurance-financial`, the crossing may still be denied.

This is intentional: the firewall errs on the side of caution when multiple domains' keywords appear in a single payload.

## Default Keyword Rules

| Rule ID                    | Domain     | Data Type            | Example Keywords                              |
|----------------------------|------------|----------------------|-----------------------------------------------|
| `health-medical-general`   | health     | medical              | patient, doctor, hospital, treatment          |
| `health-prescription`      | health     | prescription         | prescription, medication, dosage, pharmacy    |
| `health-diagnosis`         | health     | diagnosis            | diagnosis, cancer, diabetes, hypertension     |
| `health-mental-health`     | health     | mental-health        | therapy, depression, anxiety, psychiatrist    |
| `health-laboratory`        | health     | laboratory           | blood-test, mri, cholesterol, glucose         |
| `health-clinical`          | health     | clinical             | ehr, emr, fhir, inpatient, telemedicine       |
| `financial-banking`        | financial  | banking              | bank, iban, wire-transfer, balance            |
| `financial-credit-card`    | financial  | credit-card          | credit-card, cvv, visa, mastercard            |
| `financial-tax`            | financial  | tax                  | tax-return, irs, w-2, 1099, capital-gains     |
| `financial-investment`     | financial  | investment           | portfolio, stock, 401k, cryptocurrency        |
| `financial-salary`         | financial  | salary               | salary, payroll, payslip, bonus               |
| `personal-family`          | personal   | family               | family, spouse, children, mother, father      |
| `personal-relationship`    | personal   | relationship         | relationship, marriage, divorce, friendship   |
| `personal-home-address`    | personal   | home-address         | home-address, residential, zip-code           |
| `personal-contact`         | personal   | personal-contact     | personal-email, cell-phone, emergency-contact |
| `work-professional`        | work       | professional         | meeting, deadline, project, deliverable, kpi  |
| `work-communication`       | work       | work-communication   | slack, teams, manager, hr, performance-review |

## Adding Custom Keyword Rules

### TypeScript

```typescript
import { ContextFirewall, ContextFirewallOptions } from "@aumos/context-firewall";
import type { KeywordRule } from "@aumos/context-firewall";

const legalRule: KeywordRule = {
  id: "legal-privileged",
  domain: "legal",
  dataType: "privileged-communication",
  keywords: ["attorney-client", "privileged", "counsel", "subpoena", "deposition"],
};

const firewall = new ContextFirewall({
  classifierOptions: {
    additionalRules: [legalRule],
  },
});
```

### Python

```python
from context_firewall import (
    ContextFirewall,
    ContextFirewallOptions,
    DataClassifierOptions,
    KeywordRule,
)

legal_rule = KeywordRule(
    id="legal-privileged",
    domain="legal",
    data_type="privileged-communication",
    keywords=["attorney-client", "privileged", "counsel", "subpoena", "deposition"],
)

firewall = ContextFirewall(
    options=ContextFirewallOptions(
        classifier_options=DataClassifierOptions(additional_rules=[legal_rule])
    )
)
```

## Replacing Default Rules

Set `replaceDefaultRules: true` (TypeScript) or `replace_default_rules=True` (Python) in the classifier options to discard all built-in keyword rules and operate with your own rule set exclusively.

## classify() Standalone

`ContextFirewall.classify(data)` returns just the winning domain name as a string, without triggering any rule evaluation. Use this for logging, routing metadata, or pre-filtering before calling `check()`.
