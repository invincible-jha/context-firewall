# Domains

A **domain** is a named isolation boundary representing a distinct life or operational context for an AI agent. Domains are static — they are declared by the operator or user at configuration time and are never inferred from data.

## Built-In Domains

| Name        | Sensitivity | Description                                                    |
|-------------|-------------|----------------------------------------------------------------|
| `work`      | medium      | Professional communications, tasks, projects, and business data |
| `personal`  | high        | Personal relationships, home, lifestyle, non-medical private data |
| `health`    | critical    | Medical records, prescriptions, diagnoses, mental health data  |
| `financial` | critical    | Banking, taxes, investments, credit, insurance, financial planning |

## Sensitivity Levels

| Level      | Meaning                                                        |
|------------|----------------------------------------------------------------|
| `low`      | Publicly available or non-sensitive data                       |
| `medium`   | Internal business data, some confidentiality expected          |
| `high`     | Significant PII present; GDPR personal data categories apply   |
| `critical` | Regulated data (HIPAA, PCI-DSS, GLBA, GDPR special categories) |

Sensitivity level influences how operators should configure boundary rules, but the firewall itself does not auto-block based on sensitivity alone — rules must be explicit.

## Adding a Custom Domain

### TypeScript

```typescript
import { ContextFirewall, Domain } from "@aumos/context-firewall";

const firewall = new ContextFirewall();

const legalDomain: Domain = {
  name: "legal",
  description: "Privileged legal communications and litigation documents",
  sensitivity: "critical",
  metadata: { regulatoryScope: "attorney-client-privilege" },
};

firewall.addDomain(legalDomain);
```

### Python

```python
from context_firewall import ContextFirewall, Domain

firewall = ContextFirewall()

legal_domain = Domain(
    name="legal",
    description="Privileged legal communications and litigation documents",
    sensitivity="critical",
    metadata={"regulatory_scope": "attorney-client-privilege"},
)

firewall.add_domain(legal_domain)
```

## Domain Name Rules

- Lowercase alphanumeric characters, hyphens (`-`), and underscores (`_`) only.
- Must start with a letter.
- Examples: `work`, `health`, `legal-contracts`, `r_and_d`.

## FIRE LINE

Domains are **never auto-discovered**. The firewall does not scan incoming data to create or suggest new domains. All domains must be explicitly declared. See [FIRE_LINE.md](../FIRE_LINE.md).
