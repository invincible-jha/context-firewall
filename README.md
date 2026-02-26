# context-firewall

**Domain isolation for AI agents** — prevent data leaking between work, personal, health, and financial contexts.

Part of the [Aumos OSS](https://github.com/muveraai/aumos-oss) suite (Phase 4, Project 4.2).

License: [Business Source License 1.1](./LICENSE)

---

## Why

AI agents operating across multiple life domains — answering work emails, booking doctor appointments, managing personal finances — must not bleed context between those domains. A health query should not surface in a work response. A financial detail should not leak into a personal chat log.

context-firewall enforces hard isolation boundaries at the data layer, before any crossing occurs.

---

## What It Is NOT

- Not an ML model or an LLM wrapper.
- Not a semantic classifier — classification is keyword-based and fully deterministic.
- Not an automatic domain discovery system — domains are declared by the operator.

See [FIRE_LINE.md](./FIRE_LINE.md) for the complete list of hard constraints.

---

## Domains (Built-In)

| Domain      | Sensitivity | Description                                   |
|-------------|-------------|-----------------------------------------------|
| `work`      | medium      | Professional communications, tasks, projects  |
| `personal`  | high        | Personal relationships, home, lifestyle       |
| `health`    | critical    | Medical, mental health, prescriptions         |
| `financial` | critical    | Banking, taxes, investments, credit           |

---

## TypeScript Quick Start

```bash
npm install @aumos/context-firewall
```

```typescript
import { ContextFirewall } from "@aumos/context-firewall";

const firewall = new ContextFirewall();

const decision = firewall.check(
  { text: "My blood pressure reading is 120/80" },
  "health",
  "work"
);

console.log(decision.allowed);  // false
console.log(decision.reason);   // "Boundary rule 'health->work' blocks this crossing"
```

---

## Python Quick Start

```bash
pip install context-firewall
```

```python
from context_firewall import ContextFirewall

firewall = ContextFirewall()

decision = firewall.check(
    data={"text": "My blood pressure reading is 120/80"},
    from_domain="health",
    to_domain="work",
)

print(decision.allowed)   # False
print(decision.reason)    # "Boundary rule 'health->work' blocks this crossing"
```

---

## Core API

### `ContextFirewall`

| Method                    | Description                                              |
|---------------------------|----------------------------------------------------------|
| `check(data, from, to)`   | Evaluate whether data may cross from one domain to another |
| `classify(data)`          | Return the most likely domain for a piece of data        |
| `addDomain(domain)`       | Register a custom domain                                 |
| `addBoundary(rule)`       | Register a custom boundary rule                          |

### `BoundaryRule`

```typescript
interface BoundaryRule {
  name: string;
  fromDomain: string;
  toDomain: string;
  direction: "one-way" | "bidirectional";
  allowedDataTypes: string[];
  blockedDataTypes: string[];
  evaluate(classification: DataClassification): boolean;
}
```

---

## Documentation

- [Domains](./docs/domains.md)
- [Boundary Rules](./docs/boundary-rules.md)
- [Classification](./docs/classification.md)

---

## Project Structure

```
context-firewall/
├── typescript/          TypeScript package (@aumos/context-firewall)
├── python/              Python package (context-firewall)
├── examples/            Usage examples
├── docs/                Detailed documentation
├── scripts/             Audit and maintenance scripts
├── FIRE_LINE.md         Hard constraints
└── CLAUDE.md            AI session context
```

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

Copyright (c) 2026 MuVeraAI Corporation. Business Source License 1.1.
