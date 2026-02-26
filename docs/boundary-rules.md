# Boundary Rules

A **boundary rule** specifies which data types may or may not cross between two domains. Rules are the enforcement mechanism of the firewall — classification tells the firewall what a piece of data contains, and boundary rules tell it whether that data is allowed to move.

## Built-In Rules

| Rule Name              | From       | To         | Direction | Blocked Types                                          |
|------------------------|------------|------------|-----------|--------------------------------------------------------|
| `health->work`         | health     | work       | one-way   | medical, prescription, diagnosis, mental-health, clinical, laboratory |
| `financial->work`      | financial  | work       | one-way   | banking, credit-card, tax, investment, insurance-financial, salary |
| `health->personal`     | health     | personal   | one-way   | medical, prescription, diagnosis, mental-health, clinical, laboratory |
| `financial->personal`  | financial  | personal   | one-way   | banking, credit-card, tax, investment, salary          |
| `personal->work`       | personal   | work       | one-way   | family, relationship, home-address, personal-contact   |

## Evaluation Logic

For each detected data type in the classification result:

1. **Blocked list check**: If the type is in `blockedDataTypes`, the crossing is denied.
2. **Allowed list check**: If `allowedDataTypes` is non-empty and the type is not on the list, the crossing is denied.
3. **Open rule**: If both lists are empty, the crossing is permitted.

A single violation is sufficient to block the entire crossing.

## Direction

- `one-way`: enforced only from `fromDomain` to `toDomain`.
- `bidirectional`: enforced in both directions. The rule is indexed under both `"A->B"` and `"B->A"` keys.

## Open Boundaries

If no rule is registered for a given `from -> to` pair, the crossing is permitted by default. Operators who want a closed-by-default posture should register an empty-allowlist rule for every domain pair they care about.

## Adding a Custom Rule

### TypeScript

```typescript
import { ContextFirewall, createBoundaryRule } from "@aumos/context-firewall";

const firewall = new ContextFirewall();

firewall.addBoundary(createBoundaryRule({
  name: "legal->work",
  fromDomain: "legal",
  toDomain: "work",
  direction: "one-way",
  allowedDataTypes: [],
  blockedDataTypes: ["privileged-communication", "litigation"],
}));
```

### Python

```python
from context_firewall import (
    ContextFirewall,
    BoundaryRuleConfig,
    create_boundary_rule,
)

firewall = ContextFirewall()

rule = create_boundary_rule(BoundaryRuleConfig(
    name="legal->work",
    from_domain="legal",
    to_domain="work",
    direction="one-way",
    blocked_data_types=["privileged-communication", "litigation"],
))

firewall.add_boundary(rule)
```

## Custom Evaluate Logic

To override the default evaluation logic, implement the `BoundaryRule` protocol (TypeScript) or subclass `StandardBoundaryRule` (Python) and override the `evaluate` / `evaluate` method.

### TypeScript (custom evaluate)

```typescript
import type { BoundaryRule, DataClassification } from "@aumos/context-firewall";

const strictRule: BoundaryRule = {
  name: "health->any",
  fromDomain: "health",
  toDomain: "work",
  direction: "one-way",
  allowedDataTypes: [],
  blockedDataTypes: [],
  evaluate(classification: DataClassification): boolean {
    // Custom logic: block if confidence in health domain exceeds 0.1
    return classification.domain !== "health" || classification.confidence < 0.1;
  },
};
```

### Python (custom evaluate)

```python
from context_firewall import StandardBoundaryRule, BoundaryRuleConfig, DataClassification

class StrictHealthRule(StandardBoundaryRule):
    def evaluate(self, classification: DataClassification) -> bool:
        # Block if confidence in health domain exceeds 0.1
        return classification.domain != "health" or classification.confidence < 0.1
```
