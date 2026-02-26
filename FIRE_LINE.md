# FIRE LINE — Hard Constraints for context-firewall

> The FIRE LINE defines absolute, non-negotiable boundaries for this project.
> Any contribution that crosses these lines will be rejected, regardless of intent.

---

## What This Project IS

- **Domain isolation enforcement** for AI agents operating across multiple life contexts (work, personal, health, financial).
- **Keyword-based classification** — deterministic, auditable, no model weights.
- **Static domain configuration** — domains are declared by the operator/user, never auto-discovered.
- **Boundary rule evaluation** — structured rules that decide whether a data crossing is allowed.

---

## Hard Constraints (Never Cross These)

### 1. No ML or LLM Classification
The `DataClassifier` uses keyword matching only.
Adding any embedding model, vector similarity, or LLM call to the classification path is **forbidden**.

Rationale: Classification must be deterministic, inspectable, and reproducible without external APIs or GPU resources.

### 2. No Cross-Domain Inference
A data item that matches a keyword from Domain A while being routed through Domain B stays classified under Domain B's context.
"work meeting about health insurance" is a **work** item, not a **health** item.

Rationale: Cross-context inference is precisely the leakage vector this firewall prevents.

### 3. No Automatic Domain Discovery
Domains are declared by the user via configuration. The firewall does not scan data to infer or create new domains.

Rationale: Automatic discovery requires ML and introduces non-determinism.

### 4. No Personal World Model (PWM) Integration
This library must not import, reference, or depend on any PWM-related module.

### 5. No Semantic / LLM-Powered Classification
No call to any external model API for the purpose of classifying data sensitivity or domain membership.

### 6. No Hardcoded Model Names
If any future extension needs an LLM for a non-classification feature, model names must come from caller-provided configuration.

---

## Audit

Run `scripts/fire-line-audit.sh` before every release to verify no forbidden identifiers or patterns have been introduced.
