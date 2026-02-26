# CLAUDE.md — context-firewall

## Project Role
context-firewall is Project 4.2 in Phase 4 of the Aumos OSS suite.
It provides domain isolation for AI agents, preventing data leakage across work, personal, health, and financial contexts.

## Core Constraints (see FIRE_LINE.md for full details)
- Classification is keyword-based only. No ML. No LLM.
- Domains are statically configured. No auto-discovery.
- No cross-domain inference.
- No PWM integration.

## Forbidden Identifiers
The following identifiers must never appear in source code:
`progressLevel`, `promoteLevel`, `computeTrustScore`, `behavioralScore`,
`adaptiveBudget`, `optimizeBudget`, `predictSpending`, `detectAnomaly`,
`generateCounterfactual`, `PersonalWorldModel`, `MissionAlignment`,
`SocialTrust`, `CognitiveLoop`, `AttentionFilter`, `GOVERNANCE_PIPELINE`

## File Header Rule
Every source file must start with:
```
// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation
```
(Use `#` for Python files.)

## TypeScript Rules
- Strict mode. Never use `any`.
- Named exports only.
- Zod for runtime validation at public API boundaries.
- TSDoc comments on all exported symbols.

## Python Rules
- Type hints on every function signature.
- Pydantic models for all structured data.
- Named exports via `__all__` in `__init__.py`.

## Architecture
- ContextFirewall: main orchestrator
- Domain: describes an isolation boundary and its sensitivity
- BoundaryRule: defines what data types can cross between two domains
- DataClassifier: keyword-based classification engine
- DataInspector: pre-crossing validation

## Session Commands
- `/session-start` — recover context at the beginning of a session
- `/session-end` — persist context at the end of a session
