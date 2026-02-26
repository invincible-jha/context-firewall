# Changelog

All notable changes to context-firewall will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Initial TypeScript and Python implementations of `ContextFirewall`
- Four built-in domains: `work`, `personal`, `health`, `financial`
- Keyword-based `DataClassifier` — no ML, no LLM dependency
- `DataInspector` for pre-crossing validation against `BoundaryRule` definitions
- `BoundaryRule` interface with `one-way` and `bidirectional` direction support
- `FirewallDecision` structured output with reason, matched rule, and blocked data types
- Provider-agnostic design — no model names hardcoded
- Pydantic-backed Python API mirroring the TypeScript surface
- Example scripts: basic isolation, custom domains, agent integration
- `FIRE_LINE.md` documenting hard constraints
- `fire-line-audit.sh` for automated constraint enforcement checks
