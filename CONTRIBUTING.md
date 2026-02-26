# Contributing to context-firewall

Thank you for your interest in contributing.

## License

By contributing, you agree your contributions are licensed under BSL 1.1.
See [LICENSE](./LICENSE) for details.

## Getting Started

Full contribution guidelines are coming soon. In the meantime:

1. Fork the repository and create a feature branch (`feature/your-feature`).
2. Follow the coding style described in [CLAUDE.md](./CLAUDE.md).
3. Ensure all changes respect the hard constraints in [FIRE_LINE.md](./FIRE_LINE.md).
4. Open a pull request against `main` with a clear description of the change and why it is needed.

## Core Rules

- TypeScript: strict mode, no `any`.
- Python: type hints on all function signatures, Pydantic for validation.
- No ML or LLM-based classification — keyword matching only.
- No automatic domain discovery.

## Questions

Open a GitHub Discussion or file an issue.
