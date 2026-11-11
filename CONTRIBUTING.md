# Contributing to pyproxifier

Thank you for your interest in contributing to **pyproxifier**!

We welcome contributions of all kinds: bug fixes, new features, documentation improvements, and extra tests.

---

## Development Setup

`pyproxifier` uses [`uv`](https://github.com/astral-sh/uv) for fast, reproducible dependency management and Python environment orchestration.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/I1Kuz/pyproxifier.git
   cd pyproxifier
   ```

2. **Create virtual environment and install dependencies:**
   ```bash
   uv sync
   ```

---

## Verification & Quality Gates

Every pull request must pass the three quality gates before merging:

### 1. Static Type Checking (`basedpyright`)
The codebase strictly adheres to type safety with zero warnings or suppressed notes in `strict` mode:
```bash
uv run basedpyright
```

### 2. Architectural Boundary Verification (`import-linter`)
To prevent circular dependencies and maintain Domain-Driven Design (DDD) boundaries:
```bash
uv run lint-imports
```

### 3. Test Suite & Coverage (`pytest`)
All unit and integration tests must pass with 100% statement coverage:
```bash
uv run pytest --cov=pyproxifier --cov-report=term-missing
```

---

## Coding Standards

- **Strict Type Annotations**: All functions, methods, parameters, and return types must be fully annotated. Do not use untyped `Any` without explicit justification.
- **Maintain Documentation Integrity**: Preserve or update relevant docstrings explaining parameters, return values, and potential exceptions.
- **Pure IPC & Native APIs**: Do not reintroduce file-swapping or hard process termination where native Windows IPC mechanisms exist.
- **Deterministic Testing**: Unit tests should not rely on external networks or unmocked remote proxies. Use loopback `asyncio` servers for protocol handshake validations.

---

## Submitting a Pull Request

1. Fork the repository and create a feature branch (`git checkout -b feature/my-feature`).
2. Implement your changes along with corresponding tests.
3. Verify all checks pass locally (`basedpyright`, `lint-imports`, `pytest --cov`).
4. Commit your changes with clear, descriptive commit messages.
5. Push to your fork and submit a Pull Request to `main`.

