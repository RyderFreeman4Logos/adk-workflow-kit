# Contributing to adk-workflow-kit

Thank you for contributing!

## Development Workflow

1. Check open feature issues and follow their priorities (`P0` -> `P1` -> `P2`).
2. Create a feature branch; direct work on `main` is blocked.
3. Install the repository hooks once with `just install-hooks`.
4. Use `just fmt`, `just lock-check`, `just check`, `just clippy`, and `just test` instead of invoking Cargo directly.
5. Run `just pre-commit-fast` before committing.
6. On the clean committed candidate, run `just quality-gates` once. The pre-push hook reuses its exact-tree receipt and requires a passing CSA review of `main...HEAD` or an exact-tree native receipt at `.csa/native-review.receipt`.
7. Open a pull request targeting `main`.
