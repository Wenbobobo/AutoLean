# AutoLean engineering rules

- The north star is open-problem research, but no result is promoted without a frozen
  statement contract, kernel verification, and semantic review.
- Builder owns statement fidelity. Prover owns proof search. They communicate only through
  versioned contracts and immutable artifacts.
- Keep mathematical, formal, and execution graphs distinct.
- Use `uv` and the scripts under `scripts/`; do not document long Windows-only commands.
- Do not add Anthropic or Claude providers, models, dependencies, examples, or fallbacks.
- Secrets are operator-owned references. Never copy host credentials into workspaces, logs,
  artifacts, fixtures, or custom endpoint configuration.
- A proof failure may emit a gap or contract-change request. It may never silently weaken a
  theorem statement.
