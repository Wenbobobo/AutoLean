# Documentation Archive Index

Status: active archive policy; no evidence file moved in the first pass

The documentation set previously had several files claiming to be the current plan. The authority
map in [the documentation index](../README.md) now assigns one responsibility to each live file.
Historical documents remain at their existing paths until a machine link/dependency check proves
that moving them will not break repository or external review links.

## Historical snapshots

| Document | Historical role | Superseded for live ordering by | Move condition |
| --- | --- | --- | --- |
| [Phase 1 current route](../phase-1-plan.md) | Decision and sequencing snapshot dated 2026-07-25 | [Active execution board](../roadmap-next.md) | All incoming links updated and a redirect stub retained |
| [Phase 1 parallel execution](../phase-1-parallel-execution.md) | Work-package snapshot bound to `48b1290` on 2026-07-24 | [Active execution board](../roadmap-next.md) | All incoming links updated and a redirect stub retained |
| [Open questions](../open-questions.md) | Stable OQ identifiers and historical decisions | [Operator and authority worklist](../operator-and-authority-worklist.md) for actionable external work | Every open OQ mapped to an AUTH item or a stable specification |

Research reports, audit reports, meeting source material, preflight reports, and evidence ledgers are
not stale merely because a later decision exists. They remain source evidence and must not be moved
or deleted as routine cleanup.

## Safe move gate

Before any future `git mv` into this directory:

1. scan every Markdown link and code/test reference;
2. update repository-owned incoming links;
3. leave a short redirect at a path likely to have external links;
4. confirm that scripts and tests do not load the old path;
5. preserve Git history and all source/evidence bytes; and
6. run the documentation link check and public-readiness checks.

Temporary files and caches are governed by `.gitignore` and repository hygiene scripts, not by this
archive.
