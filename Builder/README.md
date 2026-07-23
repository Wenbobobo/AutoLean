# AutoLean Builder

`autolean-builder` owns statement fidelity. It turns reviewed source records into a frozen
`StatementContractV1` and an immutable `FormalizationTaskBundleV1`; it never invokes a model,
executes Lean, or accepts proof output.

The freeze gate requires source and rights review, resolved blocking ambiguity, independent
formalization candidates, reverse rendering, mutation evidence, and role-appropriate signoff.
A later statement change produces a new revision, never mutates a bundle already handed to the
Prover.

`ExperienceRetriever` supplies statement-conversion roles with deterministic, content-addressed
advisory context. It filters by role, domain, formal-graph frontier, exact rights scope, endpoint,
item budget, and token budget. Retrieved successes, failures, and gaps remain untrusted evidence;
they cannot edit a contract or satisfy a freeze gate. See
[`builder-experience-retrieval.md`](../docs/builder-experience-retrieval.md).

`StatementFidelityHarness` is the only high-level statement-conversion path. It binds permitted
source excerpts, normalized mathematics, two or more independent candidates, reverse renderings,
semantic obligations, the required mutation suite, and an independent expert verdict into one
canonical evidence artifact. `freeze_contract` accepts that complete evaluation rather than
caller-assembled Boolean checks.

See [the Harness protocol](../docs/builder-fidelity-harness.md) for the automatic-versus-expert
decision boundary and the remaining reviewer-authentication requirement. The proposed first
chapter-scale calibration is the rights-gated
[Riemannian-connections pilot](../docs/domain-pilot-selection.md); no textbook prose has been
ingested.
