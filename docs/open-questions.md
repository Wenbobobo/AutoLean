# Open Questions and Required Decisions

This is a decision register, not a backlog of optional polish. Items stay open until a named owner
records a decision and its evidence. Defaults below are conservative so work can continue without
silently broadening authority.

| ID | Decision needed | Conservative default while unresolved | Why it matters | Suggested owner | Status |
| --- | --- | --- | --- | --- | --- |
| OQ-001 | Who can freeze an L2/L3 statement and approve an open-conjecture release? | Only explicitly named independent reviewers; no promotion | Separates mathematical authority from agent output | Project owner plus domain reviewers | Open |
| OQ-002 | What is the exact external compatibility policy for contract schema versions? | Reject unrecognized versions/fields; no automatic migration | Prevents a serialized contract from changing meaning across workers | Contracts owner | Open |
| OQ-003 | Which source licenses and endpoint classes are permitted for textbook ingestion? | Do not send text to external models unless rights record explicitly allows it | Builder fidelity depends on legally usable, attributable source material | Rights reviewer | Open |
| OQ-004 | Which custom endpoints and model revisions are operator-approved? | Fake provider only; no automatic fallback | Prevents task-controlled routing and unbounded external egress | Provider operator | Open |
| OQ-005 | What is the canonical pinned OCI image, image registry trust policy, and Lean/mathlib attestation process? | Do not promote any host/Windows result as authoritative | Proof acceptance needs a reproducible Linux environment | Execution owner | Open |
| OQ-006 | How is external lean-eval-style comparator/workspace compatibility represented in a future bundle revision? | Do not claim external evaluator compatibility | Current V1 materializes locally but lacks an explicit portable comparator record | Contracts and verifier owners | Open |
| OQ-007 | What dashboard remote-access, authentication, retention, and export policy is acceptable? | Verified loopback-only read model; no public export | A dashboard can otherwise expose source, proof, or operational metadata | Dashboard/security owner | Local gate verified; remote policy open |
| OQ-008 | Has the HF incident been contained, and which credential rotations are complete? | Quarantine verified; treat archived credentials as exposed; do not migrate raw data | Recovery without rotation/private access is not incident closure | Dataset and credential owners | Local recovery complete; operator containment open |
| OQ-009 | Which sanitized AutoArchon concepts or artifacts, if any, are approved for migration? | Reimplement ideas only; no raw runtime/session/workspace import | Prevents old trust-boundary failures from returning through a backup | Migration/security reviewers | Open |
| OQ-010 | Which first Builder pilot source/domain has clear rights and expert availability? | Riemannian-connections proposal only; do not ingest or expand | Phase 2 needs calibrated statement fidelity, not merely available text | Builder lead plus experts | Proposal recorded; rights/expert gates open |
| OQ-011 | What is the open-problem portfolio and how are dependency-leverage claims reviewed? | Keep conjectures quarantined; do not announce a solution | Avoids optimizing a benchmark or a local lemma while overclaiming research progress | Scientific governance group | Open |
| OQ-012 | What are the approved model budget, concurrency, failure-circuit-breaker, and retention limits? | Durable threshold/cooldown defaults and small fixed test budgets; no external run | Thousands of workers require operational containment as well as correctness | Operations owner | Mechanism implemented; operator limits open |
| OQ-013 | Which FATE tasks belong to regression and comparison sets after stable hash ordering is frozen? | Use answer-free `benchmarks/fate-splits.v1.json`; comparison remains disjoint from regression | Prevents benchmark cherry-picking and suite overlap | Benchmark owner | Closed in split manifest V1 |
| OQ-014 | What is the policy for human override of a verifier rejection or a Builder freeze rejection? | No override; produce new evidence/revision | An undocumented override destroys the audit trail | Project governance | Open |
| OQ-015 | Which mTLS/ACL deployment and KMS/HSM owns the implemented verifier-gateway authority, and how is it isolated from proof workers? | Gateway protocol enabled; test-only HMAC and in-process transport cannot promote a result | The lease-bound software boundary is implemented, but a signer reachable through a raw or unauthenticated operation still collapses independent verification | Execution and security owners | Open |
| OQ-016 | Which egress proxy or provider-side account limit enforces the external model spend ceiling? | Client-side reservation is accounting only; do not make a hard-spend claim | Provider-reported usage arrives after remote traffic may already be accepted | Provider and operations owners | Open |

## Decisions that block promotion now

The following do not block local architecture coding, but they block any claim of a promoted,
networked, or open-problem result: OQ-001, OQ-003 through OQ-008, OQ-011, OQ-012, OQ-015, and
OQ-016.

## Decision record template

When resolving an item, add a short dated record below with:

    Decision: <what is approved or rejected>
    Owner: <accountable person or role>
    Evidence: <review, test, manifest, or incident reference>
    Scope: <where the decision applies>
    Expiry/review date: <when it must be reconsidered>

Do not place credential values, raw archive information, unredacted model prompts, or private
source excerpts in this register.
