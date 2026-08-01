# iFEM Unknown-Only Classification Triage v1

## Purpose

This is a source-free, read-only projection of the current 21-node iFEM
prerequisite denominator.  It is intentionally smaller than the prerequisite
census: every output node is fixed to `unknown`, even when a candidate Lean
declaration is visible under one or more pinned singleton imports.

Candidate visibility answers only this mechanical question: whether the name
listed in the frozen census plan appears as present in a profile's public
observation.  It does **not** answer whether that declaration formalizes the
mathematical concept, has the intended type, is sufficient for a theorem, or
can be used in a statement contract.

## Boundary

The artifact contains only:

- denominator node ID, source order, and discovery node kind;
- non-semantic profile IDs where at least one candidate name was visible;
- source-free structural case IDs and risk families;
- the critical-restriction marker; and
- exact file/content hashes for its evidence inputs.

It never contains textbook text, source spans, candidate Lean names, Lean
types, imports, prompts, model input, a statement contract, or a proof task.
All authority flags are `false`; `freeze_statement()` and
`handoff_to_prover()` always raise.

## Exact Replay Boundary

The triage command loads and validates these supplied inputs:

1. the candidate dependency graph;
2. the prerequisite census plan and result;
3. the redacted pinned-profile public summary;
4. the structural role-probe corpus, including its embedded catalog; and
5. a P2-08 readiness decision.

It also deterministically rebuilds the pinned profile plan from the supplied
census-plan path.  The summary must bind that exact rebuilt plan and candidate
vocabulary.  The structural catalog and corpus must replay against the graph.
The readiness decision must replay from the exact census plan/result without
profile evidence that is unavailable at this public boundary.

The raw P2-07 profile-plan file is not one of the six triage inputs.  Its
`plan_file_sha256`, as declared inside the public summary, is therefore never
copied into triage evidence.  The triage records the rebuilt profile plan's
content hash and the public summary file/content hashes only; it does not make
a false file-identity claim for an unread file.

Consequently, the old readiness decision that binds census result `d39d...`
cannot be combined with the candidate graph that binds `af4a...`.  The
graph-chain successor decision binds `af4a...` and is the default input.  The
tool fails on a mismatch rather than selecting an artifact from either chain.

## Command

Create an immutable local output with the repository's pinned environment:

```powershell
uv run --frozen python scripts/ifem_classification_triage.py `
  --out .cache/ifem-classification-triage.v1.json
```

The command prints only the output content hash.  An existing output path is
accepted only when its bytes are identical; it is never overwritten.

## Loading and Provenance

`load_ifem_unknown_only_classification_triage()` checks only that a saved
artifact is canonically rendered, has the required source-free shape, and
matches its own content hash.  That is sufficient for inspection, but it is
not a claim about which external files produced the artifact.

Any consumer that depends on exact input identity must call
`verify_ifem_unknown_only_classification_triage_against_paths()` with the six
paths it relies on.  The verifier independently rebuilds the projection and
requires byte-level model equality with the supplied artifact.  Artifact
creation is deliberately exposed only through
`materialize_ifem_unknown_only_classification_triage_from_paths_once()`, which
performs that replay before it writes immutable output.  A rehashed artifact
with fabricated evidence file hashes can be parsed for inspection, but fails
this path-based provenance verification.

## What This Does Not Close

This artifact does not close any Builder fidelity gate.  In particular, it
does not replace the census's `IFEMNodeClassificationEvidenceV1`, a source
rights decision, a semantic review, canonical-type verification, adapter
compilation, a frozen statement contract, Lean kernel verification, or a
Prover handoff.  It is a snapshot-consistency aid for later multi-agent work,
not evidence that any iFEM proposition was formalized correctly.

## Regression Coverage

Focused tests cover a coherent `af4a...` chain, the real `d39...` fork,
candidate-graph and candidate-set drift, profile-plan drift, corpus/catalog
drift, rehashed readiness tampering, non-`unknown` output rejection,
deterministic input bindings, and forbidden freeze/handoff methods.
