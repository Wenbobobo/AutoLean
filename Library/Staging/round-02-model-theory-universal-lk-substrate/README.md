# Target-Free UniversalLK Substrate Preflight

This directory is a staged source split for the accepted
`library-substrate-v1` architecture.  It is not a selected Builder pilot, a
frozen statement contract, a compiled Library runtime image, an OCI receipt,
or a promoted proof result.

The retained aggregate modules remain immutable historical evidence and are
forbidden imports here:

- `Library/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK.lean`
- `Library/AutoLeanLibrary/Fixtures/ModelTheory/Packet.lean`

The staged sources deliberately retain the historical namespace
`AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK`, declaration spelling, and
closed-sound binder names.  That makes a later isolated type comparison
meaningful without making the old aggregate visible in the staged runtime.
Their source paths are new and live only below this staging root.

| Module | Role | Runtime status |
| --- | --- | --- |
| `Core` | formulas, substitution, semantic vocabulary, and `Deriv` constructors | both profiles |
| `SemanticPrelude` | realization lemmas, explicit semantics, and the closed-side bridge used to state `closed_sound` | both profiles |
| `RulePrelude` | local rule-soundness lemmas, without global `Deriv.sound` | both profiles |
| `Targets.DerivSound` | historical global soundness theorem | compositional profile only; explicitly **unadmitted** |
| `Targets.ClosedSound` | reference target theorem and exact statement anchor | never runtime |
| `Controls` | countermodels and capture/freshness review controls | offline only |

The two `Candidate.lean` files define exactly the same historical
`Deriv.closed_sound` statement.  The independent candidate reconstructs its
local soundness induction from `RulePrelude`; the compositional candidate uses
the staged `Deriv.sound` dependency.  The latter is a preflight diagnostic,
not an accepted Library theorem or a reclassification of any task.

`profiles/independent_reproof.profile.v1.json` binds the runtime closure only
through `RulePrelude` and forbids `Deriv.sound`.  The compositional profile
adds `Targets.DerivSound`, labels it `unadmitted_preflight_dependency`, and
still forbids the closed-sound target module.  Neither profile has a contract
or a `library-substrate-v1` image digest.

Run the static boundary check through the repository environment:

```text
uv run --frozen python Library/scripts/verify_substrate_fixture.py check
```

For an operator-local WSL/ext4 compile and direct-proof-dependency diagnostic
against the existing digest-pinned source-v2 image, run:

```text
uv run --frozen python Library/scripts/run_substrate_canary.py canary
```

CI without Docker or the pinned local image must run the explicit static mode:

```text
uv run --frozen python Library/scripts/run_substrate_canary.py static --reason ci_no_docker
```

That fallback proves no Lean compilation, target ownership, type comparison,
axiom observation, dependency closure, image receipt, or proof admission.  A
successful real canary remains host-mounted diagnostic evidence; the future
image-owned verifier must repeat the query with full closure, module-origin,
and exact-type-collision checks.
