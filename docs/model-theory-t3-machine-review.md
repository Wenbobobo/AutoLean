# Model-Theory T3 Machine Review

## Purpose

The tracked packet at
[`Builder/pilots/model-theory-admission/machine-review/packet.v1.json`](../Builder/pilots/model-theory-admission/machine-review/packet.v1.json)
is a replayable machine aid for the unresolved T3 boundary. It turns the existing evidence into
one compact packet for later multi-role review: locator ambiguity, mutation controls, and formal
profile options stay together without becoming a new authority path.

## What the packet says

The machine cross-check leaves all nine ambiguity rows unresolved. It records three retained
kernel-level rejection controls: universal-right old-variable reuse, the corresponding
existential-left witness, and capture-avoiding substitution. Those controls are evidence against
specific bad encodings; they are not source-fidelity or completeness results.

The packet presents three unselected successor profiles:

1. Reprove the full candidate under the current strict empty-axiom policy.
2. Use an explicit allowlist matching the exact-image observations (`Classical.choice`,
   `Quot.sound`, and `propext`) for all retained declarations.
3. Use the same observed axiom set only for `closed_sound` and an independently retained exact
   dependency closure.

The machine preference for option 2 is an engineering recommendation for the next replay only.
It is not a selection, admission, freeze, handoff, promotion, or open-problem claim. Every option
requires a new decision revision, an exact-image replay, and the remaining authority checks.

## Verification boundary

The packet binds the immutable decision bytes and canonical payload, all public T3 attachments,
the exact-image query, the pending-review list, and the retained Lean source. It contains no source
excerpt, local cache path, prompt, raw model output, or credential. Its quorum section records only
role/policy compatibility; no provider request, control-plane receipt, or authenticated reviewer
identity exists.

Run:

```text
uv run python scripts/model_theory_machine_review.py check
```

The command must preserve `gap`, `not_selected`, `not_frozen`, and forbidden Prover handoff. It
does not authorize changing `decision.v2.json`.
