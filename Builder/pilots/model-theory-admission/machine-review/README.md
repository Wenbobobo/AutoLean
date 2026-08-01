# T3 Machine Review Packet

`packet.v1.json` is a deterministic, public-safe review aid for the model-theory T3 boundary.
It is intentionally non-authoritative. It does not represent a provider call, a
`MachineQuorumReport`, a human or expert review, a Builder decision, a frozen statement, or a
Prover handoff.

The packet is built from the unchanged `decision.v2.json`, source-rule matrix, fine source-span
attachment, exact-image attachment and declaration query, human packet, pending-review list, and
the retained `UniversalLK.lean` source. Each input has a raw SHA-256 and JSON inputs also have a
canonical SHA-256. The builder rejects any decision bytes other than the retained `gap`,
`not_selected`, `not_frozen` revision.

It contains three machine-readable sections:

- an ambiguity table with the two unresolved PDF/printed-page pairs and seven semantic or profile
  ambiguities;
- three mutation-control results, each bound to the exact-image declaration observations rather
  than presented as a new Lean run; and
- three successor formal-profile alternatives. The machine preference is only a proposal for the
  next evidence replay; all alternatives remain unselected and require a new decision revision.

The packet reuses the role and policy vocabulary of `machine_semantic_quorum.py` only to make the
boundary explicit. No quorum execution, provider request, control-plane receipt, or authenticated
failure-domain evidence is present.

Use the deterministic check from the repository root:

```text
uv run python scripts/model_theory_machine_review.py check
```

The check must continue to report `gap`, `not_selected`, `not_frozen`, `forbidden`, and
`machine_advisory`. A successful check does not close any item in `pending-review.md`.
