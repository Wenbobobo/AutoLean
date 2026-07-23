# AutoLean Contracts

Provider-neutral, immutable Pydantic contracts shared by Builder and Prover.
The package deliberately contains no model, orchestration, database, or transport SDK.

The V1 boundary separates stable identifiers from content digests. In particular,
source bytes, Lean statement source, elaborated Lean types, environments, graph
snapshots, proofs, events, and frozen contracts use distinct digest kinds and cannot
be substituted for one another.
