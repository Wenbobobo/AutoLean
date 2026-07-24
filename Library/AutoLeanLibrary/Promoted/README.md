# Promoted Assets

This directory is the only future public math-asset surface. Add a Lean module
only after the exact source-to-contract, proof, semantic-review, and independent
verification records are frozen. The public root must import only promoted
modules that have an accompanying immutable record under `records/promoted/`.

Do not put draft declarations, `axiom`, `sorry`, or `admit` here. A proof
failure belongs in a gap report or contract-change request, never in a weaker
replacement declaration.
