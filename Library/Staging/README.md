# Staging

Staging is Builder-owned scratch space for a candidate contract revision and
Prover-owned candidate proofs. It has no public import path and may not be
imported by `AutoLeanLibrary.lean` or `AutoLeanLibrary/Promoted/`.

Every staged item must name its target contract ID and revision in its review
packet. Keep external source text, credentials, prompts, and raw worker logs
out of this directory. Store only allowed references and content hashes.
