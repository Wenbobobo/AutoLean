# Staging

Staging is Builder-owned scratch space for a candidate contract revision and
Prover-owned candidate proofs. It has no public import path and may not be
imported by `AutoLeanLibrary.lean` or `AutoLeanLibrary/Promoted/`.

Every staged candidate contract or proof must name its target contract ID and
revision in its review packet. An architecture preflight fixture may remain
unbound only when it:

- declares `profile_state = preflight_fixture`;
- keeps every target-binding field explicitly `null` or `unbound`;
- points to the architecture decision it tests; and
- lists non-claims that make the fixture non-consumable as a proof or promoted
  Library asset.

Keep external source text, credentials, prompts, and raw worker logs out of
this directory. Store only allowed references and content hashes.
