# iFEM source-free DeepSeek canary: recoverable single coordinate

Date: 2026-08-01

Status: retained provider-path and restart-recovery observation; non-promotable

## Bound experiment

This experiment advanced only the first `statement_formalizer` coordinate of the persisted
nine-case source-free seed manifest. The other 26 coordinates remained pending. The request had
no textbook text, retrieval, Lean surface, hidden oracle, native tool, or Prover input. Every
attempt used a fresh state/private root, a one-attempt authorization, and the same strict finite
response parser.

The first strictly accepted D plan binds:

- profile SHA-256
  `5faba1964bdbda24f03b9a290e4fd18c92b9dac70418d711cf7296643b4fafe3`;
- statement-formalizer prompt-contract SHA-256
  `393b936be5e8dabd434633c51f6cccfc7c4eccd8f0f8f78790fd3ddbe8020b66`;
- plan SHA-256
  `d1aabcf3e17c17e46d0bdffd5f598629ea1644cea73dff9253ff32260579f7a3`;
- 2,048 input-token and 4,096 output-token ceilings, high reasoning effort, JSON-object output,
  and `max_attempts_per_stage=1`.

The 61,440 micro-USD authorization ceiling is a conservative local accounting bound, not a
provider invoice or billed-price claim.

## Evidence-driven iterations

| Run | Immutable observation | Change permitted for the next run |
| --- | --- | --- |
| A | The 256-token completion ceiling was exhausted before any response text. The settled receipt was retained and the coordinate was not retried. | Move to the already reviewed 1,024-token D35 profile. |
| B | A JSON object was returned without exhausting the ceiling, but it used the generic stage-output version rather than the strict role-output version. The parser rejected it and the receipt remained immutable. | State each role's exact output schema literal in the prompt. |
| C | Before dispatch, preflight showed that prompt drift did not alter the plan hash. The plan was fixed to bind the prompt contract. The later 1,024-token request exhausted its completion ceiling without response text and was retained as rejected. | Introduce the hash-pinned D36 profile with a 4,096-token ceiling. |
| D | The response passed the original strict finite parser. Run-time readback verified the private CAS receipt, exact attempt binding, and terminal stage-ledger binding. | No adaptive retry. Exercise credential-free recovery only. |
| E | After independent audit, the V2 prompt contract additionally bound the input-envelope key set and role-specific card schema, stated all finite bounds, and restored legal downstream abstention paths. One fresh request passed the same strict parser and recovered without provider construction. | Treat E as the current protocol canary; do not combine D and E into a model score. |

No rejected output was normalized, repaired, or resubmitted. A, B, and C remain immutable failed
observations rather than attempts combined into a success claim.

## Recovery evidence

After D settled, a fresh `resume` invocation used no API-key lookup and constructed no provider.
It reproduced the three D public commitments from the settled run:

- stage ledger: `e9c5ef54a2e547526bed8aea2c6b063b83cd18cd94684f277d8ae162f61d9bdb`;
- attempt binding: `5c85332f41dbc17dd9c41985a3181381ceda19b89fe11b2a488fb408cb99598a`;
- completion binding: `b5857bd488de1ae885cacac81d4904eca5f3bc78caaf35ee63852e726f3fe416`.

The control database contained one authorization, one completion settlement, one completion
receipt, and one attempt event. The public contract deliberately makes no actual provider-dispatch
count claim. Read-only `report` mode observed the attempt and settlement rows but kept
`private_completion_verified=false`; it did not substitute row presence for CAS verification.

The retained canonical recovery report is
[ifem-source-free-deepseek-canary-2026-08-01-d.json](ifem-source-free-deepseek-canary-2026-08-01-d.json).
Its file SHA-256 is
`fcd19ff02662791847113f74c84cb058d6b172cf623184ac44dbeb73f5746449`, and its internal content
SHA-256 is `98d69c877ca3aacf83583004c56e1d968af65e2a1ff0522a51a5cd89a8803bca`.

The audited E successor binds prompt-contract SHA-256
`2725d13be2ed82016527104b1dea7318981014941d9626e39182ed7fff6c1eee` and plan SHA-256
`458228066bdbb24801d6d6947a4989994ba919a195140f460f2758c3da9452db`. Its no-key recovery
reproduced stage-ledger commitment
`4f54973de634b23bf4a882b0467b1cdc3d2050d8a2d031c7c468e259951f7af7`, attempt commitment
`adeb9677827ef553b73785ad01dbb6811577c0c774025d1779b034c7251a74a3`, and completion commitment
`b9e303043e5cc204c1fb9e6b0167d863de22d948ebfeb92343bbe70b9a071626`.

The current canonical recovery report is
[ifem-source-free-deepseek-canary-2026-08-01-e.json](ifem-source-free-deepseek-canary-2026-08-01-e.json).
Its file SHA-256 is
`f4b695da857b9a51839631236b3c2729017da4e31a0cdca194b97836112f31d0`, and its internal content
SHA-256 is `1f06a31e8bdb07ff180abb064da2b129974ead1156bc6674360ff829ace02c1a`.

## Interpretation and authority

This establishes one real-provider, strict-response, durable-settlement, restart-recovery path for
one source-free coordinate. It does not establish a model capability floor, benchmark score,
semantic fidelity, iFEM classification, statement contract, formal graph, proof, Builder freeze,
Prover handoff, provider billing, production signing, release, or Open Problem authority. Every
corresponding flag in the report remains false.

The experiment also found and closed a provenance defect: changing the role prompt previously did
not change the plan hash. The plan now includes a deterministic digest of the role, input-envelope
version, exact system prompt, and response format. This is regression-tested before any further
source-free role is dispatched.

Post-D independent audit versioned the successor prompt contract. V2 additionally binds the exact
input-envelope key set and the role-specific card JSON schema, states all finite candidate bounds,
and includes the valid reviewer/supervisor abstention paths. E exercised that successor once. D
remains an immutable V1 observation with its original hashes and is not relabelled as V2 evidence.
