# D32/D34 iFEM DeepSeek role calibration

Status: implemented operator runner; no live observation is claimed by this document

`python -m scripts.ifem_deepseek_role_calibration` is the only iFEM role-calibration runner. It
loads one tracked source-text-free candidate graph and one tracked sixteen-case corpus, verifies
the exact file and canonical content SHA-256 of both, and rebuilds the corpus against the graph
before any live path. It uses the fixed `deepseek-v4-pro` Chat Completions profile,
`IFEMDeepSeekExactExecutor`, and the D31 `LocalIFEMSyntheticRolePrivateLedger`; it never imports a
test corpus or evaluates the private expected side. The mandatory `--protocol` selects a closed
request revision; it is not a model-capability claim.

| Protocol | Fixed profile | Output budget | Response contract |
| --- | --- | ---: | --- |
| `d32-v1` | `deepseek-v4-pro.chat-completions.v1.json` | 256 | `selected_option` plus reason |
| `d34-v2` | `deepseek-v4-pro.ifem-role-calibration.v2.json` | 512 | exactly one `selected_option` field |

`d34-v2` exists because the recorded D32 observation exhausted its 256-token completion budget
without a final answer. It changes neither the fixture nor the private expected side. It is a fresh
calibration protocol, not a retry of that observation.

Use `uv` from the repository root. The state/private parents must already exist, be physical
directories outside the checkout, and the two requested roots must be distinct.

```text
uv run --frozen python -m scripts.ifem_deepseek_role_calibration plan --protocol d34-v2 --state-root <ABS_STATE> --private-root <ABS_PRIVATE>
uv run --frozen python -m scripts.ifem_deepseek_role_calibration preflight --protocol d34-v2 --state-root <ABS_STATE> --private-root <ABS_PRIVATE>
uv run --frozen python -m scripts.ifem_deepseek_role_calibration run --operator-approved --protocol d34-v2 --state-root <ABS_STATE> --private-root <ABS_PRIVATE>
```

`plan` and `preflight` read only the hash-pinned tracked graph/corpus pair and fixed profile. They
do not need the ignored source cache, resolve no secret, make no provider call, and create neither root;
preflight also requires both future run roots to be absent. `run` alone resolves the
operator-owned process-environment references
`AUTOLEAN_DEEPSEEK_API_KEY`, `AUTOLEAN_IFEM_OPERATOR_SEED`, and
`AUTOLEAN_IFEM_LEDGER_HMAC_KEY`. The seed and ledger key must each be at least 32 UTF-8 bytes, and
all three values must be distinct.

Each protocol definition pins the SHA-256 of its exact profile bytes plus the graph and corpus file
and canonical content hashes. Changing any input requires a new protocol ID and is rejected before
any root claim or provider transport. The tracked pair is a reproducibility input only: it
contains project-synthetic structural pairs and digest/source metadata, but no source text,
source excerpt, Lean statement, prompt, provider request, or model response. It is regenerated
only through the explicit `scripts/ifem_structural_role_corpus.py materialize` operator path,
which still requires the locked ignored source cache and refuses to overwrite different bytes.
The first run exclusively claims an absent root pair and binds it to the exact graph/corpus
revision, fixture, provider configuration, profile bytes, request policy, and response contract
with the local ledger HMAC. A subsequent invocation may only recover that same revision. New roots
use marker v3. Historical v1/v2 markers remain readable only while the protocol still pins their
original graph/corpus revision; `d32-v1` cannot be resumed as `d34-v2`.
The private ledger records `dispatch_started` before a provider call, so an interrupted dispatch is
never automatically replayed. A CAS-persisted response can be recovered without another request;
an ambiguous dispatch returns `reconciliation_required`.

This is an open project-synthetic calibration set, not a held-out benchmark. The tracked corpus
publishes each baseline/mutant structural pair and its risk metadata, while the separate fixture
bridge randomizes option order and binds the derived prompt to its own source and rights records.
The provider receives only the neutral derived prompt, but a model or agent with repository access
could recover the intended baseline by lookup. Results therefore remain diagnostic observations;
they cannot support contamination-free ranking, a capability floor, or promotion.

Stdout is one digest-free, redacted JSON status object. It contains neither roots, secrets, raw
responses, response identifiers, oracle material, expected sides, nor output commitments. The
local HMAC ledger is explicitly non-promotable: all benchmark, semantic, statement, freeze, Prover,
and promotion authority flags remain false.
