# FATE v4.28.0 and FATE-Eval Audit

**Decision:** use FATE v4.28.0 as a pinned, split-preserving Prover fixture source. Do
not reuse FATE-Eval's verifier, model layer, datasets, or execution runtime. Build a small
AutoLean-owned adapter that turns the original Lean source file into an immutable
FormalizationTaskBundleV1 and accepts only a proof-slot patch. Confidence: **high**.

This audit inspected exactly these revisions:

- FATE root: [bb646ecb9b68942ebf4bac31ccf4218a58ef9771](https://github.com/frenzymath/FATE/tree/bb646ecb9b68942ebf4bac31ccf4218a58ef9771), tag v4.28.0.
- FATE-M: [4eb33c8ccd0ff058b461cd763cc406509129743f](https://github.com/frenzymath/FATE-M/tree/4eb33c8ccd0ff058b461cd763cc406509129743f).
- FATE-H: [17967b3118082adfba7c5a5fc03b5f4a53717b59](https://github.com/frenzymath/FATE-H/tree/17967b3118082adfba7c5a5fc03b5f4a53717b59).
- FATE-X: [a6fb49ee85fd05bb8ce9fc66e1c66797b5a0592d](https://github.com/frenzymath/FATE-X/tree/a6fb49ee85fd05bb8ce9fc66e1c66797b5a0592d).
- FATE-Eval: [fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4](https://github.com/frenzymath/FATE-Eval/tree/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4).

The repositories are MIT-licensed at these revisions. This permits an adapter and fixture
metadata, but provenance and license records must still travel with every bundle.

## First Principles

FATE can tell us whether a frozen Lean theorem proof compiles in a particular environment.
It cannot establish that a natural-language source was faithfully translated, and its
one-file tasks do not exercise cross-file dependency construction, recovery, or scheduling.
It is therefore an early Prover benchmark, not evidence that the Builder--Prover architecture
or an open-problem pipeline is correct.

The FATE authors describe three distinct splits (M=150, H=100, X=100), one sorry per file,
and materially different formalization characteristics; M/H have no added definitions while
X can have dependent ones ([README lines 5-41](https://github.com/frenzymath/FATE/blob/bb646ecb9b68942ebf4bac31ccf4218a58ef9771/README.md#L5-L41)).
Results must remain split-specific. A combined score is at most a secondary diagnostic.

## Verified Fixture Lock

| Item | Verified value |
| --- | --- |
| Root/submodule topology | Root [.gitmodules](https://github.com/frenzymath/FATE/blob/bb646ecb9b68942ebf4bac31ccf4218a58ef9771/.gitmodules) names exactly FATE-M/H/X; git submodule status --recursive at the root pin yielded the three SHAs above. |
| Task source | 150 M, 100 H, and 100 X Lean task files. Every one of the 350 source files contains exactly one sorry and has a named theorem target. |
| Lean toolchain | Every pinned submodule has leanprover/lean4:v4.28.0. |
| Mathlib | Every pinned submodule's lake manifest pins mathlib to 8f9d9cff6bd728b17a24e163c9402775d9e6a365 (inputRev: v4.28.0), e.g. [FATE-M manifest lines 4-11](https://github.com/frenzymath/FATE-M/blob/4eb33c8ccd0ff058b461cd763cc406509129743f/lake-manifest.json#L4-L11). |
| JSON SHA-256 | M 6edf623256539cf955f939fbe40098ad0c6bd17a86060d8cded51c57de62e11e; H 7f130106dbb9e574bd4f4d87aba8065a66f74c69a8c6b468b3986865654b2a2f; X a322932a23a534fbbb5129f927a3d4359bd10c70841fd2ab6e40c294b394ce3b. |
| Lake manifest SHA-256 | M 8403899ad037e733385ed21746c79c772b918a1ce4a6d291fddadb8899ee9e24; H e6cec32cb305c7cb9e4de6ef7e0c1c1411b23bb92183d5b2c8759b38b62e54c5; X 3e26eab2f55368e8a32d6315d022078c1f3136b48f67eff04a993d412ea61005. |

The v4.28.0 changelog is semantically relevant, not cosmetic. It records statement repairs
for M-15, M-134, H-93, X-11, X-77, and X-86, plus unique X namespaces
([lines 16-30](https://github.com/frenzymath/FATE/blob/bb646ecb9b68942ebf4bac31ccf4218a58ef9771/CHANGELOG.md#L16-L30)).
The original Lean source, not a copied JSON record from another repository, is the
authoritative frozen statement for this adapter.

## FATE-Eval Findings

### Critical: theorem type substitution passes the static gate

CodeUtil.extract_components assigns last_theorem to only the last theorem **name**
([utils.py lines 173-206](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/lean_verifier/utils.py#L173-L206)).
static_precheck later asks only whether that name is a canonicalized substring of the
submission; it never parses or compares the expected theorem type
([lines 258-294](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/lean_verifier/utils.py#L258-L294)).

I reproduced the fault against the pinned FATE-Eval data by importing its exact CodeUtil with
uv and changing the final theorem to ": True := by trivial". For X, the original prefix
declarations and namespace were retained verbatim. static_precheck accepted:

| FATE-Eval split | Replaced theorem with True | Static acceptance |
| --- | ---: | ---: |
| M | 149 of 150 | 149 of 149 parsed-theorem tasks |
| H | 100 of 100 | 100 of 100 |
| X | 100 of 100 | 100 of 100 |

The M/H candidates have only import Mathlib plus
theorem <original-name> : True := by trivial; they are plainly kernel-checkable and have no
sorry. This host does not have Lean/elan installed, so the reproduction measured the
evaluator's static acceptance rather than a local lake run. That limitation does not weaken
the defect: FATE-Eval sends the normalized candidate that passed this gate to Lean
([verify.py lines 107-132](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/verify.py#L107-L132)),
and its completion test only rejects Lean errors and sorries
([verifier.py lines 70-85](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/lean_verifier/verifier.py#L70-L85)).

This is not a minor parser weakness. It prevents FATE-Eval's current statement-binding rule
from providing trustworthy certification for any reported score.

### Critical: evaluator input is self-authenticating

The verifier takes formal_statement from the generated-results payload's extra_info
([verify.py lines 62-80 and 107-120](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/verify.py#L62-L120)),
rather than resolving a canonical task ID to a pinned fixture. Generation serializes that same
mutable field into the result
([generate.py lines 228-241](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/generate.py#L228-L241)).
Anyone who can edit a result JSON can replace both the expected statement and the candidate.
No result file is a trustworthy external submission without an independently stored manifest
and source hash.

### High: pinned FATE and FATE-Eval are different benchmarks

FATE-Eval's three data files are not byte-identical to the v4.28.0 task JSONs:

| Split | Current FATE records different from FATE-Eval's records |
| --- | ---: |
| M | 15 / 150 |
| H | 95 / 100 |
| X | 100 / 100 |

Some differences are formatting or added namespaces, but known semantic corrections are also
missing:

- M-15 is the invalid existential/implication form in [FATE-Eval data line 89](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/data/FATE-M.json#L89), rather than v4.28.0's explicit y and z hypotheses
  ([current FATE line 103](https://github.com/frenzymath/FATE-M/blob/4eb33c8ccd0ff058b461cd763cc406509129743f/FATE-M.json#L103)).
- H-93 retains the problematic UniqueFactorizationMonoid (Ideal O) premise in
  [FATE-Eval line 1017](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/data/FATE-H.json#L1017), not the repaired explicit existence/uniqueness assumptions in
  [FATE v4.28.0 line 1109](https://github.com/frenzymath/FATE-H/blob/17967b3118082adfba7c5a5fc03b5f4a53717b59/FATE-H.json#L1109).
- X-77 omits IsNoetherianRing R in [FATE-Eval line 841](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/data/FATE-X.json#L841), while v4.28.0 has it at
  [line 1088](https://github.com/frenzymath/FATE-X/blob/a6fb49ee85fd05bb8ce9fc66e1c66797b5a0592d/FATE-X.json#L1088).

M-134 exposes another static-precheck failure. Its old FATE-Eval item is an anonymous
instance with sorry, so no theorem name is extracted. Unlike lemmas, formal_instances are not
proof-stripped before exact-substring checking
([utils.py lines 260-287](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/lean_verifier/utils.py#L260-L287)).
A valid proof body such as "exact inferInstance" is rejected as "missing instance", because
the expected string still contains sorry. The v4.28.0 M-134 is instead a repaired theorem
([source file](https://github.com/frenzymath/FATE-M/blob/4eb33c8ccd0ff058b461cd763cc406509129743f/FATEM/134.lean)).

### High: environment selection cannot reproduce the pinned release

All current FATE records declare v4.28.0; their source lock is Lean 4.28 and the mathlib
revision above. FATE-Eval contains only v4.13, v4.16, and v4.19 workspaces, and its default
is v4.16 ([verify_config.yaml lines 6-19](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/config/verify_config.yaml#L6-L19)).
The verification code reads only that one configured workspace and does not dispatch by a
task's claimed version
([verify.py lines 247-267](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/verify.py#L247-L267)).

This does not prove every v4.28 source fails under v4.16; it proves FATE-Eval cannot attest
that it used the pinned FATE environment. AutoLean must reject an environment mismatch rather
than silently compiling under a nearby version.

### High: execution is not a safe worker boundary

FATE-Eval writes arbitrary candidate code to a host temporary file and invokes lake env lean
in a mutable workspace
([verifier.py lines 28-54](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/lean_verifier/verifier.py#L28-L54)).
There is no OCI isolation, network denial, read-only dependency cache, write allowlist, or
fencing of an attempt. Lean elaboration/tactics are executable code, so syntactic rejection
of a few words is not a sandbox. The batch cleanup additionally assumes Unix pkill
([utils.py lines 363-385](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/lean_verifier/utils.py#L363-L385)),
which is unsuitable as the Windows development authority.

### Policy incompatibility: do not reuse FATE-Eval's model layer

FATE-Eval's requirements and commercial client directly include Anthropic
([requirements.txt](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/requirements.txt),
[commercial_api.py lines 1-13 and 149-159](https://github.com/frenzymath/FATE-Eval/blob/fe358fb5b0a53fdafaaf156540a2ecbf9b5b98a4/src/model_interface/commercial_api.py#L1-L13)).
That conflicts with AutoLean's provider policy. Its model, prompt, and executor code are
outside the benchmark adapter's scope.

## Safe AutoLean FATE Adapter

The adapter's job is narrow: make a FATE task a reproducible frozen contract and verify a proof
of that exact contract. It never accepts an externally supplied full Lean file as the task.

### Immutable input manifest

Create benchmarks/fate/manifest-v1.json from a clean checkout. The manifest is
content-addressed and should include at least:

~~~json
{
  "schema_version": "FateFixtureManifestV1",
  "benchmark": "FATE",
  "release": "v4.28.0",
  "root_commit": "bb646ecb9b68942ebf4bac31ccf4218a58ef9771",
  "submodules": {
    "M": "4eb33c8ccd0ff058b461cd763cc406509129743f",
    "H": "17967b3118082adfba7c5a5fc03b5f4a53717b59",
    "X": "a6fb49ee85fd05bb8ce9fc66e1c66797b5a0592d"
  },
  "toolchain": "leanprover/lean4:v4.28.0",
  "mathlib_commit": "8f9d9cff6bd728b17a24e163c9402775d9e6a365",
  "tasks": [{
    "id": "FATE-M-001",
    "split": "M",
    "source_path": "FATE-M/FATEM/1.lean",
    "source_sha256": "...",
    "proof_slot": { "original_token": "sorry", "byte_start": 0, "byte_end": 0 },
    "target": { "qualified_name": "prod_card_eq_card_pow", "elaborated_type_hash": "..." }
  }]
}
~~~

The real manifest must contain byte positions and hashes, not the illustrative zeroes above.
Build it once in the authoritative Linux/WSL environment after pinned dependencies are
available. Refuse to generate or verify a bundle if the root commit, submodule SHA, source
hash, lake-manifest hash, toolchain, or mathlib revision differs.

Use the original Lean file as statement authority. JSON supplies natural-language metadata,
tags, and provenance only after its hash is linked to the source task. For FATE-X, preserve
the source namespace and all per-file declarations; they are part of the frozen formal context.

### Bundle and submission boundary

FateAdapter.claim(task_id) should emit a normal FormalizationTaskBundleV1 with:

- a StatementContractV1 revision pinned to the manifest and source hash;
- separate MathematicalGraph, FormalGraph, and ExecutionGraph references;
- source/license records, import and axiom allowlists, exact Lean environment, and the
  target declaration's elaborated-type hash;
- an immutable source artifact plus one ProofSlotV1 range; and
- benchmark_split set to M, H, or X. Reporting code must not erase this field.

ProofSubmissionV1 for FATE contains a proof *body* for that slot, bundle/contract/artifact
hashes, and attempt metadata. It does not contain imports, declarations, a theorem name, an
alternative formal statement, or arbitrary source patches. The materializer replaces only the
original sorry token inside the already-present ":= by" block, then independently checks that
the prefix and suffix byte hashes are unchanged.

This is the decisive boundary: a proposed "theorem t : True := by trivial" is not a valid proof
body for the source slot and is rejected before Lean runs. A Prover failure can return
GapReportV1 or ContractChangeRequestV1; it cannot alter the fixture or weaken the theorem.

### Verification sequence

1. Resolve the task ID from the content-addressed manifest, not submission JSON.
2. Recreate a fresh workspace from the immutable source artifact and matching locked dependency
   image; keep dependencies read-only.
3. Apply the proof-body patch only at the recorded slot. Reject extra text, a second declaration,
   source-hash mismatch, or missing/extra sorry token.
4. Compile the original target file in the pinned environment. Kernel success is necessary but
   not enough: reject sorryAx, unapproved axioms, compiler errors, and warnings that establish
   a declaration used sorry.
5. Query the produced target declaration and compare qualified name and elaborated-type hash to
   the manifest. Record "#print axioms" output and require it to fit the contract allowlist.
6. Emit an immutable VerificationReportV1 with manifest/source/patch hashes, worker image
   digest, Lean/mathlib identifiers, compiler output, axiom report, elapsed time, and fencing
   token.

Steps 2-5 run in the project's OCI worker: default-deny network, non-root process, bounded
CPU/RAM/time, read-only dependencies, and an attempt-specific writable directory. The local
Windows setup may prepare fixtures, but it is not the authority for acceptance.

### Required adapter tests

- Verify every locked source file has exactly one intended slot and that task ID, source SHA-256,
  and qualified declaration are stable.
- Regression-test the FATE-Eval exploit: a full-file candidate changing the target to True
  must be rejected before compilation. Include M-15, M-134, H-93, X-11, X-77, and X-86 because
  the release explicitly repaired them.
- Reject changed imports, namespace, preceding definitions, appended axioms, sorry/admit,
  declaration replacement, and a stale bundle revision.
- Refuse FATE-Eval's old JSON hashes and any v4.13/v4.16/v4.19 workspace for this v4.28 fixture.
- Run clean-build canaries separately for M {3,15,134}, H {31,51,93}, and
  X {11,15,62,72,77,86}; do not aggregate these into one pass rate.
- Use stable SHA-256 ordering over FATE/v4.28.0/<split>/<id> for non-golden sampling so that
  regression-48 and compare-90 stay deterministic and disjoint.

## Uncertainties and Next Verification

The current workstation lacks Lean and elan, so this audit did not run a v4.28 clean build.
Before accepting the fixture manifest, the Linux/WSL worker image must run lake exe cache get,
parse and hash all 350 original sources, and baseline-elaborate them with their one expected
source sorry only to obtain declaration metadata. Clean builds must then use real proof bodies
for accepted tasks and preserve a replayable build log.

FATE's own release repairs demonstrate responsible maintenance, but they also show why the
Builder's semantic-fidelity gate cannot be delegated to a benchmark release. Keep FATE out of
Builder fidelity metrics; use its frozen formal statements only after the adapter records source
provenance and environment.
