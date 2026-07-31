"""Adversarial tests for the project-synthetic atomic-span protocol."""

from __future__ import annotations

import ast
import hashlib
import os
import pickle
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_atomic_source_span as atomic
from autolean_contracts import canonical_json_bytes

CELL_TEXT = (
    "Definition alpha: x >= 0.\n"
    "定义 beta\uff1a对每个 x\uff0c存在 y。\n"
    "Claim emoji 🚀 stays whole.\n"
    "Combining e\u0301 is not normalized.\n"
)
FIXED_NONCE = "ab" * 32


def _binding(text: str = CELL_TEXT) -> atomic.IFEMAtomicSpanInputBindingV1:
    return atomic.build_project_synthetic_atomic_span_input(
        fixture_label="unicode-protocol-fixture",
        cell_text=text,
    )


def _range(text: str, fragment: str, *, occurrence: int = 0) -> tuple[int, int]:
    encoded = text.encode("utf-8")
    target = fragment.encode("utf-8")
    start = -1
    cursor = 0
    for _ in range(occurrence + 1):
        start = encoded.index(target, cursor)
        cursor = start + 1
    return start, start + len(target)


def _observation(
    text: str,
    fragment: str,
    *,
    span_class: atomic.IFEMAtomicSpanClassV1 = (atomic.IFEMAtomicSpanClassV1.MATHEMATICAL_CLAIM),
    atomicity: atomic.IFEMAtomicityV1 = atomic.IFEMAtomicityV1.ATOMIC,
    proof_entangled: bool = False,
) -> atomic.IFEMAtomizerObservationV1:
    start, end = _range(text, fragment)
    return _raw_observation(
        text,
        start,
        end,
        span_class=span_class,
        atomicity=atomicity,
        proof_entangled=proof_entangled,
    )


def _raw_observation(
    text: str,
    start: int,
    end: int,
    *,
    span_class: atomic.IFEMAtomicSpanClassV1 = (atomic.IFEMAtomicSpanClassV1.MATHEMATICAL_CLAIM),
    atomicity: atomic.IFEMAtomicityV1 = atomic.IFEMAtomicityV1.ATOMIC,
    proof_entangled: bool = False,
    digest: str | None = None,
) -> atomic.IFEMAtomizerObservationV1:
    selected = text.encode("utf-8")[start:end]
    return atomic.IFEMAtomizerObservationV1(
        start_byte=start,
        end_byte=end,
        span_content_sha256=digest or hashlib.sha256(selected).hexdigest(),
        span_class=span_class,
        atomicity=atomicity,
        proof_entangled=proof_entangled,
    )


def _output(
    binding: atomic.IFEMAtomicSpanInputBindingV1,
    slot: atomic.IFEMAtomizerSlotV1,
    observations: tuple[atomic.IFEMAtomizerObservationV1, ...],
    *,
    decision: atomic.IFEMAtomizerDecisionV1 = atomic.IFEMAtomizerDecisionV1.PROPOSE,
    reasons: tuple[atomic.IFEMAtomicSpanGapReasonV1, ...] = (),
    method_id: str | None = None,
    group: str | None = None,
) -> atomic.IFEMAtomizerOutputV1:
    suffix = "a" if slot is atomic.IFEMAtomizerSlotV1.A else "b"
    return atomic.build_ifem_atomizer_output(
        input_binding=binding,
        slot=slot,
        method_id=method_id or f"synthetic-atomizer-{suffix}",
        independence_group=group or f"synthetic-group-{suffix}",
        decision=decision,
        observations=observations,
        reason_codes=reasons,
    )


def _sidecar(
    observations_a: tuple[atomic.IFEMAtomizerObservationV1, ...],
    observations_b: tuple[atomic.IFEMAtomizerObservationV1, ...] | None = None,
    *,
    text: str = CELL_TEXT,
    method_b: str | None = None,
    group_b: str | None = None,
    nonce: str = FIXED_NONCE,
) -> atomic.IFEMAtomicSpanPrivateSidecarV1:
    binding = _binding(text)
    return atomic.reconcile_project_synthetic_atomic_spans(
        input_binding=binding,
        cell_text=text,
        atomizer_a=_output(binding, atomic.IFEMAtomizerSlotV1.A, observations_a),
        atomizer_b=_output(
            binding,
            atomic.IFEMAtomizerSlotV1.B,
            observations_b if observations_b is not None else observations_a,
            method_id=method_b,
            group=group_b,
        ),
        commitment_nonce=nonce,
    )


def _rehash(payload: dict[str, object]) -> None:
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()


def test_input_binding_is_strictly_project_synthetic_and_text_free() -> None:
    binding = _binding()

    assert binding.cell_utf8_byte_count == len(CELL_TEXT.encode("utf-8"))
    assert binding.cell_utf8_sha256 == hashlib.sha256(CELL_TEXT.encode("utf-8")).hexdigest()
    assert binding.input_scope == "project_synthetic_protocol_fixture"
    assert binding.real_ifem_source_present is False
    assert binding.rights_attestation_present is False
    assert binding.source_backed_execution_authorized is False
    assert "cell_text" not in binding.model_dump(mode="json")


def test_exact_consensus_accepts_ascii_chinese_emoji_and_combining_bytes() -> None:
    observations = (
        _observation(
            CELL_TEXT,
            "Definition alpha: x >= 0.",
            span_class=atomic.IFEMAtomicSpanClassV1.DEFINITION,
        ),
        _observation(CELL_TEXT, "定义 beta\uff1a对每个 x\uff0c存在 y。"),
        _observation(CELL_TEXT, "Claim emoji 🚀 stays whole."),
        _observation(CELL_TEXT, "Combining e\u0301 is not normalized."),
    )

    sidecar = _sidecar(observations)

    assert sidecar.outcome is atomic.IFEMAtomicSpanOutcomeV1.MACHINE_LOCATED_PENDING_SEMANTIC_REVIEW
    assert len(sidecar.accepted_spans) == 4
    assert sidecar.gaps == ()
    assert sidecar.independence_verified is False
    assert sidecar.semantic_review_state == "not_performed"
    for located, observation in zip(sidecar.accepted_spans, observations, strict=True):
        assert located.start_byte == observation.start_byte
        assert located.end_byte == observation.end_byte
        assert located.span_content_sha256 == observation.span_content_sha256
        assert located.locator_state == "machine_located_pending_semantic_review"


def test_locator_identity_ignores_machine_classification() -> None:
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    located = _sidecar((observation,)).accepted_spans[0]
    changed = atomic.IFEMMachineLocatedSpanV1(
        locator_id=located.locator_id,
        parent_cell_span_id=located.parent_cell_span_id,
        start_byte=located.start_byte,
        end_byte=located.end_byte,
        span_content_sha256=located.span_content_sha256,
        span_class=atomic.IFEMAtomicSpanClassV1.DEFINITION,
    )

    assert changed.locator_id == located.locator_id
    assert changed.span_class is not located.span_class


@pytest.mark.parametrize("fragment", ("定义", "🚀", "e\u0301"))
def test_utf8_boundaries_accept_whole_multibyte_fragments(fragment: str) -> None:
    observation = _observation(CELL_TEXT, fragment)

    sidecar = _sidecar((observation,))

    assert sidecar.outcome is atomic.IFEMAtomicSpanOutcomeV1.MACHINE_LOCATED_PENDING_SEMANTIC_REVIEW


def test_continuation_byte_boundary_becomes_typed_abstention() -> None:
    whole_start, whole_end = _range(CELL_TEXT, "定义")
    observation = _raw_observation(CELL_TEXT, whole_start + 1, whole_end)

    sidecar = _sidecar((observation,))

    assert sidecar.outcome is atomic.IFEMAtomicSpanOutcomeV1.ABSTAIN
    assert atomic.IFEMAtomicSpanGapReasonV1.INVALID_UTF8_BOUNDARY in sidecar.gaps[0].reason_codes
    assert sidecar.accepted_spans == ()


@pytest.mark.parametrize(
    ("observation", "reason"),
    (
        (
            _raw_observation(CELL_TEXT, 0, len(CELL_TEXT.encode("utf-8")) + 1),
            atomic.IFEMAtomicSpanGapReasonV1.OUT_OF_BOUNDS,
        ),
        (
            _raw_observation(CELL_TEXT, 0, 4, digest="0" * 64),
            atomic.IFEMAtomicSpanGapReasonV1.DIGEST_MISMATCH,
        ),
        (
            _observation(
                CELL_TEXT,
                "Claim emoji 🚀 stays whole.",
                atomicity=atomic.IFEMAtomicityV1.MIXED,
            ),
            atomic.IFEMAtomicSpanGapReasonV1.MIXED_ATOM,
        ),
        (
            _observation(
                CELL_TEXT,
                "Claim emoji 🚀 stays whole.",
                atomicity=atomic.IFEMAtomicityV1.UNCERTAIN,
            ),
            atomic.IFEMAtomicSpanGapReasonV1.UNCERTAIN_ATOMICITY,
        ),
        (
            _observation(
                CELL_TEXT,
                "Claim emoji 🚀 stays whole.",
                proof_entangled=True,
            ),
            atomic.IFEMAtomicSpanGapReasonV1.PROOF_ENTANGLED,
        ),
        (
            _observation(
                CELL_TEXT,
                "Claim emoji 🚀 stays whole.",
                span_class=atomic.IFEMAtomicSpanClassV1.OTHER,
            ),
            atomic.IFEMAtomicSpanGapReasonV1.UNSUPPORTED_SPAN_CLASS,
        ),
    ),
)
def test_invalid_or_nonatomic_observation_abstains(
    observation: atomic.IFEMAtomizerObservationV1,
    reason: atomic.IFEMAtomicSpanGapReasonV1,
) -> None:
    sidecar = _sidecar((observation,))

    assert sidecar.outcome is atomic.IFEMAtomicSpanOutcomeV1.ABSTAIN
    assert reason in sidecar.gaps[0].reason_codes


def test_overlapping_spans_abstain() -> None:
    first = _observation(CELL_TEXT, "Definition alpha")
    second = _observation(CELL_TEXT, "alpha: x >= 0.")

    sidecar = _sidecar((first, second))

    assert atomic.IFEMAtomicSpanGapReasonV1.OVERLAPPING_SPANS in sidecar.gaps[0].reason_codes


@pytest.mark.parametrize("drift", ("offset", "class", "count"))
def test_any_atomizer_observation_disagreement_abstains(drift: str) -> None:
    baseline = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    if drift == "offset":
        start, end = _range(CELL_TEXT, "emoji 🚀 stays whole.")
        changed = (_raw_observation(CELL_TEXT, start, end),)
    elif drift == "class":
        changed = (
            _observation(
                CELL_TEXT,
                "Claim emoji 🚀 stays whole.",
                span_class=atomic.IFEMAtomicSpanClassV1.DEFINITION,
            ),
        )
    else:
        changed = (baseline, _observation(CELL_TEXT, "Combining e\u0301 is not normalized."))

    sidecar = _sidecar((baseline,), changed)

    assert sidecar.outcome is atomic.IFEMAtomicSpanOutcomeV1.ABSTAIN
    assert atomic.IFEMAtomicSpanGapReasonV1.ATOMIZER_DISAGREEMENT in sidecar.gaps[0].reason_codes


def test_atomizer_abstention_and_shared_failure_domain_are_retained() -> None:
    binding = _binding()
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    sidecar = atomic.reconcile_project_synthetic_atomic_spans(
        input_binding=binding,
        cell_text=CELL_TEXT,
        atomizer_a=_output(
            binding,
            atomic.IFEMAtomizerSlotV1.A,
            (),
            decision=atomic.IFEMAtomizerDecisionV1.ABSTAIN,
            reasons=(atomic.IFEMAtomicSpanGapReasonV1.AMBIGUOUS_BOUNDARY,),
            group="shared-domain",
        ),
        atomizer_b=_output(
            binding,
            atomic.IFEMAtomizerSlotV1.B,
            (observation,),
            group="shared-domain",
        ),
        commitment_nonce=FIXED_NONCE,
    )

    reasons = set(sidecar.gaps[0].reason_codes)
    assert atomic.IFEMAtomicSpanGapReasonV1.ATOMIZER_ABSTAINED in reasons
    assert atomic.IFEMAtomicSpanGapReasonV1.AMBIGUOUS_BOUNDARY in reasons
    assert atomic.IFEMAtomicSpanGapReasonV1.INDEPENDENCE_NOT_ESTABLISHED in reasons


def test_same_method_id_is_not_treated_as_independent() -> None:
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")

    sidecar = _sidecar((observation,), method_b="synthetic-atomizer-a")

    assert atomic.IFEMAtomicSpanGapReasonV1.INDEPENDENCE_NOT_ESTABLISHED in (
        sidecar.gaps[0].reason_codes
    )


def test_binding_and_output_model_construct_bypasses_fail_revalidation() -> None:
    binding = _binding()
    unsafe_binding = atomic.IFEMAtomicSpanInputBindingV1.model_construct(
        **{**binding.model_dump(mode="python"), "content_sha256": "0" * 64}
    )
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")

    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="input failed revalidation"):
        atomic.build_ifem_atomizer_output(
            input_binding=unsafe_binding,
            slot=atomic.IFEMAtomizerSlotV1.A,
            method_id="synthetic-a",
            independence_group="group-a",
            decision=atomic.IFEMAtomizerDecisionV1.PROPOSE,
            observations=(observation,),
        )

    output = _output(binding, atomic.IFEMAtomizerSlotV1.A, (observation,))
    unsafe_output = atomic.IFEMAtomizerOutputV1.model_construct(
        **{**output.model_dump(mode="python"), "content_sha256": "1" * 64}
    )
    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="output failed revalidation"):
        atomic.reconcile_project_synthetic_atomic_spans(
            input_binding=binding,
            cell_text=CELL_TEXT,
            atomizer_a=unsafe_output,
            atomizer_b=_output(binding, atomic.IFEMAtomizerSlotV1.B, (observation,)),
            commitment_nonce=FIXED_NONCE,
        )


def test_rehashed_sidecar_tampering_is_rejected() -> None:
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    sidecar = _sidecar((observation,))
    payload = sidecar.model_dump(mode="json")
    accepted = cast(list[dict[str, object]], payload["accepted_spans"])[0]
    accepted["start_byte"] = cast(int, accepted["start_byte"]) + 1
    _rehash(payload)

    with pytest.raises(ValueError):
        atomic.IFEMAtomicSpanPrivateSidecarV1.model_validate(payload)


def test_self_rehashed_success_cannot_reuse_one_atomizer_lineage() -> None:
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    sidecar = _sidecar((observation,))
    malicious_b = _output(
        sidecar.input_binding,
        atomic.IFEMAtomizerSlotV1.B,
        (observation,),
        method_id=sidecar.atomizer_a.method_id,
    )
    payload = sidecar.model_dump(mode="json")
    payload["atomizer_b"] = malicious_b.model_dump(mode="json")
    payload["sidecar_id"] = atomic._sidecar_id(
        sidecar.input_binding.content_sha256,
        sidecar.atomizer_a.content_sha256,
        malicious_b.content_sha256,
    ).model_dump(mode="json")
    _rehash(payload)

    with pytest.raises(ValueError, match="distinct actor lineage"):
        atomic.IFEMAtomicSpanPrivateSidecarV1.model_validate(payload)


def test_sidecar_is_non_authoritative_even_after_exact_consensus() -> None:
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    sidecar = _sidecar((observation,))

    assert sidecar.commitment_nonce_source == "test_injected"

    for operation in (
        sidecar.authorize_model_execution,
        sidecar.freeze_statement,
        sidecar.handoff_to_prover,
    ):
        with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="cannot authorize"):
            operation()


def test_default_nonce_path_is_labelled_but_not_attested() -> None:
    binding = _binding()
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")

    sidecar = atomic.reconcile_project_synthetic_atomic_spans(
        input_binding=binding,
        cell_text=CELL_TEXT,
        atomizer_a=_output(binding, atomic.IFEMAtomizerSlotV1.A, (observation,)),
        atomizer_b=_output(binding, atomic.IFEMAtomizerSlotV1.B, (observation,)),
    )

    assert sidecar.commitment_nonce_source == "os_csprng"
    assert len(sidecar.commitment_nonce) == 64


def test_explicit_invalid_nonce_is_not_replaced_by_randomness() -> None:
    binding = _binding()
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")

    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="32-byte lowercase hex"):
        atomic.reconcile_project_synthetic_atomic_spans(
            input_binding=binding,
            cell_text=CELL_TEXT,
            atomizer_a=_output(binding, atomic.IFEMAtomizerSlotV1.A, (observation,)),
            atomizer_b=_output(binding, atomic.IFEMAtomizerSlotV1.B, (observation,)),
            commitment_nonce="",
        )


def test_self_rehashed_abstention_gap_cannot_bind_a_different_input() -> None:
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    changed = _observation(CELL_TEXT, "Combining e\u0301 is not normalized.")
    sidecar = _sidecar((observation,), (changed,))
    payload = sidecar.model_dump(mode="json")
    gap = cast(list[dict[str, object]], payload["gaps"])[0]
    foreign_binding_sha256 = "0" * 64
    reasons = tuple(
        atomic.IFEMAtomicSpanGapReasonV1(reason) for reason in cast(list[str], gap["reason_codes"])
    )
    gap["input_binding_sha256"] = foreign_binding_sha256
    gap["gap_id"] = atomic._gap_id(foreign_binding_sha256, reasons).model_dump(mode="json")
    _rehash(gap)
    _rehash(payload)

    with pytest.raises(ValueError, match="gap binds a different input"):
        atomic.IFEMAtomicSpanPrivateSidecarV1.model_validate(payload)


def test_persist_then_project_is_recoverable_and_public_bytes_are_redacted(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    private = tmp_path / "private"
    repo.mkdir()
    (repo / ".git").mkdir()
    private.mkdir()
    target = private / "atomic.private.json"
    marker = "Claim emoji 🚀 stays whole."
    sidecar = _sidecar((_observation(CELL_TEXT, marker),))

    persisted = atomic.persist_ifem_atomic_span_private_sidecar_once(
        target,
        sidecar,
        repository_root=repo,
        cell_text=CELL_TEXT,
    )
    public = atomic.project_ifem_atomic_span_public_commitment(persisted)
    recovered = atomic.load_persisted_ifem_atomic_span_private_sidecar(
        target,
        repository_root=repo,
        cell_text=CELL_TEXT,
    )
    recovered_public = atomic.project_ifem_atomic_span_public_commitment(recovered)
    rendered = atomic.render_ifem_atomic_span_public_commitment(public)

    assert target.read_bytes() == persisted.canonical_bytes
    assert recovered.canonical_bytes == persisted.canonical_bytes
    assert recovered_public == public
    assert atomic.verify_ifem_atomic_span_public_commitment(recovered, public) == public
    assert (
        public.private_sidecar_commitment_sha256
        != hashlib.sha256(persisted.canonical_bytes).hexdigest()
    )
    assert marker.encode("utf-8") not in rendered
    assert str(target).encode("utf-8") not in rendered
    for forbidden in (
        b'"start_byte"',
        b'"end_byte"',
        b'"span_content_sha256"',
        b'"commitment_nonce"',
        b'"commitment_nonce_source"',
        b'"atomizer_a"',
    ):
        assert forbidden not in rendered
    assert public.commitment_authenticated is False
    assert public.private_persistence_provenance_verified is False
    assert public.commitment_is_private_cas_locator is False
    assert public.nonce_provenance_verified is False
    assert public.commitment_non_enumerability_verified is False
    with pytest.raises(atomic.IFEMAtomicSourceSpanError):
        public.freeze_statement()


def test_private_nonce_changes_commitment_without_claiming_verified_hiding(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    private = tmp_path / "private"
    repo.mkdir()
    (repo / ".git").mkdir()
    private.mkdir()
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    first = _sidecar((observation,), nonce="11" * 32)
    second = _sidecar((observation,), nonce="22" * 32)
    persisted_first = atomic.persist_ifem_atomic_span_private_sidecar_once(
        private / "first.private.json",
        first,
        repository_root=repo,
        cell_text=CELL_TEXT,
    )
    persisted_second = atomic.persist_ifem_atomic_span_private_sidecar_once(
        private / "second.private.json",
        second,
        repository_root=repo,
        cell_text=CELL_TEXT,
    )

    first_public = atomic.project_ifem_atomic_span_public_commitment(persisted_first)
    second_public = atomic.project_ifem_atomic_span_public_commitment(persisted_second)
    assert (
        first_public.private_sidecar_commitment_sha256
        != second_public.private_sidecar_commitment_sha256
    )
    assert first_public.commitment_non_enumerability_verified is False
    assert second_public.commitment_non_enumerability_verified is False


def test_write_once_conflict_and_post_persistence_change_are_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    private = tmp_path / "private"
    repo.mkdir()
    (repo / ".git").mkdir()
    private.mkdir()
    target = private / "atomic.private.json"
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    first = _sidecar((observation,), nonce="11" * 32)
    second = _sidecar((observation,), nonce="22" * 32)
    persisted = atomic.persist_ifem_atomic_span_private_sidecar_once(
        target,
        first,
        repository_root=repo,
        cell_text=CELL_TEXT,
    )

    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="conflicts"):
        atomic.persist_ifem_atomic_span_private_sidecar_once(
            target,
            second,
            repository_root=repo,
            cell_text=CELL_TEXT,
        )
    target.write_bytes(b"{}\n")
    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="changed"):
        atomic.project_ifem_atomic_span_public_commitment(persisted)


def test_private_storage_rejects_repo_path_and_reparse_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    private = tmp_path / "private"
    repo.mkdir()
    (repo / ".git").mkdir()
    private.mkdir()
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    sidecar = _sidecar((observation,))

    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="outside the repo"):
        atomic.persist_ifem_atomic_span_private_sidecar_once(
            repo / "inside.private.json",
            sidecar,
            repository_root=repo,
            cell_text=CELL_TEXT,
        )

    other_checkout = tmp_path / "other-checkout"
    other_checkout.mkdir()
    (other_checkout / ".git").mkdir()
    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="every Git checkout"):
        atomic.persist_ifem_atomic_span_private_sidecar_once(
            other_checkout / "blocked.private.json",
            sidecar,
            repository_root=repo,
            cell_text=CELL_TEXT,
        )

    original_isjunction = getattr(os.path, "isjunction", None)

    def fake_isjunction(path: object) -> bool:
        if Path(path) == private:
            return True
        return bool(original_isjunction is not None and original_isjunction(path))

    monkeypatch.setattr(os.path, "isjunction", fake_isjunction, raising=False)
    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="junctions"):
        atomic.persist_ifem_atomic_span_private_sidecar_once(
            private / "blocked.private.json",
            sidecar,
            repository_root=repo,
            cell_text=CELL_TEXT,
        )


def test_persisted_handle_rejects_ordinary_construction_and_serialization(
    tmp_path: Path,
) -> None:
    observation = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    sidecar = _sidecar((observation,))

    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="process-local marker"):
        atomic.PersistedIFEMAtomicSpanSidecar(
            sidecar,
            atomic.render_ifem_atomic_span_private_sidecar(sidecar),
            tmp_path / "fake.private.json",
            tmp_path,
            (),
            object(),
        )

    repo = tmp_path / "repo"
    private = tmp_path / "private"
    repo.mkdir()
    (repo / ".git").mkdir()
    private.mkdir()
    persisted = atomic.persist_ifem_atomic_span_private_sidecar_once(
        private / "real.private.json",
        sidecar,
        repository_root=repo,
        cell_text=CELL_TEXT,
    )
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(persisted)


def test_projection_revalidates_repo_external_path_even_with_internal_marker(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    sidecar = _sidecar((_observation(CELL_TEXT, "Claim emoji 🚀 stays whole."),))
    raw = atomic.render_ifem_atomic_span_private_sidecar(sidecar)
    path = repo / "forged.private.json"
    path.write_bytes(raw)
    forged = atomic.PersistedIFEMAtomicSpanSidecar(
        sidecar,
        raw,
        path,
        repo,
        atomic._snapshot_existing_directory(repo),
        atomic._HANDLE_TOKEN,
    )

    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="outside the repo"):
        atomic.project_ifem_atomic_span_public_commitment(forged)


def test_rehashed_public_commitment_tampering_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    private = tmp_path / "private"
    repo.mkdir()
    (repo / ".git").mkdir()
    private.mkdir()
    sidecar = _sidecar((_observation(CELL_TEXT, "Claim emoji 🚀 stays whole."),))
    persisted = atomic.persist_ifem_atomic_span_private_sidecar_once(
        private / "atomic.private.json",
        sidecar,
        repository_root=repo,
        cell_text=CELL_TEXT,
    )
    public = atomic.project_ifem_atomic_span_public_commitment(persisted)
    payload = public.model_dump(mode="json")
    payload["commitment_authenticated"] = True
    _rehash(payload)

    with pytest.raises(ValueError):
        atomic.IFEMAtomicSpanPublicCommitmentV1.model_validate(payload)


def test_invalid_primitive_inputs_and_noncanonical_outputs_are_rejected() -> None:
    with pytest.raises(atomic.IFEMAtomicSourceSpanError):
        atomic.build_project_synthetic_atomic_span_input(
            fixture_label="bad label",
            cell_text=CELL_TEXT,
        )
    with pytest.raises(atomic.IFEMAtomicSourceSpanError):
        atomic.build_project_synthetic_atomic_span_input(
            fixture_label="empty",
            cell_text="",
        )
    with pytest.raises(atomic.IFEMAtomicSourceSpanError):
        atomic.build_project_synthetic_atomic_span_input(
            fixture_label="surrogate",
            cell_text="\ud800",
        )
    with pytest.raises(ValueError):
        atomic.IFEMAtomizerObservationV1(
            start_byte=True,
            end_byte=1,
            span_content_sha256="0" * 64,
            span_class=atomic.IFEMAtomicSpanClassV1.DEFINITION,
            atomicity=atomic.IFEMAtomicityV1.ATOMIC,
            proof_entangled=False,
        )

    binding = _binding()
    earlier = _observation(CELL_TEXT, "Definition alpha: x >= 0.")
    later = _observation(CELL_TEXT, "Claim emoji 🚀 stays whole.")
    with pytest.raises(atomic.IFEMAtomicSourceSpanError, match="atomizer output is invalid"):
        _output(
            binding,
            atomic.IFEMAtomizerSlotV1.A,
            (later, earlier),
        )
    with pytest.raises(ValueError):
        atomic.IFEMAtomizerObservationV1(
            start_byte=1,
            end_byte=1,
            span_content_sha256="0" * 64,
            span_class=atomic.IFEMAtomicSpanClassV1.DEFINITION,
            atomicity=atomic.IFEMAtomicityV1.ATOMIC,
            proof_entangled=False,
        )


def test_module_has_no_real_source_provider_prover_or_public_contract_dependency() -> None:
    module_path = Path(atomic.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.Import)
        for alias in statement.names
    }
    imported_roots.update(
        statement.module.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom) and statement.module is not None
    )

    assert not imported_roots.intersection(
        {"Prover", "benchmarks", "http", "httpx", "openai", "requests", "socket", "urllib"}
    )
    source = module_path.read_text(encoding="utf-8")
    for forbidden in (
        "StatementContractV1",
        "FormalGraph",
        "ExecutionGraph",
        "GapReportV1",
        "IFEMNotebookMarkdownCellTextProjectionV1",
        "IFEMLocalUseResolutionV1",
    ):
        assert forbidden not in source
