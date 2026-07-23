from __future__ import annotations

from dataclasses import replace

import pytest
from autolean_contracts import (
    ActorKindV1,
    EndpointClassV1,
    HashKindV1,
    ProvenanceTraceV1,
    stable_identifier,
)
from autolean_prover.adapters import ArchonCandidate, ArchonProofAdapter
from autolean_prover.context import ContextPackBuilder, SpecialistRole
from autolean_prover.errors import PolicyViolation, ValidationError
from autolean_prover.execution import OciWorkerHarness, OciWorkerSpec, ProcessResult
from autolean_prover.providers import ModelRequest

from .helpers import frozen_bundle


class RecordingHarness:
    def __init__(self) -> None:
        self.request = None

    def execute(self, request):
        self.request = request
        return ProcessResult(
            argv=request.argv,
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            output_truncated=False,
        )


def test_context_pack_blocks_unapproved_external_egress() -> None:
    with pytest.raises(PolicyViolation, match="external model egress"):
        ContextPackBuilder().build(
            frozen_bundle(),
            role=SpecialistRole.TACTIC,
            endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
        )


def test_context_pack_is_projected_from_frozen_bundle_only() -> None:
    pack = ContextPackBuilder().build(
        frozen_bundle(external_egress=True),
        role=SpecialistRole.PLANNER,
        endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
    )
    assert "For every natural n" in pack.render()
    assert "source snapshot" not in pack.render()


def test_context_pack_hash_and_model_request_bind_the_exact_projection() -> None:
    pack = ContextPackBuilder().build(
        frozen_bundle(external_egress=True),
        role=SpecialistRole.TACTIC,
        endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
    )

    request = ModelRequest.from_context_pack(
        pack,
        system_prompt="Return only a Lean proof term.",
        max_input_tokens=512,
        max_output_tokens=128,
    )

    assert request.prompt == pack.render()
    assert request.context_pack_hash == pack.content_hash()
    assert request.context_pack_hash.kind is HashKindV1.PROMPT
    assert (
        request.outbound_request_hash()
        != ModelRequest(
            prompt="arbitrary replacement text",
            system_prompt="Return only a Lean proof term.",
            max_input_tokens=512,
            max_output_tokens=128,
            context_pack_hash=pack.content_hash(),
        ).outbound_request_hash()
    )


def test_oci_command_disables_network_and_pins_the_worker_image(tmp_path) -> None:
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    deps = tmp_path / "deps"
    for path in (source, workspace, deps):
        path.mkdir()
    recorder = RecordingHarness()
    spec = OciWorkerSpec(
        runtime="docker",
        image="registry.invalid/lean@sha256:" + "a" * 64,
        dependency_root=deps,
    )
    OciWorkerHarness(harness=recorder, spec=spec).execute(
        immutable_source=source,
        workspace=workspace,
        command=("lake", "env", "lean", "Candidate.lean"),
    )
    assert recorder.request is not None
    argv = recorder.request.argv
    assert (argv[3], argv[4]) == ("--network", "none")
    assert "--read-only" in argv
    assert spec.image in argv


def test_archon_adapter_exposes_only_a_frozen_proof_term_boundary() -> None:
    bundle = frozen_bundle()
    context = ContextPackBuilder().build(
        bundle,
        role=SpecialistRole.TACTIC,
        endpoint_class=EndpointClassV1.LOCAL,
    )
    adapter = ArchonProofAdapter()
    request = adapter.request(bundle, context)
    assert request.proof_slot_path == "Proof.lean"
    assert request.proof_boundary_hash == bundle.proof_boundary.boundary_hash.value
    candidate = ArchonCandidate(
        attempt_key="attempt-1",
        proof_source="by\n  rfl",
        provenance=ProvenanceTraceV1(
            trace_id=stable_identifier("trace", "archon-adapter"),
            actor_id="archon-worker",
            actor_kind=ActorKindV1.MODEL,
            endpoint_class=EndpointClassV1.LOCAL,
            provider="openai",
            model_name="gpt-5",
            model_revision="pinned",
        ),
    )
    submission = adapter.submission(bundle, candidate)
    assert submission.proof_boundary_hash == bundle.proof_boundary.boundary_hash

    with pytest.raises(ValidationError, match="proof boundary"):
        adapter.request(bundle, replace(context, proof_boundary_hash="not-the-boundary"))
