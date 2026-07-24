from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from autolean_contracts import (
    DigestV1,
    HashKindV1,
    OciExecutionAuthorityV1,
    OciVerificationArtifactV2,
)


def _authority() -> OciExecutionAuthorityV1:
    return OciExecutionAuthorityV1(
        execution_claim_hash="a" * 64,
        worker_id="verifier-worker",
        fencing_token=7,
        expires_at=datetime(2030, 1, 1, tzinfo=UTC),
        wrapper_identity_hash="b" * 64,
    )


def test_oci_v2_requires_lease_bound_execution_authority() -> None:
    compile_command_hash = "3" * 64
    query_command_hash = "4" * 64
    sealed_candidate_sha256 = "5" * 64
    command_hash = hashlib.sha256(
        json.dumps(
            {
                "schema_version": "autolean.oci-command-transcript.v2",
                "handoff_protocol": "autolean.oci-compile-query-handoff.v1",
                "compile_command_hash": compile_command_hash,
                "query_command_hash": query_command_hash,
                "sealed_candidate_sha256": sealed_candidate_sha256,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    artifact = OciVerificationArtifactV2(
        worker_image_digest="sha256:" + "c" * 64,
        wrapper_protocol="autolean.oci-lean-wrapper.v2",
        command_policy_hash=DigestV1(
            kind=HashKindV1.VERIFICATION_COMMAND,
            value="d" * 64,
        ),
        command_hash=DigestV1(
            kind=HashKindV1.VERIFICATION_COMMAND,
            value=command_hash,
        ),
        compile_command_hash=DigestV1(
            kind=HashKindV1.VERIFICATION_COMMAND,
            value=compile_command_hash,
        ),
        query_command_hash=DigestV1(
            kind=HashKindV1.VERIFICATION_COMMAND,
            value=query_command_hash,
        ),
        sealed_candidate_sha256=sealed_candidate_sha256,
        candidate_sha256="f" * 64,
        trusted_statement_sha256="1" * 64,
        bundle_manifest_sha256="2" * 64,
        execution_authority=_authority(),
    )

    assert artifact.schema_version == "autolean.oci-execution-evidence.v2"
    assert artifact.execution_authority.fencing_token == 7


def test_oci_execution_authority_rejects_naive_expiry_and_unsafe_worker() -> None:
    payload = _authority().model_dump()
    with pytest.raises(ValidationError, match="timezone-aware"):
        OciExecutionAuthorityV1.model_validate({**payload, "expires_at": datetime(2030, 1, 1)})

    with pytest.raises(ValidationError, match="worker_id"):
        OciExecutionAuthorityV1.model_validate({**payload, "worker_id": "../unsafe worker"})


def test_oci_v2_rejects_a_command_hash_that_does_not_bind_the_handoff() -> None:
    with pytest.raises(ValidationError, match="does not bind"):
        OciVerificationArtifactV2(
            worker_image_digest="sha256:" + "c" * 64,
            wrapper_protocol="autolean.oci-lean-wrapper.v2",
            command_policy_hash=DigestV1(
                kind=HashKindV1.VERIFICATION_COMMAND,
                value="d" * 64,
            ),
            command_hash=DigestV1(
                kind=HashKindV1.VERIFICATION_COMMAND,
                value="e" * 64,
            ),
            compile_command_hash=DigestV1(
                kind=HashKindV1.VERIFICATION_COMMAND,
                value="3" * 64,
            ),
            query_command_hash=DigestV1(
                kind=HashKindV1.VERIFICATION_COMMAND,
                value="4" * 64,
            ),
            sealed_candidate_sha256="5" * 64,
            candidate_sha256="f" * 64,
            trusted_statement_sha256="1" * 64,
            bundle_manifest_sha256="2" * 64,
            execution_authority=_authority(),
        )
