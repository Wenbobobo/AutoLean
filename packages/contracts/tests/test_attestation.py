from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from autolean_contracts import (
    AttestationError,
    AttestationPurposeV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
)


def test_hmac_attestation_is_domain_bound_expiring_and_revocable() -> None:
    clock_state = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    key = HmacAttestationKeyV1(
        key_id="builder-test-v1",
        secret=b"contracts-test-secret-material-0123456789",
        allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
    )
    signer = HmacAttestationSignerV1(key, clock=clock)
    verifier = HmacAttestationVerifierV1({key.key_id: key}, clock=clock)
    payload = {"contract_hash": "a" * 64, "bundle_hash": "b" * 64}
    attestation = signer.issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=payload,
        evidence_identity="builder-freeze-run",
        ttl_seconds=60,
        nonce="n" * 24,
    )

    verifier.verify(
        attestation,
        expected_purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=payload,
    )
    with pytest.raises(AttestationError, match="payload hash"):
        verifier.verify(
            attestation,
            expected_purpose=AttestationPurposeV1.BUILDER_FREEZE,
            payload={"contract_hash": "c" * 64, "bundle_hash": "b" * 64},
        )
    with pytest.raises(AttestationError, match="purpose"):
        verifier.verify(
            attestation,
            expected_purpose=AttestationPurposeV1.VERIFICATION,
            payload=payload,
        )

    clock_state["now"] += timedelta(seconds=61)
    with pytest.raises(AttestationError, match="expired"):
        verifier.verify(
            attestation,
            expected_purpose=AttestationPurposeV1.BUILDER_FREEZE,
            payload=payload,
        )

    revoked_key = HmacAttestationKeyV1(
        key_id=key.key_id,
        secret=key.secret,
        allowed_purposes=key.allowed_purposes,
        revoked=True,
    )
    revoked_verifier = HmacAttestationVerifierV1(
        {revoked_key.key_id: revoked_key},
        clock=clock,
    )
    with pytest.raises(AttestationError, match="revoked"):
        revoked_verifier.verify(
            attestation,
            expected_purpose=AttestationPurposeV1.BUILDER_FREEZE,
            payload=payload,
        )

    mixed_role_key = HmacAttestationKeyV1(
        key_id="mixed-role-test-v1",
        secret=b"mixed-role-test-secret-material-0123456789",
        allowed_purposes=frozenset(
            {AttestationPurposeV1.BUILDER_FREEZE, AttestationPurposeV1.VERIFICATION}
        ),
    )
    mixed_attestation = HmacAttestationSignerV1(mixed_role_key, clock=clock).issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=payload,
        evidence_identity="mixed-role-run",
        ttl_seconds=60,
        nonce="m" * 24,
    )
    with pytest.raises(AttestationError, match="role-dedicated"):
        HmacAttestationVerifierV1(
            {mixed_role_key.key_id: mixed_role_key},
            clock=clock,
        ).verify(
            mixed_attestation,
            expected_purpose=AttestationPurposeV1.BUILDER_FREEZE,
            payload=payload,
        )
