"""Narrow authorization-gate interface for model generation.

The Prover depends on this protocol rather than on a particular control-plane database.  A
production caller injects the control-plane implementation; tests may inject a deterministic
fake.  The registry never treats a raw provider name as authority to send context to a model.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from autolean_contracts import DigestV1
from autolean_contracts.authorization import (
    ModelExecutionAuthorizationV1,
    ModelExecutionProviderBindingV1,
    ModelExecutionReservationV1,
)


class ProviderFailureCodeV1(StrEnum):
    """Stable, credential-free failure taxonomy persisted by the authorization gate."""

    PROBE_FAILED = "probe_failed_v1"
    PROBE_INVALID = "probe_invalid_v1"
    PROBE_CAPABILITY_MISMATCH = "probe_capability_mismatch_v1"
    GENERATION_FAILED = "generation_failed_v1"
    RESPONSE_INVALID = "response_invalid_v1"
    SETTLEMENT_REJECTED = "settlement_rejected_v1"
    LOCAL_POLICY_REJECTED = "local_policy_rejected_v1"


class ModelExecutionAuthorizationGate(Protocol):
    """Reserve and settle a signed model-execution capability without seeing prompt contents."""

    def preflight(
        self,
        authorization: ModelExecutionAuthorizationV1,
        *,
        provider: ModelExecutionProviderBindingV1,
        requested_input_tokens: int,
        requested_output_tokens: int,
        context_pack_hash: DigestV1 | None,
        outbound_request_hash: DigestV1,
    ) -> None:
        """Reject invalid authority before a probe can contact an external endpoint."""

    def reserve(
        self,
        authorization: ModelExecutionAuthorizationV1,
        *,
        provider: ModelExecutionProviderBindingV1,
        requested_input_tokens: int,
        requested_output_tokens: int,
        context_pack_hash: DigestV1 | None,
        outbound_request_hash: DigestV1,
    ) -> ModelExecutionReservationV1: ...

    def settle(
        self,
        reservation: ModelExecutionReservationV1,
        *,
        input_tokens: int,
        cached_input_tokens: int,
        output_tokens: int,
    ) -> None: ...

    def abandon(
        self,
        reservation: ModelExecutionReservationV1,
        *,
        failure_code: str,
    ) -> None:
        """Release a failed reservation and persist only its stable V1 failure code."""
