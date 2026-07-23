class ControlPlaneError(Exception):
    """Base class for control-plane errors."""


class ConcurrencyError(ControlPlaneError):
    """An entity changed after the caller observed it."""

    def __init__(self, entity_type: str, entity_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"{entity_type}/{entity_id} sequence mismatch: expected {expected}, actual {actual}"
        )
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.expected = expected
        self.actual = actual


class IdempotencyConflict(ControlPlaneError):
    """An idempotency key was reused for a different request."""


class AttestationReplay(ControlPlaneError):
    """A signed authority nonce was already consumed by another state transition."""


class ContractRevisionConflict(ControlPlaneError):
    """A frozen contract revision is already bound to another immutable bundle."""


class TaskNotFound(ControlPlaneError):
    """The requested task does not exist."""


class InvalidTransition(ControlPlaneError):
    """The requested task lifecycle transition is not legal."""


class LeaseUnavailable(ControlPlaneError):
    """A task already has a live lease."""


class StaleFence(ControlPlaneError):
    """A worker attempted to act through an expired or superseded lease."""


class ProjectionError(ControlPlaneError):
    """Projection state is inconsistent with the canonical event stream."""


class ArtifactNotFound(ControlPlaneError):
    """A content-addressed artifact does not exist."""


class ArtifactCorruption(ControlPlaneError):
    """Stored artifact bytes do not match their content address."""
