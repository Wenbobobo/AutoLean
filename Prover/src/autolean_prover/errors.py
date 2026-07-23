from __future__ import annotations


class ProverError(Exception):
    """Base class for errors that are safe to surface at the Prover boundary."""


class ConfigurationError(ProverError):
    """Provider or harness configuration is incomplete or unsafe."""


class PolicyViolation(ConfigurationError):
    """Configuration requested a provider, model, endpoint, or action outside policy."""


class CapabilityError(ProverError):
    """A provider cannot satisfy all explicitly required capabilities."""


class ProviderResponseError(ProverError):
    """A provider returned malformed, truncated, or otherwise unusable output."""


class ExecutionPolicyError(ProverError):
    """A process request violated the clean execution policy."""


class ValidationError(ProverError):
    """A proof artifact violated an immutable contract or write boundary."""

    def __init__(self, code: str, message: str | None = None) -> None:
        if message is None:
            message = code
            code = "validation_error"
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
