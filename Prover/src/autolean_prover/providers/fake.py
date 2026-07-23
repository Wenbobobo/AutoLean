from __future__ import annotations

import threading
from collections.abc import Iterable

from autolean_contracts import DigestV1, EndpointClassV1, HashKindV1, digest_model

from autolean_prover.errors import ConfigurationError, ProviderResponseError
from autolean_prover.providers.base import (
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    TokenUsage,
    require_request_capabilities,
)
from autolean_prover.providers.policy import validate_provider_identity


class FakeProvider:
    """Deterministic provider for tests and offline architecture exercises."""

    def __init__(
        self,
        responses: Iterable[str | ModelResponse],
        *,
        model_id: str = "fake-model",
        capabilities: ProviderCapabilities,
    ) -> None:
        validate_provider_identity("fake", model_id)
        if not isinstance(capabilities, ProviderCapabilities):
            raise ConfigurationError("fake provider capabilities must be ProviderCapabilities")
        self._responses = tuple(responses)
        self._model_id = model_id
        self._capabilities = capabilities
        self._next = 0
        self._lock = threading.Lock()

    @property
    def provider_id(self) -> str:
        return "fake"

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def endpoint_class(self) -> EndpointClassV1:
        return EndpointClassV1.LOCAL

    @property
    def configuration_hash(self) -> DigestV1:
        return digest_model(
            HashKindV1.CONFIG,
            {
                "schema_version": "autolean.provider-config.fake.v1",
                "provider_id": self.provider_id,
                "model_id": self.model_id,
                "endpoint_class": self.endpoint_class.value,
                "capabilities": sorted(capability.value for capability in self.capabilities.values),
            },
        )

    @property
    def capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def probe(self) -> ProviderCapabilities:
        """Useful to callers that want a local capability check without network access."""

        return self._capabilities

    def generate(self, request: ModelRequest) -> ModelResponse:
        require_request_capabilities(self, request)
        with self._lock:
            if self._next >= len(self._responses):
                raise ProviderResponseError("fake provider has no scripted response remaining")
            response = self._responses[self._next]
            self._next += 1
        if isinstance(response, ModelResponse):
            if response.provider_id != self.provider_id or response.model_id != self.model_id:
                raise ProviderResponseError(
                    "fake provider response identity does not match its configuration"
                )
            return response
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            text=response,
            # Authenticated registry calls require non-optional usage accounting.  The fake
            # adapter supplies deterministic nonzero usage so it remains useful for those tests.
            usage=TokenUsage(input_tokens=1, output_tokens=1),
        )
