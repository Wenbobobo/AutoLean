"""Provider configuration guardrails; secret values never enter configuration objects."""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from autolean_contracts import EndpointClassV1

from autolean_prover.errors import ConfigurationError, PolicyViolation

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_REASONING_EFFORT = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_FORBIDDEN_TERMS = ("anthropic", "claude")
_OFFICIAL_OPENAI_PROVIDER_IDS = frozenset({"openai", "openai-responses"})
_OFFICIAL_OPENAI_HOST = "api.openai.com"
_SENSITIVE_PATH_MARKER = re.compile(
    r"(?:^|[/;:_=-])(?:api[_-]?key|token|secret|password|credential|bearer)(?:$|[/;:_=-])"
)


@dataclass(frozen=True, slots=True)
class EndpointTarget:
    """A parsed endpoint with its network classification, never a credential value."""

    base_url: str
    host: str
    port: int | None
    path: str
    local: bool


def _normalized(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _validate_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigurationError(f"{label} must be a non-empty string")
    if value != value.strip() or any(character.isspace() for character in value):
        raise ConfigurationError(f"{label} must not contain whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ConfigurationError(f"{label} must not contain control characters")
    normalized = _normalized(value)
    if any(term in normalized for term in _FORBIDDEN_TERMS):
        raise PolicyViolation("Anthropic and Claude identifiers are not permitted in AutoLean")
    return normalized


def validate_provider_identity(provider_id: str, model_id: str) -> None:
    _validate_identifier(provider_id, label="provider_id")
    _validate_identifier(model_id, label="model_id")


def validate_registry_name(name: str) -> str:
    """Registry keys are routing identifiers and must follow the same provider policy."""

    return _validate_identifier(name, label="provider registry name")


def validate_reasoning_effort(value: str | None, *, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not _REASONING_EFFORT.fullmatch(value):
        raise ConfigurationError(
            f"{label} must be a lower-case identifier containing letters, digits, '_' or '-'"
        )


def validate_positive_timeout(value: float, *, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ConfigurationError(f"{label} must be a finite positive number")


def validate_secret_reference(environment_variable: str | None) -> None:
    if environment_variable is None:
        return
    if not isinstance(environment_variable, str) or not _ENV_NAME.fullmatch(environment_variable):
        raise ConfigurationError(
            "API credentials must be referenced by a valid environment variable name"
        )


def resolve_secret_reference(
    environment_variable: str | None,
    environment: Mapping[str, str],
) -> str | None:
    """Resolve a credential only at the network boundary and never include it in an error."""

    if environment_variable is None:
        return None
    value = environment.get(environment_variable)
    if not isinstance(value, str) or not value or "\r" in value or "\n" in value:
        raise ConfigurationError(
            f"required API key environment variable is unset or unsafe: {environment_variable}"
        )
    return value


def _endpoint_target(base_url: str) -> EndpointTarget:
    if not isinstance(base_url, str) or not base_url:
        raise ConfigurationError("endpoint base_url must be a non-empty string")
    if base_url != base_url.strip() or "\\" in base_url or "\x00" in base_url:
        raise ConfigurationError("endpoint base_url contains unsafe whitespace or characters")
    if any(term in _normalized(unquote(base_url)) for term in _FORBIDDEN_TERMS):
        raise PolicyViolation("endpoint identifiers for Anthropic and Claude are not permitted")
    try:
        parsed = urlsplit(base_url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("endpoint base_url has an invalid host or port") from exc
    if parsed.scheme.casefold() not in {"http", "https"} or host is None:
        raise ConfigurationError("endpoint base_url must be an absolute HTTP(S) URL")
    if (
        "@" in parsed.netloc
        or parsed.username
        or parsed.password
        or "?" in base_url
        or "#" in base_url
    ):
        raise ConfigurationError(
            "endpoint base_url must not contain credentials, query, or fragment"
        )

    normalized_host = _normalized(host)
    if normalized_host.endswith(".") or not normalized_host:
        raise ConfigurationError("endpoint base_url host must be canonical")
    try:
        literal_ip = ipaddress.ip_address(normalized_host)
    except ValueError as exc:
        if not normalized_host.isascii() or not _HOSTNAME.fullmatch(normalized_host):
            raise ConfigurationError(
                "endpoint base_url host must be a canonical DNS name or IP literal"
            ) from exc
        local = normalized_host == "localhost"
    else:
        if not literal_ip.is_loopback:
            raise PolicyViolation("numeric endpoint addresses must be loopback-only")
        local = True

    decoded_path = unquote(parsed.path)
    path_segments = [segment for segment in decoded_path.split("/") if segment]
    if any(segment == ".." for segment in path_segments):
        raise ConfigurationError("endpoint base_url path must not contain parent traversal")
    if _SENSITIVE_PATH_MARKER.search(_normalized(decoded_path)):
        raise ConfigurationError("endpoint base_url path must not embed credential material")
    if parsed.scheme.casefold() == "http" and not local:
        raise PolicyViolation("non-local custom endpoints must use HTTPS")

    return EndpointTarget(
        base_url=base_url.rstrip("/"),
        host=normalized_host,
        port=port,
        path=decoded_path.rstrip("/"),
        local=local,
    )


def validate_endpoint_url(base_url: str, *, allow_custom: bool = True) -> str:
    """Validate a credential-free endpoint and return a canonical trailing-slash form."""

    target = _endpoint_target(base_url)
    if not allow_custom and (
        target.local
        or target.host != _OFFICIAL_OPENAI_HOST
        or target.port not in {None, 443}
        or target.path != "/v1"
    ):
        raise PolicyViolation("the OpenAI provider must use the official https://api.openai.com/v1")
    return target.base_url


def validate_endpoint_class(base_url: str, endpoint_class: EndpointClassV1) -> None:
    """Bind endpoint routing metadata to the actual endpoint, not caller-controlled labels."""

    if not isinstance(endpoint_class, EndpointClassV1):
        raise ConfigurationError("endpoint_class must be an EndpointClassV1 value")
    target = _endpoint_target(base_url)
    required = EndpointClassV1.LOCAL if target.local else EndpointClassV1.APPROVED_EXTERNAL
    if endpoint_class is not required:
        raise PolicyViolation(
            f"endpoint_class {endpoint_class.value!r} does not match the configured endpoint"
        )


def is_official_openai_provider(provider_id: str) -> bool:
    return _normalized(provider_id) in _OFFICIAL_OPENAI_PROVIDER_IDS
