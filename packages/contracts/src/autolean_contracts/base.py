from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Never, Self

from pydantic import BaseModel, ConfigDict


def utc_now() -> datetime:
    return datetime.now(UTC)


class FrozenDict(dict[Any, Any]):
    """A ``dict``-compatible mapping which refuses in-place mutation.

    Contract fields intentionally retain ``dict`` annotations for JSON and Pydantic
    compatibility.  ``ConfigDict(frozen=True)`` only protects attribute assignment,
    so this small wrapper closes the otherwise mutable nested-container escape hatch.
    """

    @staticmethod
    def _immutable() -> Never:
        raise TypeError("contract mappings are immutable")

    def __setitem__(self, _key: Any, _value: Any) -> Never:
        self._immutable()

    def __delitem__(self, _key: Any) -> Never:
        self._immutable()

    def __or__(self, other: Mapping[Any, Any]) -> FrozenDict:
        frozen = _deep_freeze({**self, **other})
        if not isinstance(frozen, FrozenDict):
            raise TypeError("contract mapping merge did not produce an immutable mapping")
        return frozen

    def __ior__(self, _other: object) -> FrozenDict:
        self._immutable()

    def clear(self) -> Never:
        self._immutable()

    def pop(self, _key: Any, _default: Any = None) -> Never:
        self._immutable()

    def popitem(self) -> Never:
        self._immutable()

    def setdefault(self, _key: Any, _default: Any = None) -> Never:
        self._immutable()

    def update(self, *_args: Any, **_kwargs: Any) -> Never:
        self._immutable()

    def copy(self) -> FrozenDict:
        return self

    def __copy__(self) -> FrozenDict:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> FrozenDict:
        memo[id(self)] = self
        return self

    def __reduce__(self) -> tuple[type[FrozenDict], tuple[dict[Any, Any]]]:
        # ``dict``'s default pickle restore path calls ``__setitem__``.
        return type(self), (dict(self),)


def _deep_freeze(value: Any) -> Any:
    """Recursively remove ordinary mutable containers from a contract payload."""

    if isinstance(value, FrozenDict):
        return value
    if isinstance(value, ContractModel):
        return value
    if isinstance(value, Mapping):
        return FrozenDict({_deep_freeze(key): _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_deep_freeze(item) for item in value)
    return value


class ContractModel(BaseModel):
    """Strict immutable base for every cross-component contract."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
    )

    def model_post_init(self, _context: Any) -> None:
        """Freeze validated nested payloads before a contract is exposed."""

        for field_name in type(self).model_fields:
            current = getattr(self, field_name)
            frozen = _deep_freeze(current)
            if frozen is not current:
                object.__setattr__(self, field_name, frozen)

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Return a revalidated replacement rather than Pydantic's unsafe copy.

        Pydantic's default ``model_copy(update=...)`` does not validate its update.
        That is unacceptable for a versioned cross-process contract: it would allow a
        caller to bypass state-machine, hash, and cross-field invariants.
        """

        # ``model_dump`` produces ordinary data, and ``model_validate`` applies both
        # field and model validators.  Nested contract values are immutable, so a
        # shallow dump is already isolated; preserve the public ``deep`` option for
        # callers that expect an independently copied transient payload.
        payload = self.model_dump(mode="python", round_trip=True)
        if deep:
            import copy

            payload = copy.deepcopy(payload)
        if update:
            payload.update(dict(update))
        return type(self).model_validate(payload)
