"""Append-only validation for proposal-only research-scout events.

The control plane stores these records solely as an audit trail.  They are intentionally unable
to bind a bundle, claim a lease, change a graph, create/freeze a contract, submit a proof, or
produce a verification or release decision.
"""

from __future__ import annotations

from autolean_contracts.research_advisory import ResearchAdvisoryEventV1

from .errors import ProjectionError
from .events import StoredEvent, canonical_json

RESEARCH_ADVISORY_ENTITY_TYPE = "research_advisory_v1"
RESEARCH_ADVISORY_EVENT_TYPES = frozenset({"research_hypothesis", "research_observation"})


def validate_research_advisory_event(event: StoredEvent) -> ResearchAdvisoryEventV1:
    """Validate one stored advisory event before projecting or replaying it.

    This check is intentionally strict even though the Dashboard discards the payload.  An event
    that merely *looks* like an advisory must not acquire a benign-looking UI representation if
    its identity, immutable payload, or proposal-only authority boundary has been substituted.
    """

    if (
        event.entity_type != RESEARCH_ADVISORY_ENTITY_TYPE
        or event.entity_sequence != 1
        or event.metadata != {}
        or event.event_type not in RESEARCH_ADVISORY_EVENT_TYPES
    ):
        raise ProjectionError("research advisory event has an invalid append-only identity")
    try:
        advisory = ResearchAdvisoryEventV1.model_validate(event.payload)
    except ValueError as error:
        raise ProjectionError("research advisory event violates the V1 public schema") from error
    if event.entity_id != advisory.proposal_id or event.event_type != advisory.event_kind.value:
        raise ProjectionError("research advisory event disagrees with its immutable proposal")
    if canonical_json(advisory.model_dump(mode="json")) != canonical_json(event.payload):
        raise ProjectionError("research advisory event payload is not its canonical V1 projection")
    return advisory
