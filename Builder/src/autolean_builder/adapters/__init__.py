"""Protocol-only adapters for untrusted Builder-side research inputs."""

from .research_scout import (
    ImmutableArtifactCommitmentV1,
    ResearchScoutAdapterError,
    ResearchScoutAdapterV1,
    ResearchScoutAuthorityV1,
    ResearchScoutEgressClassV1,
    ResearchScoutInputArtifactsV1,
    ResearchScoutProposalKindV1,
    ResearchScoutProposalV1,
    ResearchScoutRequestV1,
    ResearchScoutResponseV1,
    ResearchScoutRoleV1,
    ResearchScoutSourceRefV1,
)

__all__ = [
    "ImmutableArtifactCommitmentV1",
    "ResearchScoutAdapterError",
    "ResearchScoutAdapterV1",
    "ResearchScoutAuthorityV1",
    "ResearchScoutEgressClassV1",
    "ResearchScoutInputArtifactsV1",
    "ResearchScoutProposalKindV1",
    "ResearchScoutProposalV1",
    "ResearchScoutRequestV1",
    "ResearchScoutResponseV1",
    "ResearchScoutRoleV1",
    "ResearchScoutSourceRefV1",
]
