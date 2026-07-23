"""Role-scoped context packs projected only from a frozen Builder-Prover contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from autolean_contracts import (
    DigestV1,
    EndpointClassV1,
    FormalizationTaskBundleV1,
    HashKindV1,
    PermissionDecisionV1,
    digest_model,
)

from autolean_prover.errors import PolicyViolation, ValidationError


class SpecialistRole(StrEnum):
    PLANNER = "planner"
    RETRIEVER = "retriever"
    TACTIC = "tactic"
    VERIFIER = "verifier"


@dataclass(frozen=True, slots=True)
class ContextItem:
    kind: str
    text: str

    def __post_init__(self) -> None:
        if not self.kind.strip() or not self.text.strip():
            raise ValidationError("context items need a kind and non-empty text")


@dataclass(frozen=True, slots=True)
class ContextPack:
    role: SpecialistRole
    contract_id: str
    revision: int
    contract_hash: str
    proof_boundary_hash: str
    items: tuple[ContextItem, ...]

    def render(self) -> str:
        return "\n\n".join(f"[{item.kind}]\n{item.text}" for item in self.items)

    def content_hash(self) -> DigestV1:
        """Return the exact role-scoped context identity without retaining prompt text in a log."""

        return digest_model(
            HashKindV1.PROMPT,
            {
                "schema_version": "autolean.context-pack.v1",
                "role": self.role.value,
                "contract_id": self.contract_id,
                "revision": self.revision,
                "contract_hash": self.contract_hash,
                "proof_boundary_hash": self.proof_boundary_hash,
                "items": [{"kind": item.kind, "text": item.text} for item in self.items],
            },
        )


class ContextPackBuilder:
    """Reduce context pressure without giving a specialized worker mutable Builder state."""

    def build(
        self,
        bundle: FormalizationTaskBundleV1,
        *,
        role: SpecialistRole,
        endpoint_class: EndpointClassV1,
        max_graph_nodes: int = 24,
    ) -> ContextPack:
        if max_graph_nodes <= 0:
            raise ValueError("max_graph_nodes must be positive")
        self._authorize_egress(bundle, endpoint_class)
        contract = bundle.contract
        base: tuple[ContextItem, ...] = (
            ContextItem(
                "contract",
                f"id={contract.contract_id.value} revision={contract.revision}",
            ),
            ContextItem("lean_statement", contract.formal.lean_statement_source),
            ContextItem(
                "environment",
                "\n".join(
                    (
                        f"lean={contract.formal.environment.lean_version}",
                        f"mathlib={contract.formal.environment.mathlib_revision}",
                        "imports=" + ", ".join(contract.formal.imports_allowlist),
                    )
                ),
            ),
        )
        items: tuple[ContextItem, ...]
        if role is SpecialistRole.PLANNER:
            items = (
                *base,
                ContextItem("normalized_mathematics", contract.mathematics.normalized_statement),
                ContextItem(
                    "assumptions",
                    "\n".join(contract.mathematics.assumptions) or "(none)",
                ),
            )
        elif role is SpecialistRole.RETRIEVER:
            items = (
                *base,
                ContextItem("formal_frontier", self._formal_frontier(bundle, max_graph_nodes)),
            )
        elif role is SpecialistRole.TACTIC:
            items = (
                *base,
                ContextItem(
                    "proof_boundary",
                    "Submit only a proof term for the frozen declaration.",
                ),
            )
        else:
            items = (
                *base,
                ContextItem(
                    "verification_boundary",
                    "Kernel build, immutable statement comparison, and axiom allowlist are "
                    "required.",
                ),
            )
        return ContextPack(
            role=role,
            contract_id=contract.contract_id.value,
            revision=contract.revision,
            contract_hash=contract.semantic_hash().value,
            proof_boundary_hash=bundle.proof_boundary.boundary_hash.value,
            items=items,
        )

    @staticmethod
    def _authorize_egress(bundle: FormalizationTaskBundleV1, endpoint: EndpointClassV1) -> None:
        rights = bundle.contract.rights
        if rights.overall_decision in {PermissionDecisionV1.UNKNOWN, PermissionDecisionV1.DENY}:
            raise PolicyViolation("unreviewed or denied source rights cannot enter a model context")
        if endpoint is EndpointClassV1.NONE:
            raise PolicyViolation("a model context requires a concrete endpoint class")
        if endpoint is EndpointClassV1.LOCAL:
            return
        if rights.model_egress is not PermissionDecisionV1.ALLOW:
            raise PolicyViolation("source rights do not permit external model egress")
        if endpoint not in rights.allowed_endpoint_classes:
            raise PolicyViolation("endpoint class is not approved by the source rights record")

    @staticmethod
    def _formal_frontier(bundle: FormalizationTaskBundleV1, limit: int) -> str:
        nodes = bundle.graphs.formal.nodes[:limit]
        if not nodes:
            return "(no formal graph nodes recorded)"
        return "\n".join(f"{node.kind.value}: {node.declaration_name}" for node in nodes)
