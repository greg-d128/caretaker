from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from caretaker import OperationContext, ProvenanceEnvelope


def test_provenance_envelope_has_canonical_bounded_projection_and_fingerprint() -> None:
    envelope = ProvenanceEnvelope(
        target_id="example.target",
        generation_id="generation-4",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation=7,
        authority_policy_fingerprint="authority-hash",
        evidence_identity="incident:123",
        evidence_fingerprint="evidence-hash",
    )

    assert envelope.as_dict() == {
        "authority_policy_fingerprint": "authority-hash",
        "authority_policy_generation": 7,
        "code_hash": "code-hash",
        "evidence_fingerprint": "evidence-hash",
        "evidence_identity": "incident:123",
        "generation_id": "generation-4",
        "policy_fingerprint": "policy-hash",
        "schema_version": 1,
        "target_id": "example.target",
    }
    assert len(envelope.fingerprint) == 64
    with pytest.raises(FrozenInstanceError):
        envelope.target_id = "other"  # type: ignore[misc]


def test_provenance_projection_reads_legacy_fields_and_ignores_family_fields() -> None:
    envelope = ProvenanceEnvelope.from_mapping(
        {
            "provenance_schema_version": 1,
            "target_id": "legacy.target",
            "policy_fingerprint": "policy-hash",
            "authority_policy_generation": "deployment-3",
            "family_specific_field": {"not": "shared provenance"},
        }
    )

    assert envelope.target_id == "legacy.target"
    assert envelope.authority_policy_generation == "deployment-3"
    assert envelope.evidence_identity is None
    assert "family_specific_field" not in envelope.as_dict()


def test_provenance_envelope_rejects_unsupported_schema_and_unbounded_values() -> None:
    with pytest.raises(ValueError, match="unsupported provenance schema"):
        ProvenanceEnvelope(schema_version=2)
    with pytest.raises(ValueError, match="character limit"):
        ProvenanceEnvelope(target_id="x" * 257)
    with pytest.raises(ValueError, match="non-negative"):
        ProvenanceEnvelope(authority_policy_generation=-1)
    with pytest.raises(ValueError, match="string, integer"):
        ProvenanceEnvelope(authority_policy_generation=True)


def test_operation_context_exposes_provenance_without_changing_its_wire_shape() -> None:
    context = OperationContext(
        operation_id=uuid4(),
        target_id="context.target",
        policy_snapshot_id=uuid4(),
        policy_fingerprint="policy-hash",
        authority_policy_generation=4,
        authority_policy_fingerprint="authority-hash",
        evidence_identity="incident:123",
        evidence_fingerprint="evidence-hash",
    )

    assert context.provenance == ProvenanceEnvelope(
        target_id="context.target",
        policy_fingerprint="policy-hash",
        authority_policy_generation=4,
        authority_policy_fingerprint="authority-hash",
        evidence_identity="incident:123",
        evidence_fingerprint="evidence-hash",
    )
    assert "provenance" not in context.as_dict()
