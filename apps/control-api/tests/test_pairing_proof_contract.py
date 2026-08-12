from __future__ import annotations

import base64
import hashlib
import json
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from control_api.security import pairing_start_proof

_VECTOR_PATH = (
    Path(__file__).resolve().parents[3]
    / "packages"
    / "control-protocol"
    / "fixtures"
    / "pairing-proof-v2.json"
)


def _vector() -> dict[str, object]:
    return json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))


def _proof(vector: dict[str, object]) -> bytes:
    return pairing_start_proof(
        pairing_id=uuid.UUID(str(vector["pairing_id"])),
        created_at=str(vector["created_at"]),
        audience=str(vector["audience"]),
        public_key=str(vector["public_key"]),
        code_commitment=str(vector["code_commitment"]),
        poll_token_commitment=str(vector["poll_token_commitment"]),
        refresh_credential_commitment=str(vector["refresh_credential_commitment"]),
        display_name=str(vector["display_name"]),
        connector_version=str(vector["connector_version"]),
        codex_version=str(vector["codex_version"]),
        workspace_roots=[str(root) for root in vector["workspace_roots"]],
    )


def test_pairing_v2_proof_matches_shared_connector_vector() -> None:
    vector = _vector()
    proof = _proof(vector)
    assert hashlib.sha256(proof).hexdigest() == vector["proof_sha256"]
    public_key = base64.urlsafe_b64decode(str(vector["public_key"]) + "=")
    signature = base64.urlsafe_b64decode(str(vector["signature"]) + "==")
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, proof)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("audience", "https://other.example/codex-api/v1/device-pairings/start"),
        ("display_name", "Contract Mac 2"),
        ("poll_token_commitment", "0" * 64),
        ("workspace_roots", ["/Volumes/Work", "/Users/example/Projects"]),
    ),
)
def test_pairing_v2_proof_binds_each_mutated_field(
    field: str,
    replacement: object,
) -> None:
    vector = _vector()
    vector[field] = replacement
    assert hashlib.sha256(_proof(vector)).hexdigest() != vector["proof_sha256"]
