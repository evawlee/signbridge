from .event_types import (
    Token,
    AttestationReceipt,
    ArtifactRequest,
    KeyRegistration,
)
from .transparency import TransparencyLog


class TokenIssuer:
    def __init__(self, transparency: TransparencyLog):
        self._tokens = {}
        self._transparency = transparency
        self._next_seq = 1

    def store_token(self, token: Token) -> None:
        self._tokens[token.token_id] = token

    def get(self, token_id: str):
        return self._tokens.get(token_id)

    def issue_attestation_receipt(
        self,
        payload: dict,
        token: Token,
    ) -> AttestationReceipt:
        receipt_id = f"recpt-{self._next_seq:06d}"
        self._next_seq += 1
        receipt = AttestationReceipt(
            receipt_id=receipt_id,
            artifact_id=payload["artifact_id"],
            repo_id=payload["repo_id"],
            tag_name=payload["tag_name"],
            sha=payload["sha"],
            issued_by=token.issued_to or token.token_id,
            signing_key_id=payload.get("signing_key_id", ""),
            extra={},
        )
        self._transparency.add(receipt_id, payload | {"receipt_id": receipt_id})
        return receipt

    def release_to_registry(
        self,
        request: ArtifactRequest,
        token: Token,
        registry_client,
    ) -> dict:
        receipt_id_for_artifact = None
        for rid, record in self._transparency._entries.items():
            if record.get("artifact_id") == request.artifact_id:
                receipt_id_for_artifact = rid
                break
        return registry_client.promote(
            request.artifact_id,
            request.repo_id,
            receipt_id_for_artifact or "pending",
        )

    def register_signing_key(
        self,
        registration: KeyRegistration,
        token: Token,
        keystore,
    ) -> str:
        keystore.register(registration.key_id, registration.public_pem)
        return registration.key_id
