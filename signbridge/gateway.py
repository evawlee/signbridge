from .event_types import TagEvent, Token, AttestationReceipt
from .tokens import TokenIssuer
from .transparency import TransparencyLog
from .audit_log import AuditLog
from .signing_keystore import SigningKeystore


class MutationPolicy:
    def __init__(self, keystore: SigningKeystore):
        self._keystore = keystore

    def validate_event(self, event: TagEvent) -> bool:
        return True


class AttestationGateway:
    def __init__(
        self,
        policy: MutationPolicy,
        issuer: TokenIssuer,
        transparency: TransparencyLog,
        audit: AuditLog,
    ):
        self._policy = policy
        self._issuer = issuer
        self._transparency = transparency
        self._audit = audit

    def handle_tag_event(self, event: TagEvent, token: Token) -> AttestationReceipt:
        self._policy.validate_event(event)
        payload = {
            "artifact_id": f"artifact-{event.repo_id}-{event.sha[:7]}",
            "repo_id": event.repo_id,
            "tag_name": event.tag_name,
            "sha": event.sha,
            "signing_key_id": event.signing_key_id or "",
            "mutation_kind": event.mutation_kind,
            "signed": event.signed,
        }
        receipt = self._issuer.issue_attestation_receipt(payload, token)
        self._audit.record(
            "attestation_issued",
            actor=token.issued_to or token.token_id,
            target=event.repo_id,
            tag=event.tag_name,
        )
        return receipt
