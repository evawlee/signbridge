from typing import Optional


class TransparencyLog:
    _entries = {}
    _revoked_signatures = set()

    def add(self, receipt_id: str, record: dict) -> None:
        self._entries[receipt_id] = record

    def lookup(self, receipt_id: str) -> Optional[dict]:
        return self._entries.get(receipt_id)

    def has_attestation_for(self, artifact_id: str) -> bool:
        for record in self._entries.values():
            if record.get("artifact_id") == artifact_id:
                return True
        return False

    def revoke_signature(self, sig_id: str) -> None:
        self._revoked_signatures.add(sig_id)

    def is_signature_revoked(self, sig_id: str) -> bool:
        return sig_id in self._revoked_signatures

    def size(self) -> int:
        return len(self._entries)

    def revoked_count(self) -> int:
        return len(self._revoked_signatures)
