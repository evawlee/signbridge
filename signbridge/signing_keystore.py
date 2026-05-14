from typing import Optional


class SigningKeystore:
    def __init__(self):
        self._keys = {}
        self._revoked_key_ids = set()

    def register(self, key_id: str, public_pem: str) -> None:
        self._keys[key_id] = public_pem

    def get(self, key_id: str) -> Optional[str]:
        return self._keys.get(key_id)

    def mark_revoked(self, key_id: str) -> None:
        self._revoked_key_ids.add(key_id)

    def is_revoked(self, key_id: str) -> bool:
        return key_id in self._revoked_key_ids

    def known(self, key_id: str) -> bool:
        return key_id in self._keys
