import time
from typing import Optional


class AuditLog:
    def __init__(self):
        self._entries = []

    def record(self, action: str, actor: str, target: Optional[str] = None, **meta) -> None:
        entry = {
            "ts": time.time(),
            "action": action,
            "actor": actor,
            "target": target,
            "meta": dict(meta),
        }
        self._entries.append(entry)

    def entries_for(self, actor: str) -> list:
        return [e for e in self._entries if e["actor"] == actor]

    def latest(self) -> Optional[dict]:
        return self._entries[-1] if self._entries else None

    def size(self) -> int:
        return len(self._entries)
