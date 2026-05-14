class RegistryClient:
    def __init__(self):
        self._promoted = []

    def promote(self, artifact_id: str, repo_id: str, receipt_id: str) -> dict:
        record = {
            "artifact_id": artifact_id,
            "repo_id": repo_id,
            "receipt_id": receipt_id,
            "status": "promoted",
        }
        self._promoted.append(record)
        return record

    def promotions_for(self, repo_id: str) -> list:
        return [p for p in self._promoted if p["repo_id"] == repo_id]

    def count(self) -> int:
        return len(self._promoted)
