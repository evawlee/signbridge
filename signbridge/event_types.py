from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class TagEvent:
    repo_id: str
    tag_name: str
    mutation_kind: str
    sha: str
    signed: bool
    signing_key_id: Optional[str]
    pusher: str


@dataclass(frozen=True)
class ArtifactRequest:
    artifact_id: str
    repo_id: str
    requested_by: str


@dataclass(frozen=True)
class KeyRegistration:
    key_id: str
    public_pem: str
    submitter: str
    submitter_ip: str


@dataclass
class Token:
    token_id: str
    scope: str
    bound_repo: Optional[str]
    revoked: bool = False
    issued_to: str = ""


@dataclass
class AttestationReceipt:
    receipt_id: str
    artifact_id: str
    repo_id: str
    tag_name: str
    sha: str
    issued_by: str
    signing_key_id: str
    extra: dict = field(default_factory=dict)


class PolicyViolation(Exception):
    pass


class AuthorizationError(Exception):
    pass


class AttestationMissing(Exception):
    pass
