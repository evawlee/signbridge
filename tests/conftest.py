import pytest

from signbridge import (
    TagEvent,
    ArtifactRequest,
    KeyRegistration,
    Token,
    MutationPolicy,
    AttestationGateway,
    TokenIssuer,
    TransparencyLog,
    AuditLog,
    SigningKeystore,
    RegistryClient,
)


@pytest.fixture(autouse=True)
def _wipe_class_state():
    TransparencyLog._entries = {}
    TransparencyLog._revoked_signatures = set()
    yield
    TransparencyLog._entries = {}
    TransparencyLog._revoked_signatures = set()


@pytest.fixture
def keystore():
    ks = SigningKeystore()
    ks.register("key-prod-001", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")
    ks.register("key-prod-002", "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----")
    return ks


@pytest.fixture
def transparency():
    return TransparencyLog()


@pytest.fixture
def audit():
    return AuditLog()


@pytest.fixture
def registry():
    return RegistryClient()


@pytest.fixture
def policy(keystore):
    return MutationPolicy(keystore)


@pytest.fixture
def issuer(transparency):
    iss = TokenIssuer(transparency)
    iss.store_token(Token(token_id="tok-attest-1", scope="attest", bound_repo="repo-a", issued_to="alice"))
    iss.store_token(Token(token_id="tok-release-1", scope="release", bound_repo="repo-a", issued_to="bob"))
    iss.store_token(Token(token_id="tok-admin-1", scope="admin", bound_repo=None, issued_to="carol"))
    iss.store_token(Token(token_id="tok-revoked-1", scope="attest", bound_repo="repo-a", revoked=True, issued_to="dave"))
    return iss


@pytest.fixture
def gateway(policy, issuer, transparency, audit):
    return AttestationGateway(policy, issuer, transparency, audit)


@pytest.fixture
def benign_event():
    return TagEvent(
        repo_id="repo-a",
        tag_name="v1.0.0",
        mutation_kind="initial_create",
        sha="abcdef1234567890",
        signed=True,
        signing_key_id="key-prod-001",
        pusher="alice",
    )


@pytest.fixture
def attest_token(issuer):
    return issuer.get("tok-attest-1")


@pytest.fixture
def release_token(issuer):
    return issuer.get("tok-release-1")


@pytest.fixture
def admin_token(issuer):
    return issuer.get("tok-admin-1")
