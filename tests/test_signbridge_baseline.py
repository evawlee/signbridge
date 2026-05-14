import pytest

from signbridge import (
    TagEvent,
    ArtifactRequest,
    KeyRegistration,
    Token,
    TokenIssuer,
    TransparencyLog,
    AuditLog,
    SigningKeystore,
    RegistryClient,
)


class TestGatewayBenignFlow:
    def test_benign_event_creates_receipt(self, gateway, benign_event, attest_token):
        receipt = gateway.handle_tag_event(benign_event, attest_token)
        assert receipt.repo_id == "repo-a"
        assert receipt.tag_name == "v1.0.0"

    def test_benign_event_records_to_transparency_log(self, gateway, benign_event, attest_token, transparency):
        gateway.handle_tag_event(benign_event, attest_token)
        assert transparency.size() == 1

    def test_benign_event_writes_audit_entry(self, gateway, benign_event, attest_token, audit):
        gateway.handle_tag_event(benign_event, attest_token)
        assert audit.size() == 1
        assert audit.latest()["action"] == "attestation_issued"

    def test_benign_event_returns_receipt_with_sha(self, gateway, benign_event, attest_token):
        receipt = gateway.handle_tag_event(benign_event, attest_token)
        assert receipt.sha == benign_event.sha


class TestTokenIssuerBasic:
    def test_store_and_get_token(self, issuer):
        t = issuer.get("tok-attest-1")
        assert t is not None
        assert t.scope == "attest"

    def test_get_returns_none_for_unknown_token(self, issuer):
        assert issuer.get("tok-does-not-exist") is None

    def test_issue_receipt_increments_sequence(self, issuer, attest_token):
        payload = {
            "artifact_id": "art-1",
            "repo_id": "repo-a",
            "tag_name": "v1",
            "sha": "1111111",
            "signing_key_id": "key-prod-001",
        }
        r1 = issuer.issue_attestation_receipt(payload, attest_token)
        r2 = issuer.issue_attestation_receipt(payload, attest_token)
        assert r1.receipt_id != r2.receipt_id


class TestTokenIssuerAccess:
    def test_issue_attestation_with_attest_scope_token_succeeds(self, issuer, attest_token):
        payload = {
            "artifact_id": "art-2",
            "repo_id": "repo-a",
            "tag_name": "v1",
            "sha": "2222222",
            "signing_key_id": "key-prod-001",
        }
        receipt = issuer.issue_attestation_receipt(payload, attest_token)
        assert receipt.repo_id == "repo-a"

    def test_release_to_registry_with_release_scope_token_succeeds(self, issuer, release_token, registry, transparency):
        transparency.add("recpt-existing", {"artifact_id": "art-3", "repo_id": "repo-a"})
        req = ArtifactRequest(artifact_id="art-3", repo_id="repo-a", requested_by="bob")
        result = issuer.release_to_registry(req, release_token, registry)
        assert result["status"] == "promoted"

    def test_register_signing_key_with_admin_scope_token_succeeds(self, issuer, admin_token, keystore):
        reg = KeyRegistration(
            key_id="key-new-001",
            public_pem="-----BEGIN PUBLIC KEY-----\nNEW\n-----END PUBLIC KEY-----",
            submitter="carol",
            submitter_ip="10.7.0.5",
        )
        result = issuer.register_signing_key(reg, admin_token, keystore)
        assert result == "key-new-001"
        assert keystore.known("key-new-001")


class TestTransparencyLogBasic:
    def test_add_and_lookup(self, transparency):
        transparency.add("r-1", {"artifact_id": "art-x"})
        assert transparency.lookup("r-1") == {"artifact_id": "art-x"}

    def test_lookup_returns_none_for_unknown(self, transparency):
        assert transparency.lookup("r-missing") is None

    def test_has_attestation_for_known_artifact(self, transparency):
        transparency.add("r-2", {"artifact_id": "art-y"})
        assert transparency.has_attestation_for("art-y") is True

    def test_size_reflects_entries(self, transparency):
        transparency.add("r-3", {"artifact_id": "art-z"})
        transparency.add("r-4", {"artifact_id": "art-w"})
        assert transparency.size() == 2


class TestSigningKeystoreBasic:
    def test_register_and_get(self, keystore):
        keystore.register("key-test-1", "PEM-DATA")
        assert keystore.get("key-test-1") == "PEM-DATA"

    def test_get_returns_none_for_unknown(self, keystore):
        assert keystore.get("key-not-there") is None

    def test_mark_revoked_and_is_revoked(self, keystore):
        keystore.mark_revoked("key-prod-002")
        assert keystore.is_revoked("key-prod-002") is True

    def test_known_returns_true_after_register(self, keystore):
        assert keystore.known("key-prod-001") is True


class TestAuditLogBasic:
    def test_record_and_size(self, audit):
        audit.record("test_action", actor="someone")
        assert audit.size() == 1

    def test_entries_for_filters_by_actor(self, audit):
        audit.record("a1", actor="alice")
        audit.record("a2", actor="bob")
        audit.record("a3", actor="alice")
        assert len(audit.entries_for("alice")) == 2

    def test_latest_returns_most_recent(self, audit):
        audit.record("first", actor="x")
        audit.record("second", actor="y")
        assert audit.latest()["action"] == "second"


class TestRegistryClientBasic:
    def test_promote_and_count(self, registry):
        registry.promote("art-1", "repo-a", "recpt-1")
        assert registry.count() == 1

    def test_promotions_for_filters_by_repo(self, registry):
        registry.promote("art-1", "repo-a", "recpt-1")
        registry.promote("art-2", "repo-b", "recpt-2")
        assert len(registry.promotions_for("repo-a")) == 1
