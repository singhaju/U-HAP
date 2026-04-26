"""
Integration tests for the Flask webhook handler (Step 8).

Tests:
  - /healthz returns 200
  - /authorize returns correct SAR response for allow/deny decisions
  - SAR parsing edge cases
  - Audit log is written on each request
  - Context enrichment is applied
"""

import io
import json
import sys
import os
import pytest

# Ensure src/ is on the path before importing app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dsl.models import RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord
from compiler.registry import ArtifactRegistry
from audit.logger import AuditLogger
from webhook.sar import parse_sar, build_sar_response, SARParseError
import webhook.handler as handler_module

# Import Flask app
from main import app, get_registry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Flask test client with a pre-loaded registry."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def registry():
    """An ArtifactRegistry loaded with test policies."""
    reg = ArtifactRegistry()
    records = [
        # pods/prod: ABAC get, deny delete for alice, RBAC for viewer
        ABACRecord(
            resource="pods", namespace="prod", action="get",
            predicate="net == 'on-premise' AND time == 'business-hours'",
        ),
        RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
        DenyRecord(subject="alice", resource="pods", namespace="prod",
                   action="delete"),
        ACLRecord(subject="charlie", resource="pods", namespace="prod",
                  action="get"),
        # secrets/prod: wildcard deny for delete
        DenyRecord(subject="*", resource="secrets", namespace="prod",
                   action="delete"),
    ]
    reg.load(records)
    return reg


@pytest.fixture
def capture_log():
    """AuditLogger writing to a StringIO for capture."""
    buf = io.StringIO()
    return AuditLogger(stream=buf), buf


# ---------------------------------------------------------------------------
# SAR parsing tests
# ---------------------------------------------------------------------------

class TestSARParsing:
    def test_minimal_valid_sar(self):
        body = {
            "spec": {
                "user": "alice",
                "groups": ["viewer"],
                "resourceAttributes": {
                    "namespace": "prod",
                    "resource": "pods",
                    "verb": "get",
                },
            }
        }
        sar = parse_sar(body)
        assert sar.user == "alice"
        assert sar.groups == ["viewer"]
        assert sar.namespace == "prod"
        assert sar.resource == "pods"
        assert sar.verb == "get"

    def test_missing_spec_raises(self):
        with pytest.raises(SARParseError):
            parse_sar({"notspec": {}})

    def test_missing_user_raises(self):
        with pytest.raises(SARParseError):
            parse_sar({
                "spec": {
                    "groups": [],
                    "resourceAttributes": {
                        "namespace": "prod",
                        "resource": "pods",
                        "verb": "get",
                    },
                }
            })

    def test_missing_resource_attributes_raises(self):
        with pytest.raises(SARParseError):
            parse_sar({"spec": {"user": "alice"}})

    def test_extra_attrs_flattened(self):
        body = {
            "spec": {
                "user": "alice",
                "resourceAttributes": {
                    "namespace": "prod",
                    "resource": "pods",
                    "verb": "get",
                },
                "extra": {
                    "dept": ["engineering"],
                    "clearance": ["top-secret"],
                },
            }
        }
        sar = parse_sar(body)
        assert sar.extra["dept"] == "engineering"
        assert sar.extra["clearance"] == "top-secret"

    def test_default_namespace(self):
        body = {
            "spec": {
                "user": "alice",
                "resourceAttributes": {"resource": "pods", "verb": "get"},
            }
        }
        sar = parse_sar(body)
        assert sar.namespace == "default"


# ---------------------------------------------------------------------------
# SAR response building tests
# ---------------------------------------------------------------------------

class TestSARResponse:
    def test_allow_response(self):
        resp = build_sar_response(True, "rbac: viewer")
        assert resp["status"]["allowed"] is True
        assert resp["status"]["reason"] == "rbac: viewer"
        assert "denied" not in resp["status"]

    def test_deny_response(self):
        resp = build_sar_response(False, "deny rule: wildcard")
        assert resp["status"]["allowed"] is False
        assert resp["status"]["denied"] is True
        assert resp["status"]["reason"] == "deny rule: wildcard"

    def test_response_api_version(self):
        resp = build_sar_response(True, "ok")
        assert resp["apiVersion"] == "authorization.k8s.io/v1"
        assert resp["kind"] == "SubjectAccessReview"


# ---------------------------------------------------------------------------
# Handler integration tests
# ---------------------------------------------------------------------------

class TestHandleAuthorize:
    def _make_body(self, user, resource, verb, namespace="prod",
                   groups=None, extra=None):
        body = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "spec": {
                "user": user,
                "groups": groups or [],
                "resourceAttributes": {
                    "namespace": namespace,
                    "resource": resource,
                    "verb": verb,
                },
            }
        }
        if extra:
            body["spec"]["extra"] = extra
        return body

    def test_rbac_allow(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        body = self._make_body("alice", "pods", "get", groups=["viewer"])
        resp = handler_module.handle_authorize(
            request_body=body,
            source_ip="10.0.0.5",    # on-premise
            utc_hour=10,              # business hours
            registry=registry,
        )
        assert resp["status"]["allowed"] is True
        assert "rbac" in resp["status"]["reason"].lower()

    def test_abac_allow(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        body = self._make_body("alice", "pods", "get")
        resp = handler_module.handle_authorize(
            request_body=body,
            source_ip="10.0.0.5",    # on-premise -> net == 'on-premise'
            utc_hour=10,              # business hours -> time == 'business-hours'
            registry=registry,
        )
        assert resp["status"]["allowed"] is True

    def test_abac_deny_remote(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        body = self._make_body("alice", "pods", "get")
        resp = handler_module.handle_authorize(
            request_body=body,
            source_ip="8.8.8.8",    # remote
            utc_hour=10,
            registry=registry,
        )
        assert resp["status"]["allowed"] is False

    def test_specific_deny_overrides_allow(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        body = self._make_body("alice", "pods", "delete")
        resp = handler_module.handle_authorize(
            request_body=body,
            source_ip="10.0.0.5",
            utc_hour=10,
            registry=registry,
        )
        assert resp["status"]["allowed"] is False
        assert resp["status"].get("denied") is True

    def test_wildcard_deny(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        for user in ["alice", "bob", "admin"]:
            body = self._make_body(user, "secrets", "delete")
            resp = handler_module.handle_authorize(
                request_body=body,
                source_ip="10.0.0.1",
                utc_hour=10,
                registry=registry,
            )
            assert resp["status"]["allowed"] is False, f"Expected deny for {user}"

    def test_acl_allow(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        body = self._make_body("charlie", "pods", "get")
        resp = handler_module.handle_authorize(
            request_body=body,
            source_ip="8.8.8.8",    # remote — ACL should still work
            utc_hour=22,             # after hours
            registry=registry,
        )
        assert resp["status"]["allowed"] is True
        assert "acl" in resp["status"]["reason"].lower()

    def test_no_policy_denies(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        body = self._make_body("alice", "configmaps", "get")
        resp = handler_module.handle_authorize(
            request_body=body,
            source_ip="10.0.0.1",
            utc_hour=10,
            registry=registry,
        )
        assert resp["status"]["allowed"] is False
        assert "no policy" in resp["status"]["reason"]

    def test_malformed_sar_denies(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        resp = handler_module.handle_authorize(
            request_body={"bad": "data"},
            source_ip="10.0.0.1",
            utc_hour=10,
            registry=registry,
        )
        assert resp["status"]["allowed"] is False

    def test_audit_log_written(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        body = self._make_body("alice", "pods", "get", groups=["viewer"])
        handler_module.handle_authorize(
            request_body=body,
            source_ip="10.0.0.5",
            utc_hour=10,
            registry=registry,
        )
        assert len(logger.records) == 1
        rec = logger.records[0]
        assert rec.user == "alice"
        assert rec.resource == "pods"
        assert rec.verb == "get"
        assert rec.decision in ("ALLOW", "DENY")
        assert rec.latency_ms >= 0

    def test_audit_log_json_parseable(self, registry, capture_log):
        logger, buf = capture_log
        handler_module.set_audit_logger(logger)

        body = self._make_body("alice", "pods", "get")
        handler_module.handle_authorize(
            request_body=body,
            source_ip="10.0.0.5",
            utc_hour=10,
            registry=registry,
        )
        output = buf.getvalue()
        lines = [l for l in output.strip().split("\n") if l]
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert "timestamp" in parsed
        assert "user" in parsed
        assert "decision" in parsed
        assert "latency_ms" in parsed


# ---------------------------------------------------------------------------
# Flask endpoint tests
# ---------------------------------------------------------------------------

class TestFlaskEndpoints:
    def _make_sar_body(self, user, resource, verb, namespace="prod", groups=None):
        return {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "spec": {
                "user": user,
                "groups": groups or [],
                "resourceAttributes": {
                    "namespace": namespace,
                    "resource": resource,
                    "verb": verb,
                },
            }
        }

    def test_healthz_returns_200(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_authorize_returns_200(self, client):
        """Even a deny response returns HTTP 200 (SAR spec requirement)."""
        body = self._make_sar_body("alice", "pods", "get")
        resp = client.post(
            "/authorize",
            data=json.dumps(body),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "status" in data
        assert "allowed" in data["status"]

    def test_authorize_invalid_json_returns_400(self, client):
        resp = client.post(
            "/authorize",
            data="not json",
            content_type="application/json",
        )
        assert resp.status_code == 400
