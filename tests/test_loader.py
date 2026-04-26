"""
Tests for the DSL loader (Step 7).

Covers:
  - Parsing valid YAML policy files
  - Validation: missing fields, unknown types, bad predicates
  - Cycle detection in hierarchy
  - Multi-document YAML
  - load_file and load_directory
"""

import os
import tempfile
import pytest

from dsl.loader import load_yaml_string, load_file, load_directory
from dsl.models import RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord


# ---------------------------------------------------------------------------
# Valid policy YAML
# ---------------------------------------------------------------------------

VALID_YAML = """
namespace: prod
resource: pods
rules:
  - type: rbac
    role: viewer
    action: get

  - type: abac
    action: get
    predicate: "net == 'on-premise' AND time == 'business-hours'"

  - type: acl
    subject: charlie
    action: get

  - type: deny
    subject: "*"
    action: delete

  - type: hierarchy
    parent: senior-dev
    child: junior-dev
"""


class TestValidYAML:
    def test_parses_all_record_types(self):
        records = load_yaml_string(VALID_YAML)
        types = {type(r) for r in records}
        assert RBACRecord in types
        assert ABACRecord in types
        assert ACLRecord in types
        assert DenyRecord in types
        assert HierRecord in types

    def test_record_count(self):
        records = load_yaml_string(VALID_YAML)
        assert len(records) == 5

    def test_rbac_record_fields(self):
        records = load_yaml_string(VALID_YAML)
        rbac = next(r for r in records if isinstance(r, RBACRecord))
        assert rbac.role == "viewer"
        assert rbac.resource == "pods"
        assert rbac.namespace == "prod"
        assert rbac.action == "get"

    def test_abac_record_fields(self):
        records = load_yaml_string(VALID_YAML)
        abac = next(r for r in records if isinstance(r, ABACRecord))
        assert abac.action == "get"
        assert "on-premise" in abac.predicate

    def test_acl_record_fields(self):
        records = load_yaml_string(VALID_YAML)
        acl = next(r for r in records if isinstance(r, ACLRecord))
        assert acl.subject == "charlie"
        assert acl.action == "get"

    def test_deny_record_fields(self):
        records = load_yaml_string(VALID_YAML)
        deny = next(r for r in records if isinstance(r, DenyRecord))
        assert deny.subject == "*"
        assert deny.is_wildcard
        assert deny.action == "delete"

    def test_hierarchy_record_fields(self):
        records = load_yaml_string(VALID_YAML)
        hier = next(r for r in records if isinstance(r, HierRecord))
        assert hier.parent_role == "senior-dev"
        assert hier.child_role == "junior-dev"
        assert hier.namespace == "prod"


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------

class TestValidationErrors:
    def test_missing_namespace(self):
        with pytest.raises(ValueError, match="namespace"):
            load_yaml_string("""
resource: pods
rules: []
""")

    def test_missing_resource(self):
        with pytest.raises(ValueError, match="resource"):
            load_yaml_string("""
namespace: prod
rules: []
""")

    def test_missing_rules(self):
        with pytest.raises(ValueError, match="rules"):
            load_yaml_string("""
namespace: prod
resource: pods
""")

    def test_unknown_rule_type(self):
        with pytest.raises(ValueError, match="Unknown rule type"):
            load_yaml_string("""
namespace: prod
resource: pods
rules:
  - type: unknown
    action: get
""")

    def test_rbac_missing_role(self):
        with pytest.raises(ValueError, match="role"):
            load_yaml_string("""
namespace: prod
resource: pods
rules:
  - type: rbac
    action: get
""")

    def test_abac_missing_predicate(self):
        with pytest.raises(ValueError, match="predicate"):
            load_yaml_string("""
namespace: prod
resource: pods
rules:
  - type: abac
    action: get
""")

    def test_abac_invalid_predicate(self):
        with pytest.raises(SyntaxError):
            load_yaml_string("""
namespace: prod
resource: pods
rules:
  - type: abac
    action: get
    predicate: "net == "
""")

    def test_acl_missing_subject(self):
        with pytest.raises(ValueError, match="subject"):
            load_yaml_string("""
namespace: prod
resource: pods
rules:
  - type: acl
    action: get
""")

    def test_deny_missing_subject(self):
        with pytest.raises(ValueError, match="subject"):
            load_yaml_string("""
namespace: prod
resource: pods
rules:
  - type: deny
    action: delete
""")

    def test_hierarchy_missing_parent(self):
        with pytest.raises(ValueError, match="parent"):
            load_yaml_string("""
namespace: prod
resource: pods
rules:
  - type: hierarchy
    child: junior
""")

    def test_cycle_in_hierarchy_raises(self):
        with pytest.raises(ValueError, match="[Cc]ycle"):
            load_yaml_string("""
namespace: prod
resource: pods
rules:
  - type: hierarchy
    parent: a
    child: b
  - type: hierarchy
    parent: b
    child: a
""")


# ---------------------------------------------------------------------------
# Multi-document YAML
# ---------------------------------------------------------------------------

class TestMultiDocumentYAML:
    def test_two_documents(self):
        text = """
namespace: prod
resource: pods
rules:
  - type: rbac
    role: viewer
    action: get
---
namespace: dev
resource: secrets
rules:
  - type: deny
    subject: "*"
    action: delete
"""
        records = load_yaml_string(text)
        assert len(records) == 2
        ns_set = {r.namespace for r in records}
        assert "prod" in ns_set
        assert "dev" in ns_set


# ---------------------------------------------------------------------------
# load_file and load_directory
# ---------------------------------------------------------------------------

class TestLoadFile:
    def test_load_file_valid(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(VALID_YAML)
            path = f.name
        try:
            records = load_file(path)
            assert len(records) == 5
        finally:
            os.unlink(path)

    def test_load_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_file("/nonexistent/policy.yaml")


class TestLoadDirectory:
    def test_load_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i, ns in enumerate(["prod", "dev"]):
                path = os.path.join(tmpdir, f"policy_{i}.yaml")
                with open(path, "w") as f:
                    f.write(f"""
namespace: {ns}
resource: pods
rules:
  - type: rbac
    role: viewer
    action: get
""")
            records = load_directory(tmpdir)
            assert len(records) == 2

    def test_load_directory_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_directory("/nonexistent/dir")

    def test_load_directory_ignores_non_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write a yaml file and a txt file
            with open(os.path.join(tmpdir, "policy.yaml"), "w") as f:
                f.write(VALID_YAML)
            with open(os.path.join(tmpdir, "readme.txt"), "w") as f:
                f.write("ignore me")
            records = load_directory(tmpdir)
            assert len(records) == 5  # only from policy.yaml
