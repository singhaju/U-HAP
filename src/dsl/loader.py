"""
DSL loader for U-HAP policy files.

Parses YAML policy files into typed policy record objects. Each file
specifies rules for one (namespace, resource) combination.

Expected YAML format:
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

Public API:
  load_file(path)           -> list of PolicyRecord
  load_directory(path)      -> list of PolicyRecord (all .yaml/.yml files)
  load_yaml_string(text)    -> list of PolicyRecord
  validate_records(records) -> raises ValueError on invalid records
"""

import os
from typing import List, Union

import yaml

from dsl.models import (
    RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord,
)
from dsl.parser import parse_predicate
from compiler.role_closure import detect_hierarchy_cycle


PolicyRecord = Union[RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord]

# Required top-level keys in every policy file
_REQUIRED_TOP_LEVEL = {"namespace", "resource", "rules"}

# Rule type -> required fields
_RULE_REQUIRED_FIELDS = {
    "rbac":      {"role", "action"},
    "abac":      {"action", "predicate"},
    "acl":       {"subject", "action"},
    "deny":      {"subject", "action"},
    "hierarchy": {"parent", "child"},
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_rule(rule: dict, namespace: str, resource: str) -> PolicyRecord:
    """Parse a single rule dict into a typed PolicyRecord.

    Args:
        rule:      Parsed YAML dict for one rule entry.
        namespace: From the file's top-level 'namespace' key.
        resource:  From the file's top-level 'resource' key.

    Returns:
        A PolicyRecord of the appropriate type.

    Raises:
        ValueError: Missing required fields or unknown rule type.
        SyntaxError: Predicate string fails to parse (ABAC only).
    """
    rule_type = rule.get("type", "").strip().lower()

    if rule_type not in _RULE_REQUIRED_FIELDS:
        raise ValueError(
            f"Unknown rule type '{rule_type}'. "
            f"Must be one of: {sorted(_RULE_REQUIRED_FIELDS.keys())}"
        )

    required = _RULE_REQUIRED_FIELDS[rule_type]
    missing = required - set(rule.keys())
    if missing:
        raise ValueError(
            f"Rule of type '{rule_type}' is missing required fields: "
            f"{sorted(missing)}. Rule was: {rule!r}"
        )

    if rule_type == "rbac":
        return RBACRecord(
            role=str(rule["role"]),
            resource=resource,
            namespace=namespace,
            action=str(rule["action"]),
        )

    if rule_type == "abac":
        # Validate that the predicate parses (raises SyntaxError if not)
        predicate = str(rule["predicate"])
        parse_predicate(predicate)   # validation only — result discarded here
        return ABACRecord(
            resource=resource,
            namespace=namespace,
            action=str(rule["action"]),
            predicate=predicate,
        )

    if rule_type == "acl":
        return ACLRecord(
            subject=str(rule["subject"]),
            resource=resource,
            namespace=namespace,
            action=str(rule["action"]),
        )

    if rule_type == "deny":
        return DenyRecord(
            subject=str(rule["subject"]),
            resource=resource,
            namespace=namespace,
            action=str(rule["action"]),
        )

    if rule_type == "hierarchy":
        return HierRecord(
            parent_role=str(rule["parent"]),
            child_role=str(rule["child"]),
            namespace=namespace,
        )

    # Should never reach here due to the check above
    raise ValueError(f"Unhandled rule type '{rule_type}'")  # pragma: no cover


def _parse_document(data: dict) -> List[PolicyRecord]:
    """Parse a single YAML document dict into a list of policy records.

    Args:
        data: Parsed YAML dict from a policy file.

    Returns:
        list of PolicyRecord

    Raises:
        ValueError: Missing top-level keys, invalid rule fields.
        SyntaxError: Invalid ABAC predicate.
    """
    # Validate top-level keys
    missing = _REQUIRED_TOP_LEVEL - set(data.keys())
    if missing:
        raise ValueError(
            f"Policy file missing required top-level keys: {sorted(missing)}"
        )

    namespace = str(data["namespace"]).strip()
    resource  = str(data["resource"]).strip()
    rules     = data["rules"]

    if not namespace:
        raise ValueError("Policy file 'namespace' must not be empty.")
    if not resource:
        raise ValueError("Policy file 'resource' must not be empty.")
    if not isinstance(rules, list):
        raise ValueError(
            f"Policy file 'rules' must be a list, got {type(rules).__name__!r}."
        )

    records = []
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(
                f"Rule #{i} must be a mapping (dict), got {type(rule).__name__!r}."
            )
        try:
            records.append(_parse_rule(rule, namespace, resource))
        except (ValueError, SyntaxError) as exc:
            raise type(exc)(f"Rule #{i} in '{namespace}/{resource}': {exc}") from exc

    return records


# ---------------------------------------------------------------------------
# Cycle validation across hierarchy records
# ---------------------------------------------------------------------------

def _validate_no_cycles(records: List[PolicyRecord]) -> None:
    """Check all HierRecord entries for cycles (across all namespaces).

    Raises ValueError if any namespace has a cycle in its role hierarchy.
    """
    # Group hier edges by namespace
    by_namespace: dict = {}
    for rec in records:
        if isinstance(rec, HierRecord):
            ns = rec.namespace
            if ns not in by_namespace:
                by_namespace[ns] = {}
            hier = by_namespace[ns]
            if rec.parent_role not in hier:
                hier[rec.parent_role] = []
            if rec.child_role not in hier[rec.parent_role]:
                hier[rec.parent_role].append(rec.child_role)

    for ns, hier in by_namespace.items():
        try:
            detect_hierarchy_cycle(hier)
        except ValueError as exc:
            raise ValueError(
                f"Cycle detected in role hierarchy for namespace '{ns}': {exc}"
            ) from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_yaml_string(text: str) -> List[PolicyRecord]:
    """Parse policy records from a YAML string.

    Supports multi-document YAML (--- separator), returning records from
    all documents combined.

    Args:
        text: YAML content as a string.

    Returns:
        list of PolicyRecord

    Raises:
        ValueError, SyntaxError: if any record is invalid.
        yaml.YAMLError: if the YAML itself is malformed.
    """
    records: List[PolicyRecord] = []
    for doc in yaml.safe_load_all(text):
        if doc is None:
            continue
        records.extend(_parse_document(doc))
    _validate_no_cycles(records)
    return records


def load_file(path: str) -> List[PolicyRecord]:
    """Parse policy records from a YAML file on disk.

    Args:
        path: Path to a .yaml or .yml policy file.

    Returns:
        list of PolicyRecord

    Raises:
        FileNotFoundError: if the file does not exist.
        ValueError, SyntaxError, yaml.YAMLError: if content is invalid.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Policy file not found: {path!r}")

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    return load_yaml_string(text)


def load_directory(directory: str) -> List[PolicyRecord]:
    """Parse all .yaml and .yml files in a directory (non-recursive).

    Args:
        directory: Path to a directory containing policy YAML files.

    Returns:
        list of PolicyRecord (combined from all files)

    Raises:
        FileNotFoundError: if the directory does not exist.
        ValueError, SyntaxError, yaml.YAMLError: if any file is invalid.
    """
    if not os.path.isdir(directory):
        raise FileNotFoundError(
            f"Policy directory not found: {directory!r}"
        )

    records: List[PolicyRecord] = []
    for fname in sorted(os.listdir(directory)):
        if fname.endswith((".yaml", ".yml")):
            fpath = os.path.join(directory, fname)
            records.extend(load_file(fpath))

    return records
