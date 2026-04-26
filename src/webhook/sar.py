"""
SubjectAccessReview (SAR) parsing and response building for U-HAP.

Kubernetes sends a SAR JSON body to the webhook and expects a SAR JSON response.

Request format (relevant fields):
{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SubjectAccessReview",
  "spec": {
    "resourceAttributes": {
      "namespace": "prod",
      "resource": "pods",
      "verb": "get"
    },
    "user": "alice",
    "groups": ["dev-role", "viewer"],
    "extra": {
      "dept": ["engineering"],
      "clearance": ["top-secret"]
    }
  }
}

Response format:
{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SubjectAccessReview",
  "status": {
    "allowed": true,
    "reason": "rbac: viewer"
  }
}

For DENY:
{
  "status": {
    "allowed": false,
    "denied": true,
    "reason": "deny rule: wildcard"
  }
}

Public API:
  parse_sar(body)                  -> SARRequest (dataclass)
  build_sar_response(allowed, reason) -> dict
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SARRequest:
    """Parsed SubjectAccessReview request — the fields U-HAP needs."""
    user: str
    groups: List[str]
    namespace: str
    resource: str
    verb: str
    # extra: SAR spec.extra map; values are lists — we flatten to scalars
    extra: Dict[str, str] = field(default_factory=dict)


class SARParseError(ValueError):
    """Raised when a SAR request body is missing required fields."""
    pass


def parse_sar(body: dict) -> SARRequest:
    """Parse a Kubernetes SubjectAccessReview request body.

    Args:
        body: The parsed JSON body from the webhook POST request.

    Returns:
        SARRequest with all relevant fields extracted.

    Raises:
        SARParseError: if required fields are missing or malformed.
    """
    if not isinstance(body, dict):
        raise SARParseError(f"SAR body must be a JSON object, got {type(body).__name__}")

    spec = body.get("spec")
    if not isinstance(spec, dict):
        raise SARParseError("SAR body missing 'spec' object")

    user = spec.get("user")
    if not user:
        raise SARParseError("SAR spec missing 'user' field")

    groups = spec.get("groups", [])
    if not isinstance(groups, list):
        groups = []

    resource_attrs = spec.get("resourceAttributes")
    if not isinstance(resource_attrs, dict):
        raise SARParseError(
            "SAR spec missing 'resourceAttributes' object. "
            "Non-resource attributes (e.g., API group checks) are not supported."
        )

    namespace = resource_attrs.get("namespace", "default")
    resource  = resource_attrs.get("resource")
    verb      = resource_attrs.get("verb")

    if not resource:
        raise SARParseError("SAR resourceAttributes missing 'resource' field")
    if not verb:
        raise SARParseError("SAR resourceAttributes missing 'verb' field")

    # Flatten extra: {"dept": ["engineering"]} -> {"dept": "engineering"}
    # Multi-valued extras take the first value.
    raw_extra = spec.get("extra", {}) or {}
    extra: Dict[str, str] = {}
    for key, values in raw_extra.items():
        if isinstance(values, list) and values:
            extra[str(key)] = str(values[0])
        elif isinstance(values, str):
            extra[str(key)] = values

    return SARRequest(
        user=str(user),
        groups=[str(g) for g in groups],
        namespace=str(namespace),
        resource=str(resource),
        verb=str(verb),
        extra=extra,
    )


def build_sar_response(allowed: bool, reason: str) -> dict:
    """Build a Kubernetes SubjectAccessReview response body.

    Args:
        allowed: True if the request is authorized, False otherwise.
        reason:  Human-readable string explaining the decision.

    Returns:
        dict: SAR response body ready for JSON serialization.
    """
    status: dict = {
        "allowed": allowed,
        "reason": reason,
    }
    if not allowed:
        # Setting 'denied: true' signals an explicit deny (as opposed to
        # "not authorized by this webhook" which would be allowed=false,
        # denied=false — telling K8s to consult the next authorizer).
        status["denied"] = True

    return {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "status": status,
    }
