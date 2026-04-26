"""
Webhook request handler for U-HAP.

Ties together:
  1. SAR parsing (webhook/sar.py)
  2. Context enrichment (engine/context.py)
  3. Authorization evaluation (engine/evaluator.py)
  4. Audit logging (audit/logger.py)
  5. SAR response building (webhook/sar.py)

Called from main.py's Flask route handler.

Public API:
  handle_authorize(request_body, source_ip, utc_hour, registry) -> dict
"""

import time
from typing import Optional

from audit.logger import AuditLogger
from compiler.registry import ArtifactRegistry
from engine.context import build_context
from engine.evaluator import evaluate_request
from webhook.sar import SARParseError, build_sar_response, parse_sar


# Module-level audit logger (shared across requests)
_audit_logger = AuditLogger()

# Module-level decision cache — None means caching disabled
_decision_cache = None


def set_decision_cache(cache) -> None:
    """Set the module-level decision cache. Pass None to disable caching."""
    global _decision_cache
    _decision_cache = cache


def get_audit_logger() -> AuditLogger:
    """Return the module-level AuditLogger. Replaceable in tests."""
    return _audit_logger


def set_audit_logger(logger: AuditLogger) -> None:
    """Replace the module-level AuditLogger (for testing)."""
    global _audit_logger
    _audit_logger = logger


def handle_authorize(
    request_body: dict,
    source_ip: str,
    utc_hour: int,
    registry,
    token_attrs: Optional[dict] = None,
) -> dict:
    """Process a SubjectAccessReview authorization request.

    Args:
        request_body: Parsed JSON body from the HTTP POST.
        source_ip:    Client IP address string (may be X-Forwarded-For).
        utc_hour:     Current UTC hour (0-23).
        registry:     Populated GraphRegistry from Phase 1.
        token_attrs:  Optional additional attributes from the auth token.

    Returns:
        SAR response dict ready for JSON serialization.
    """
    start_ns = time.perf_counter_ns()

    # Step 1: Parse SAR request
    try:
        sar = parse_sar(request_body)
    except SARParseError as exc:
        # Malformed request -> deny with error reason
        response = build_sar_response(False, f"bad request: {exc}")
        return response

    # Step 2: Build merged context
    ctx = build_context(
        source_ip=source_ip,
        utc_hour=utc_hour,
        token_attrs=token_attrs,
        extra_attrs=sar.extra,
    )

    # Step 3: Evaluate
    allowed, reason = evaluate_request(
        registry=registry,
        namespace=sar.namespace,
        resource=sar.resource,
        action=sar.verb,
        uid=sar.user,
        roles=sar.groups,
        groups=[],
        context=ctx,
        cache=_decision_cache,
    )

    # Step 4: Audit log
    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
    get_audit_logger().log(
        user=sar.user,
        namespace=sar.namespace,
        resource=sar.resource,
        verb=sar.verb,
        decision="ALLOW" if allowed else "DENY",
        reason=reason,
        latency_ms=elapsed_ms,
        context=ctx,
    )

    # Step 5: Build and return SAR response
    return build_sar_response(allowed, reason)
