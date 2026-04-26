"""
Structured audit logging for U-HAP.

Every authorization decision is written as a single-line JSON record to
stdout (where Kubernetes will capture it via the container log driver).

Fields per log entry:
  timestamp   - ISO-8601 UTC timestamp (e.g., "2026-03-25T14:30:00.123Z")
  user        - requesting subject identity
  namespace   - Kubernetes namespace
  resource    - resource name
  verb        - action verb (get, delete, etc.)
  decision    - "ALLOW" or "DENY"
  reason      - string identifying the policy path that decided the outcome
  latency_ms  - float: milliseconds spent in the evaluate() call
  context     - dict of context key/values (net, time, etc.)

This is the unified audit trail described in Section 1 of the U-HAP paper:
"no unified audit trail" is one of the problems this system solves.

Public API:
  AuditLogger    -- the logger class
  AuditRecord    -- dataclass for one log entry (for testing)
"""

import json
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import IO, List, Optional


@dataclass
class AuditRecord:
    """A single structured audit log entry."""
    timestamp:  str
    user:       str
    namespace:  str
    resource:   str
    verb:       str
    decision:   str      # "ALLOW" | "DENY"
    reason:     str
    latency_ms: float
    context:    dict


class AuditLogger:
    """Writes structured JSON audit records to an output stream.

    Default output is sys.stdout. In tests, pass a custom stream (e.g.,
    io.StringIO) to capture output.

    Thread safety: each write() call is a single json.dumps() + write +
    flush — effectively atomic on CPython for short messages.
    """

    def __init__(self, stream: Optional[IO[str]] = None):
        """
        Args:
            stream: Output stream for log lines. Defaults to sys.stdout.
        """
        self._stream = stream or sys.stdout
        self._records: List[AuditRecord] = []  # in-memory buffer for testing

    def log(
        self,
        user: str,
        namespace: str,
        resource: str,
        verb: str,
        decision: str,
        reason: str,
        latency_ms: float,
        context: dict,
    ) -> AuditRecord:
        """Write a structured audit record.

        Args:
            user:       Requesting subject identity.
            namespace:  Kubernetes namespace.
            resource:   Resource name.
            verb:       Action verb.
            decision:   "ALLOW" or "DENY".
            reason:     Policy path that decided the outcome.
            latency_ms: Evaluation latency in milliseconds.
            context:    Merged context dict used for evaluation.

        Returns:
            AuditRecord (also appended to in-memory buffer).
        """
        record = AuditRecord(
            timestamp  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            user       = user,
            namespace  = namespace,
            resource   = resource,
            verb       = verb,
            decision   = decision,
            reason     = reason,
            latency_ms = round(latency_ms, 3),
            context    = dict(context),
        )

        # Serialize to JSON and write as a single line
        line = json.dumps(asdict(record), ensure_ascii=False)
        self._stream.write(line + "\n")
        self._stream.flush()

        # Keep in-memory buffer for introspection (tests)
        self._records.append(record)

        return record

    @property
    def records(self) -> List[AuditRecord]:
        """Return the in-memory list of all records written in this session."""
        return list(self._records)

    def clear(self) -> None:
        """Clear the in-memory buffer (useful in tests)."""
        self._records.clear()
