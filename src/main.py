"""
U-HAP Flask webhook server entry point.

Endpoints:
  POST /authorize  -- Kubernetes SubjectAccessReview webhook
  GET  /healthz    -- Health check (returns 200 OK)

Environment variables:
  UHAP_POLICY_DIR   -- directory containing YAML policy files (default: /etc/uhap/policies)
  UHAP_HOST         -- bind host (default: 0.0.0.0)
  UHAP_PORT         -- bind port (default: 8443)
  UHAP_TLS_CERT     -- path to TLS certificate PEM (default: /etc/uhap/tls/tls.crt)
  UHAP_TLS_KEY      -- path to TLS private key PEM (default: /etc/uhap/tls/tls.key)

Usage (development):
    python src/main.py

Usage (production in K8s):
    Deployed as a container; TLS terminated by the Flask dev server for local
    testing or via a reverse proxy / service mesh in production.
"""

import os
import sys
import time
import logging

# Add src/ to path so imports work when running from project root
_SRC = os.path.dirname(os.path.abspath(__file__))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from flask import Flask, jsonify, request

from dsl.loader import load_directory
from compiler.registry import ArtifactRegistry
from webhook.handler import handle_authorize

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("uhap.main")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Global artifact registry — populated at startup from policy files
_registry: ArtifactRegistry = ArtifactRegistry()


def get_registry() -> ArtifactRegistry:
    """Return the module-level artifact registry."""
    return _registry


def load_policies(policy_dir: str) -> None:
    """Load policy YAML files from directory into the global registry."""
    global _registry
    logger.info("Loading policies from %s", policy_dir)
    try:
        records = load_directory(policy_dir)
        _registry = ArtifactRegistry()
        _registry.load(records)
        logger.info(
            "Loaded %d artifacts across %d namespaces",
            len(_registry),
            len(_registry.namespaces()),
        )
    except FileNotFoundError:
        logger.warning("Policy directory %r not found — starting with empty registry", policy_dir)
    except Exception as exc:
        logger.error("Failed to load policies: %s", exc)
        raise


def _startup() -> None:
    """Initialize at import time so gunicorn workers load policies and cache."""
    policy_dir = os.environ.get("UHAP_POLICY_DIR", "/etc/uhap/policies")
    try:
        load_policies(policy_dir)
    except Exception as exc:
        logger.error("Policy loading failed, starting with empty registry: %s", exc)

    if os.environ.get("UHAP_ENABLE_CACHE", "0").lower() in ("1", "true", "yes"):
        from engine.cache import DecisionCache
        from webhook.handler import set_decision_cache
        cache = DecisionCache(ttl_seconds=300.0)
        set_decision_cache(cache)
        logger.info("Decision cache enabled (TTL=300s)")


# Run at import time — supports both direct execution and gunicorn deployment
_startup()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/healthz", methods=["GET"])
def healthz():
    """Health check endpoint — returns 200 OK with simple JSON body."""
    return jsonify({"status": "ok", "graphs": len(_registry)}), 200


@app.route("/authorize", methods=["POST"])
def authorize():
    """Kubernetes SubjectAccessReview webhook endpoint.

    Expects JSON body conforming to the K8s SubjectAccessReview API.
    Returns a SAR response JSON.
    """
    body = request.get_json(force=True, silent=True)
    if body is None:
        return jsonify({
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "status": {
                "allowed": False,
                "denied": True,
                "reason": "bad request: body is not valid JSON",
            }
        }), 400

    # Extract source IP for context enrichment
    source_ip = (
        request.headers.get("X-Forwarded-For", "")
        or request.remote_addr
        or "127.0.0.1"
    )

    # Current UTC hour for time classification
    utc_hour = time.gmtime().tm_hour

    response_body = handle_authorize(
        request_body=body,
        source_ip=source_ip,
        utc_hour=utc_hour,
        registry=_registry,
    )

    return jsonify(response_body), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host     = os.environ.get("UHAP_HOST", "0.0.0.0")
    port     = int(os.environ.get("UHAP_PORT", "8443"))
    tls_cert = os.environ.get("UHAP_TLS_CERT", "/etc/uhap/tls/tls.crt")
    tls_key  = os.environ.get("UHAP_TLS_KEY",  "/etc/uhap/tls/tls.key")
    # Policies and cache already loaded by _startup() above

    ssl_context = None
    if os.path.isfile(tls_cert) and os.path.isfile(tls_key):
        ssl_context = (tls_cert, tls_key)
        logger.info("TLS enabled: cert=%s key=%s", tls_cert, tls_key)
    else:
        logger.warning(
            "TLS cert/key not found (%s, %s) — running HTTP only (not for production)",
            tls_cert, tls_key,
        )

    logger.info("Starting U-HAP on %s:%d", host, port)
    app.run(host=host, port=port, ssl_context=ssl_context)
