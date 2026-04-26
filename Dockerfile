# U-HAP webhook authorizer — container image
#
# Multi-stage build for a minimal production image.
# Stage 1: dependency installation
# Stage 2: runtime image (no build tools)
#
# Build: docker build -t uhap:latest .
# Run:   docker run -p 8443:8443 uhap:latest

FROM python:3.11-slim AS base

WORKDIR /app

# Install runtime dependencies first (layer cache optimization)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Create non-root user
RUN useradd --uid 1000 --no-create-home --shell /sbin/nologin uhap

# Create directories for mounted volumes (TLS certs + policy files)
# These will be bind-mounted or volume-mounted in Kubernetes.
RUN mkdir -p /etc/uhap/tls /etc/uhap/policies \
    && chown -R uhap:uhap /etc/uhap

USER uhap

# The webhook listens on 8443 (HTTPS) or falls back to HTTP if no cert found.
EXPOSE 8443

# Health check — Kubernetes liveness probe calls this
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/healthz')" || exit 1

ENV UHAP_POLICY_DIR=/etc/uhap/policies
ENV UHAP_HOST=0.0.0.0
ENV UHAP_PORT=8443
ENV UHAP_TLS_CERT=/etc/uhap/tls/tls.crt
ENV UHAP_TLS_KEY=/etc/uhap/tls/tls.key

# Add src/ to PYTHONPATH so imports work
ENV PYTHONPATH=/app/src

CMD ["python", "src/main.py"]
