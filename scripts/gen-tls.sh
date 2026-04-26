#!/usr/bin/env bash
# Generate self-signed TLS certificates for the U-HAP webhook.
#
# Produces:
#   tls/ca.key        — CA private key
#   tls/ca.crt        — CA certificate (add to webhook caBundle)
#   tls/tls.key       — webhook server private key
#   tls/tls.crt       — webhook server certificate (signed by CA)
#
# Also produces:
#   /tmp/uhap-kind/webhook-kubeconfig.yaml  — kubeconfig for the K8s API server
#   deploy/tls-secret.yaml                  — K8s Secret containing TLS certs
#
# Usage:
#   bash scripts/gen-tls.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TLS_DIR="${PROJECT_DIR}/tls"
KIND_DIR="/tmp/uhap-kind"
SERVICE_NAME="uhap-webhook"
NAMESPACE="kube-system"
DNS_NAME="${SERVICE_NAME}.${NAMESPACE}.svc"

mkdir -p "${TLS_DIR}" "${KIND_DIR}"

echo "[gen-tls] Generating CA key and certificate..."
openssl genrsa -out "${TLS_DIR}/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes \
    -key "${TLS_DIR}/ca.key" \
    -subj "/CN=uhap-webhook-ca/O=U-HAP" \
    -days 3650 \
    -out "${TLS_DIR}/ca.crt"

echo "[gen-tls] Generating server key..."
openssl genrsa -out "${TLS_DIR}/tls.key" 2048 2>/dev/null

echo "[gen-tls] Generating server CSR..."
openssl req -new \
    -key "${TLS_DIR}/tls.key" \
    -subj "/CN=${DNS_NAME}/O=U-HAP" \
    -out "${TLS_DIR}/tls.csr"

echo "[gen-tls] Signing server certificate with CA..."
cat > "${TLS_DIR}/san.cnf" <<EOF
[SAN]
subjectAltName=DNS:${DNS_NAME},DNS:${SERVICE_NAME},DNS:localhost
EOF

openssl x509 -req \
    -in "${TLS_DIR}/tls.csr" \
    -CA "${TLS_DIR}/ca.crt" \
    -CAkey "${TLS_DIR}/ca.key" \
    -CAcreateserial \
    -days 3650 \
    -extfile "${TLS_DIR}/san.cnf" \
    -extensions SAN \
    -out "${TLS_DIR}/tls.crt" 2>/dev/null

rm -f "${TLS_DIR}/tls.csr" "${TLS_DIR}/san.cnf" "${TLS_DIR}/ca.srl"

echo "[gen-tls] Generating webhook kubeconfig for API server..."
CA_BUNDLE=$(base64 -w 0 < "${TLS_DIR}/ca.crt")

cat > "${KIND_DIR}/webhook-kubeconfig.yaml" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: uhap-webhook
    cluster:
      server: https://${DNS_NAME}/authorize
      certificate-authority-data: ${CA_BUNDLE}
users:
  - name: kube-apiserver
contexts:
  - name: webhook
    context:
      cluster: uhap-webhook
      user: kube-apiserver
current-context: webhook
EOF

echo "[gen-tls] Generating K8s TLS Secret manifest..."
TLS_CRT=$(base64 -w 0 < "${TLS_DIR}/tls.crt")
TLS_KEY=$(base64 -w 0 < "${TLS_DIR}/tls.key")

cat > "${PROJECT_DIR}/deploy/tls-secret.yaml" <<EOF
---
# U-HAP TLS Secret — created by scripts/gen-tls.sh
# Apply with: kubectl apply -f deploy/tls-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: uhap-tls
  namespace: kube-system
type: kubernetes.io/tls
data:
  tls.crt: ${TLS_CRT}
  tls.key: ${TLS_KEY}
EOF

echo "[gen-tls] Updating caBundle in deploy/webhook-config.yaml..."
sed -i "s|caBundle: REPLACE_WITH_CA_BUNDLE|caBundle: ${CA_BUNDLE}|g" \
    "${PROJECT_DIR}/deploy/webhook-config.yaml"

echo ""
echo "[gen-tls] Done. Files generated:"
echo "  ${TLS_DIR}/ca.crt       (CA certificate — also embedded in webhook-config.yaml)"
echo "  ${TLS_DIR}/tls.crt      (webhook server certificate)"
echo "  ${TLS_DIR}/tls.key      (webhook server private key)"
echo "  ${KIND_DIR}/webhook-kubeconfig.yaml"
echo "  ${PROJECT_DIR}/deploy/tls-secret.yaml"
echo ""
echo "Next steps:"
echo "  1. kind create cluster --config deploy/kind-config.yaml --name uhap"
echo "  2. docker build -t uhap:latest ."
echo "  3. kind load docker-image uhap:latest --name uhap"
echo "  4. kubectl apply -f deploy/tls-secret.yaml"
echo "  5. kubectl create configmap uhap-policies --from-file=deploy/sample-policies/ -n kube-system"
echo "  6. kubectl apply -f deploy/webhook-deployment.yaml"
echo "  7. kubectl apply -f deploy/webhook-service.yaml"
echo "  8. kubectl apply -f deploy/webhook-config.yaml"
