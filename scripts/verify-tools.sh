#!/usr/bin/env bash
# Verifica la cadena de confianza de Trivy antes de actualizar su hash en lab/images/controller/Dockerfile:
#   1. la firma Sigstore (keyless, OIDC de GitHub Actions del repo aquasecurity/trivy) del archivo de checksums;
#   2. que el SHA-256 del tarball coincida con el publicado en ese archivo firmado.
# Uso: scripts/verify-tools.sh [versión]   (por defecto la fijada en el Dockerfile)
set -euo pipefail

version="${1:-$(sed -n 's/^ARG TRIVY_VERSION=//p' lab/images/controller/Dockerfile | head -1)}"
cosign_image="ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8"
base="https://github.com/aquasecurity/trivy/releases/download/v${version}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

curl -fsSLo "${work}/checksums.txt" "${base}/trivy_${version}_checksums.txt"
curl -fsSLo "${work}/checksums.txt.sigstore.json" "${base}/trivy_${version}_checksums.txt.sigstore.json"

# En Git Bash (Windows) docker necesita la ruta de Windows del directorio temporal.
mount="$(cygpath -w "${work}" 2>/dev/null || echo "${work}")"
MSYS_NO_PATHCONV=1 docker run --rm -v "${mount}:/work:ro" "${cosign_image}" verify-blob \
  --bundle /work/checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/aquasecurity/trivy/\.github/workflows/.+@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  /work/checksums.txt

expected="$(grep " trivy_${version}_Linux-64bit.tar.gz$" "${work}/checksums.txt" | cut -d' ' -f1)"
pinned="$(sed -n 's/^ARG TRIVY_SHA256=//p' lab/images/controller/Dockerfile | head -1)"
echo "SHA-256 publicado y firmado: ${expected}"
echo "SHA-256 fijado en Dockerfile: ${pinned}"
if [ "${expected}" != "${pinned}" ]; then
  echo "ERROR: el hash fijado no coincide con el publicado" >&2
  exit 1
fi
echo "OK: Trivy ${version} verificado (firma Sigstore + SHA-256)."
