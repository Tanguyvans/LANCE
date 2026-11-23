#!/usr/bin/env bash
# Build a self-contained, offline-installable image bundle for the partner deploy.
#
# Produces a gzipped `docker save` tarball plus a sha256 checksum. The partner
# loads it with `docker load` — no GHCR access or internet needed at deploy time.
# The image is saved BY TAG, so `docker load` restores that tag and `docker
# compose up` finds it directly (no retag step). The tarball's own sha256 locks
# the exact bytes; the source image digest is printed for provenance.
#
# Usage:
#   scripts/deployment/build-offline-bundle.sh [TAG]
#   TAG=latest PLATFORM=linux/amd64 OUT_DIR=./dist scripts/deployment/build-offline-bundle.sh
#
# On the partner host (amd64 GPU box):
#   gunzip -c lance-<tag>-<arch>.tar.gz | docker load     # restores ghcr.io/tanguyvans/lance:<tag>
#   sha256sum -c lance-<tag>-<arch>.tar.gz.sha256          # run from the tarball's directory
#   docker compose up -d                                   # compose references :latest
set -euo pipefail

IMAGE="${IMAGE:-ghcr.io/tanguyvans/lance}"
TAG="${1:-${TAG:-latest}}"
PLATFORM="${PLATFORM:-linux/amd64}"   # partner GPU hosts are amd64
OUT_DIR="${OUT_DIR:-./dist}"
ARCH="${PLATFORM##*/}"                # name the tarball after the real platform

mkdir -p "$OUT_DIR"

echo "[bundle] pulling ${IMAGE}:${TAG} (${PLATFORM})"
docker pull --platform "$PLATFORM" "${IMAGE}:${TAG}"

# Provenance only (guarded so a locally-built image without a RepoDigest doesn't
# abort under `set -e`); the tarball's sha256 is the actual integrity guarantee.
DIGEST="$(docker inspect --format='{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "${IMAGE}:${TAG}")"
echo "[bundle] source digest: ${DIGEST:-<none>}"

SAFE_TAG="${TAG//[:\/]/_}"
TARBALL="${OUT_DIR}/lance-${SAFE_TAG}-${ARCH}.tar.gz"

echo "[bundle] saving ${IMAGE}:${TAG} -> ${TARBALL}"
docker save "${IMAGE}:${TAG}" | gzip > "$TARBALL"

# sha256sum on Linux, shasum on macOS build hosts.
# Hash from inside OUT_DIR so the checksum file records the basename and
# `sha256sum -c <file>.sha256` works in any target directory on the partner host.
TARBALL_NAME="$(basename "$TARBALL")"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$OUT_DIR" && sha256sum "$TARBALL_NAME") | tee "${TARBALL}.sha256"
else
  (cd "$OUT_DIR" && shasum -a 256 "$TARBALL_NAME") | tee "${TARBALL}.sha256"
fi

cat <<EOF

[bundle] done.
  tarball : ${TARBALL}
  source  : ${IMAGE}:${TAG}${DIGEST:+ (${DIGEST})}

On the partner host:
  gunzip -c $(basename "$TARBALL") | docker load
  docker compose up -d
EOF
if [ "$TAG" != "latest" ]; then
  echo "  # compose references :latest — retag if needed:"
  echo "  #   docker tag ${IMAGE}:${TAG} ${IMAGE}:latest"
fi
