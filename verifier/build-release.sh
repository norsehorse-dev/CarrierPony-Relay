#!/usr/bin/env bash
#
# Build the cp-verify binaries that are attached to a relay release, and record
# their checksums.
#
#   ./build-release.sh v1.1.0
#
# Writes verifier/dist/cp-verify-linux-amd64 and cp-verify-linux-arm64, and
# verifier/RELEASE with the tag and the SHA-256 of each. install.sh downloads a
# binary from the release named in RELEASE and refuses it unless it matches.
#
# Order for a release: run this, commit RELEASE, tag that commit with the same
# tag, then attach the two files in dist/ to the GitHub release for the tag.
set -euo pipefail

tag="${1:-}"
if [ -z "$tag" ]; then
  echo "usage: ./build-release.sh <tag>" >&2
  exit 2
fi

cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p dist

if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$1" | awk '{ print $1 }'; }
else
  sum() { shasum -a 256 "$1" | awk '{ print $1 }'; }
fi

{
  echo "tag $tag"
  for arch in amd64 arm64; do
    out="dist/cp-verify-linux-${arch}"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -buildid=" -o "$out" ./cmd/cp-verify
    echo "$arch $(sum "$out")"
  done
} > RELEASE.tmp
mv RELEASE.tmp RELEASE

cat RELEASE
echo "Built dist/cp-verify-linux-amd64 and dist/cp-verify-linux-arm64."
