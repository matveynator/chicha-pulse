#!/usr/bin/env bash
# This script builds release binaries locally so GitHub Actions can publish them.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${root_dir}/dist"

# Keep the build list explicit so release artifacts are predictable.
targets=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
  "windows/arm64"
  "freebsd/amd64"
  "freebsd/arm64"
  "openbsd/amd64"
  "openbsd/arm64"
)

mkdir -p "${output_dir}"

for target in "${targets[@]}"; do
  IFS="/" read -r goos goarch <<< "${target}"
  # Disable CGO to make cross-compilation deterministic across CI runners.
  export CGO_ENABLED=0
  export GOOS="${goos}"
  export GOARCH="${goarch}"
  suffix=""
  if [[ "${goos}" == "windows" ]]; then
    suffix=".exe"
  fi
  binary_name="chicha-pulse_${goos}_${goarch}${suffix}"
  echo "Building ${binary_name}"
  go build -trimpath -ldflags "-s -w" -o "${output_dir}/${binary_name}" "${root_dir}"
done
