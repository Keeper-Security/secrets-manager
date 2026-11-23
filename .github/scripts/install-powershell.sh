#!/usr/bin/env bash
# Installs one exact PowerShell release into a directory. The runner image's own pwsh version
# changes without notice, and the PowerShell module tests need a known host version.
# Usage: install-powershell.sh <version> <destination-directory>
set -euo pipefail

version="$1"
dest="$2"

case "${RUNNER_OS:-}-${RUNNER_ARCH:-}" in
  Linux-X64) asset="powershell-${version}-linux-x64.tar.gz" ;;
  macOS-ARM64) asset="powershell-${version}-osx-arm64.tar.gz" ;;
  macOS-X64) asset="powershell-${version}-osx-x64.tar.gz" ;;
  Windows-X64) asset="PowerShell-${version}-win-x64.zip" ;;
  *) echo "Unsupported runner: ${RUNNER_OS:-unset} ${RUNNER_ARCH:-unset}" >&2; exit 1 ;;
esac

base="https://github.com/PowerShell/PowerShell/releases/download/v${version}"
work="$(mktemp -d)"
curl -fsSL --retry 3 -o "${work}/${asset}" "${base}/${asset}"
curl -fsSL --retry 3 -o "${work}/hashes.sha256" "${base}/hashes.sha256"

# Each line is "<hash> *<file name>". Some releases publish this file as UTF-16 with CRLF line endings,
# so the tr call removes the null bytes, the byte order mark, and the carriage returns.
expected="$(LC_ALL=C tr -d '\000\377\376\r' < "${work}/hashes.sha256" | awk -v f="${asset}" '{n=$2; sub(/^\*/, "", n); if (tolower(n) == tolower(f)) print tolower($1)}' | head -n 1)"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${work}/${asset}" | awk '{print tolower($1)}')"
else
  actual="$(shasum -a 256 "${work}/${asset}" | awk '{print tolower($1)}')"
fi
if [ -z "${expected}" ] || [ "${expected}" != "${actual}" ]; then
  echo "SHA-256 check failed for ${asset}: expected '${expected}', got '${actual}'" >&2
  exit 1
fi

mkdir -p "${dest}"
case "${asset}" in
  *.zip) powershell.exe -NoProfile -Command "Expand-Archive -LiteralPath '$(cygpath -w "${work}/${asset}")' -DestinationPath '$(cygpath -w "${dest}")' -Force" ;;
  *) tar -xzf "${work}/${asset}" -C "${dest}"; chmod +x "${dest}/pwsh" ;;
esac
echo "Installed PowerShell ${version} in ${dest}"
