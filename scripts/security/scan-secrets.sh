#!/usr/bin/env bash
# Scan every tracked current file without scanning installed dependencies or Git credentials.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
task_tmp="$(mktemp -d)"
trap 'rm -rf "$task_tmp"' EXIT
version=8.30.1
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) archive="gitleaks_${version}_linux_x64.tar.gz"; digest=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
  Linux-aarch64) archive="gitleaks_${version}_linux_arm64.tar.gz"; digest=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;;
  Darwin-arm64) archive="gitleaks_${version}_darwin_arm64.tar.gz"; digest=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
  Darwin-x86_64) archive="gitleaks_${version}_darwin_x64.tar.gz"; digest=dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709 ;;
  *) echo "Unsupported secret-scanner platform" >&2; exit 1 ;;
esac
# Digests are pinned from the upstream v8.30.1 release asset metadata.
curl --fail --silent --show-error --location --retry 3 "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}" --output "$task_tmp/$archive"
if command -v sha256sum >/dev/null; then
  actual="$(sha256sum "$task_tmp/$archive" | cut -d ' ' -f 1)"
else
  actual="$(shasum -a 256 "$task_tmp/$archive" | cut -d ' ' -f 1)"
fi
if [[ "$actual" != "$digest" ]]; then echo "Secret scanner checksum mismatch" >&2; exit 1; fi
tar -xzf "$task_tmp/$archive" -C "$task_tmp" gitleaks
mkdir "$task_tmp/source"
git -C "$root" ls-files -z | tar --null -C "$root" -T - -cf "$task_tmp/source.tar"
tar -xf "$task_tmp/source.tar" -C "$task_tmp/source"
cd "$task_tmp/source"
"$task_tmp/gitleaks" dir . --redact=100 --no-banner --verbose
