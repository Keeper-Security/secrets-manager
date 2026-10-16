#!/usr/bin/env bash
# Runs ansible-test sanity against the collection as Galaxy would see it.
# ansible-test only runs from inside ansible_collections/<ns>/<name>/, and the plugins live in the
# Python package rather than the collection directory, so this assembles a throwaway tree first.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
work="${1:-$(mktemp -d)}"
dest="$work/ansible_collections/keepersecurity/keeper_secrets_manager"

rm -rf "$dest"
mkdir -p "$dest"
cp -R "$here/ansible_galaxy/keepersecurity/keeper_secrets_manager/." "$dest/"
cp -R "$here/keeper_secrets_manager_ansible/plugins" "$dest/plugins"
find "$dest" -name __pycache__ -prune -exec rm -rf {} +
sed -i.bak 's/VERSION_PLACEHOLDER/0.0.0/' "$dest/galaxy.yml" && rm "$dest/galaxy.yml.bak"

# ansible-test only sees files tracked by git.
cd "$dest"
git init -q
git add -A

shift || true
ansible-test sanity --venv "$@"
