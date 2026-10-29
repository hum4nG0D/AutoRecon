#!/usr/bin/env bash
set -euo pipefail

if ! command -v pipx >/dev/null 2>&1; then
  printf "pipx is required. Install it with your package manager, then rerun this script.\n" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  printf "curl is required to download LinPEAS.\n" >&2
  exit 1
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
pipx install --force "$repo_dir"

# Refresh this fork's plugin if AutoRecon has already created its user plugin directory.
plugin_dir="${XDG_DATA_HOME:-$HOME/.local/share}/AutoRecon/plugins"
if [ -d "$plugin_dir" ]; then
  install -m 644 "$repo_dir/autorecon/default-plugins/ssh-authenticated-host-checks.py" "$plugin_dir/ssh-authenticated-host-checks.py"
fi

cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/AutoRecon"
mkdir -p "$cache_dir"
chmod 700 "$cache_dir"
tmp_file="$(mktemp "$cache_dir/.linpeas.sh.XXXXXX")"
trap 'rm -f "$tmp_file"' EXIT

curl --fail --location --silent --show-error --retry 3 \
  --connect-timeout 10 --max-time 180 \
  --proto "=https" --proto-redir "=https" \
  --output "$tmp_file" \
  "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"

if [ ! -s "$tmp_file" ]; then
  printf "LinPEAS download was empty; keeping any previous cached copy.\n" >&2
  exit 1
fi

chmod 600 "$tmp_file"
mv -f "$tmp_file" "$cache_dir/linpeas.sh"
trap - EXIT
printf "AutoRecon installed. LinPEAS saved to %s\n" "$cache_dir/linpeas.sh"
