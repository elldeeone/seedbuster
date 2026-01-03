#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

backup_dir="backups/nightly"
mkdir -p "$backup_dir"

timestamp="$(date +%Y-%m-%d)"
archive="$backup_dir/seedbuster-data-$timestamp.tgz"

tar -czf "$archive" data

git add "$archive"
if git diff --cached --quiet -- "$archive"; then
  exit 0
fi

git commit -m "Backup data $timestamp" -- "$archive"
