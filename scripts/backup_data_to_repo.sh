#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="$repo_root/data"
worktree_dir="$repo_root/.backup-worktree"
branch="backup"
backup_remote="${BACKUP_REMOTE:-backup}"
backup_ssh_command="${BACKUP_SSH_COMMAND:-ssh -i /etc/seedbuster/backup_deploy_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts}"

if ! git -C "$repo_root" rev-parse --git-dir >/dev/null 2>&1; then
  echo "Not a git repo: $repo_root" >&2
  exit 1
fi

if [ ! -d "$data_dir" ]; then
  echo "Missing data dir: $data_dir" >&2
  exit 1
fi

if ! git -C "$repo_root" remote get-url "$backup_remote" >/dev/null 2>&1; then
  echo "Missing git remote: $backup_remote" >&2
  exit 1
fi

if [ ! -e "$worktree_dir/.git" ]; then
  if GIT_SSH_COMMAND="$backup_ssh_command" git -C "$repo_root" ls-remote --exit-code --heads "$backup_remote" "$branch" >/dev/null 2>&1; then
    git -C "$repo_root" worktree add -B "$branch" "$worktree_dir" "$backup_remote/$branch"
  else
    git -C "$repo_root" worktree add -B "$branch" "$worktree_dir"
  fi
fi

git -C "$worktree_dir" switch "$branch" >/dev/null 2>&1 || true
GIT_SSH_COMMAND="$backup_ssh_command" git -C "$worktree_dir" pull --ff-only "$backup_remote" "$branch" >/dev/null 2>&1 || true

backup_dir="$worktree_dir/backups/nightly"
mkdir -p "$backup_dir"

timestamp="$(date +%Y-%m-%d)"
archive_rel="backups/nightly/seedbuster-data-$timestamp.tgz"
archive="$worktree_dir/$archive_rel"

tar -czf "$archive" -C "$repo_root" data

git -C "$worktree_dir" add "$archive_rel"
if git -C "$worktree_dir" diff --cached --quiet -- "$archive_rel"; then
  exit 0
fi

git -C "$worktree_dir" commit -m "Backup data $timestamp" -- "$archive_rel"
GIT_SSH_COMMAND="$backup_ssh_command" git -C "$worktree_dir" push "$backup_remote" "$branch"
