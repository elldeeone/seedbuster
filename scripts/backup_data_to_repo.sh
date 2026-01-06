#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="$repo_root/data"
worktree_dir="$repo_root/.backup-worktree"
branch="backup"
backup_remote="${BACKUP_REMOTE:-backup}"
backup_ssh_command="${BACKUP_SSH_COMMAND:-ssh -i /etc/seedbuster/backup_deploy_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts}"

echo "Backup start $(date -Is)"

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

include_paths=(
  "opt/seedbuster/data"
  "opt/seedbuster/config"
  "etc/seedbuster/admin-ips.conf"
  "etc/systemd/system/seedbuster.service"
  "etc/systemd/system/seedbuster-dashboard.service"
  "etc/systemd/system/update-cloudflare-nft.service"
  "etc/systemd/system/update-cloudflare-nft.timer"
  "etc/ssh/sshd_config.d/99-hardening.conf"
  "etc/nginx/nginx.conf"
  "etc/nginx/sites-available/seedbuster"
  "etc/nftables.conf"
  "etc/nftables.d/seedbuster.nft"
  "etc/sysctl.d/99-seedbuster-hardening.conf"
)
missing_paths=()
final_paths=()
for path in "${include_paths[@]}"; do
  if [ -e "/$path" ]; then
    final_paths+=("$path")
  else
    missing_paths+=("$path")
  fi
done
if [ "${#missing_paths[@]}" -gt 0 ]; then
  echo "Missing paths: ${missing_paths[*]}"
fi

tar -czf "$archive" -C / \
  --exclude="etc/seedbuster/seedbuster.env" \
  --exclude="etc/seedbuster/backup_deploy_key" \
  --exclude="etc/seedbuster/backup_deploy_key.pub" \
  --exclude="etc/seedbuster/seedbuster.env.bak"* \
  --ignore-failed-read \
  "${final_paths[@]}"
echo "Archive created $archive_rel"

git -C "$worktree_dir" add "$archive_rel"
if git -C "$worktree_dir" diff --cached --quiet -- "$archive_rel"; then
  echo "No changes for $timestamp (already backed up)"
  exit 0
fi

git -C "$worktree_dir" commit -m "Backup data $timestamp" -- "$archive_rel"
GIT_SSH_COMMAND="$backup_ssh_command" git -C "$worktree_dir" push "$backup_remote" "$branch"
echo "Backup pushed to $backup_remote/$branch"
