#!/usr/bin/env bash
set -euo pipefail

host="${HOST:-fistel}"
port="${PORT:-4720}"
target="${TARGET:-.#fistel}"
nixos_dir="${NIXOS_DIR:-/etc/nixos}"
edge="${EDGE:-right}"
remote_width="${REMOTE_WIDTH:-1920}"
remote_height="${REMOTE_HEIGHT:-1080}"
ssh_check_log="$(mktemp -t macolinux-fistel-ssh-check.XXXXXX)"
trap 'rm -f "$ssh_check_log"' EXIT

usage() {
  cat <<EOF
usage: $0 [--no-deploy] [--live]

Environment:
  HOST=$host
  PORT=$port
  TARGET=$target
  NIXOS_DIR=$nixos_dir
  EDGE=$edge
  REMOTE_WIDTH=$remote_width
  REMOTE_HEIGHT=$remote_height

The script requires root SSH to HOST. It does not git-add or commit /etc/nixos.
EOF
}

deploy=1
live=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --no-deploy)
      deploy=0
      ;;
    --live)
      live=1
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

echo "checking SSH reachability for root@$host ..."
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$host" 'hostname; uptime' >"$ssh_check_log" 2>&1; then
  cat "$ssh_check_log" >&2
  echo "root@$host is not reachable; wake or reconnect the laptop, then rerun this script." >&2
  exit 69
fi
cat "$ssh_check_log"

if [[ "$deploy" -eq 1 ]]; then
  echo "deploying $target from $nixos_dir ..."
  (
    cd "$nixos_dir"
    nix run github:serokell/deploy-rs -- --targets "$target"
  )
fi

echo "verifying Linux input service ..."
ssh "root@$host" '
  set -e
  systemctl is-active macolinux-uc-input
  systemctl status macolinux-uc-input --no-pager --lines=20
  test -c /dev/uinput
  ls -l /dev/uinput
'

echo "running macOS-to-Linux input self-test ..."
nix run .#macolinux-macos-input-forwarder -- \
  --host "$host" \
  --port "$port" \
  --self-test

if [[ "$live" -eq 1 ]]; then
  echo "starting live bridge; move into the configured $edge edge to enter Linux input."
  exec nix run .#macolinux-macos-input-forwarder -- \
    --host "$host" \
    --port "$port" \
    --edge "$edge" \
    --remote-width "$remote_width" \
    --remote-height "$remote_height"
fi

cat <<EOF
self-test succeeded.

Start the live bridge with:
  $0 --no-deploy --live
EOF
