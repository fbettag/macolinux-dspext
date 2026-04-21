#!/usr/bin/env bash
set -euo pipefail

duration="${1:-60}"
out="${2:-/tmp/universal-control-awdl.pcap}"
iface="${UC_CAPTURE_IFACE:-awdl0}"
root_host="${UC_CAPTURE_ROOT_HOST:-root@localhost}"

case "$duration" in
  ''|*[!0-9]*)
    echo "duration must be an integer number of seconds" >&2
    exit 2
    ;;
esac

remote_cmd=$(cat <<EOF
set -euo pipefail
rm -f "$out"
(tcpdump -i "$iface" -n -s 0 -w "$out" &
 pid=\$!
 sleep "$duration"
 kill -INT \$pid 2>/dev/null || true
 wait \$pid 2>/dev/null || true)
chmod 0644 "$out"
ls -lh "$out"
EOF
)

echo "capturing $iface for ${duration}s through ssh $root_host"
ssh "$root_host" "$remote_cmd"
echo "pcap written to $out"
