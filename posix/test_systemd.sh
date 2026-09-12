#!/bin/sh
# Optional real-manager fixture; creates only uniquely named transient test units.
set -eu
case "${1:---help}" in --run) ;; *) echo "Usage: sh installer/posix/test_systemd.sh --run (isolated Linux user manager)"; exit 0;; esac
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$here/linux/lifecycle.sh"
work=$(mktemp -d)
unit=oa-posix-lifecycle-test-$$.service
cleanup() { manager stop "$unit" >/dev/null 2>&1 || true; manager reset-failed "$unit" >/dev/null 2>&1 || true; rm -f "$work/pid" "$work/graceful"; rmdir "$work"; }
trap cleanup EXIT HUP INT TERM
for mode in graceful forced; do
    rm -f "$work/pid" "$work/graceful"
    # A one-second cooperative budget keeps the hostile test short.
    systemd-run --user --unit="$unit" --property=Type=exec --property=KillMode=control-group --property=TimeoutStopSec=1s \
        /bin/sh -c 'if [ "$1" = graceful ]; then dir=$2; finish() { echo done > "$dir/graceful"; exit 0; }; trap finish TERM; else trap "" TERM; fi; sleep 600 & echo $! > "$2/pid"; wait' sh "$mode" "$work"
    count=0
    until [ -s "$work/pid" ]; do count=$((count+1)); [ "$count" -le 30 ]; sleep 0.1; done
    descendant=$(cat "$work/pid")
    output=$(stop_unit "$unit" 2>&1)
    echo "$output"
    if kill -0 "$descendant" 2>/dev/null; then echo "descendant still exists: $descendant" >&2; exit 1; fi
    if [ "$mode" = graceful ]; then [ -f "$work/graceful" ]; else
        [ ! -f "$work/graceful" ]
        echo "$output" | grep 'graceful completion not established'
    fi
    manager reset-failed "$unit" >/dev/null 2>&1 || true
    unit=oa-posix-lifecycle-forced-test-$$.service
 done
echo "PASS real user-manager graceful and forced descendant shutdown"
