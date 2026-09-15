#!/bin/sh
# Removes exactly what the package installed, and nothing it did not.
# macOS ships no uninstaller for a .pkg, so the package ships one.
#
# Order: stop the LaunchAgent, forget the package receipt, delete the payload,
# delete runtime lock files, then delete this script and MANIFEST last. Every
# step tolerates a previous partial run, so the printed recovery command is
# always a command that can still run.
set -eu

share=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest=$share/MANIFEST
self=$share/uninstall.sh
home=${HOME:-/}
receipt=com.openabstractions.abstraction
uid=$(id -u)
service=gui/$uid/com.openabstractions.jobd

# Single-quotes a value for a command line the person can paste.
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

rerun="/bin/sh $(quote "$self")"
recovery="from Terminal in this user's desktop session: $rerun"
retained_extra=

notice() {
    echo "      retained user data (review before removing it separately):"
    echo "        ~/.abstraction                                      legacy job store"
    echo "        ~/Library/Application Support/abstraction           legacy settings"
    echo "        ~/Library/Application Support/openabstractions/runtime-v1  runtime state and accepted work"
    echo "        ~/Library/Caches/openabstractions                   user cache/logging data"
    if [ -n "$retained_extra" ]; then printf '%s' "$retained_extra"; fi
}

finish() {
    code=$?
    trap - EXIT
    if [ "$code" -ne 0 ]; then
        echo "uninstall.sh: removal incomplete (exit $code)" >&2
        echo "      recovery, $recovery" >&2
        notice >&2
    fi
    exit "$code"
}
trap finish EXIT

fail() { echo "uninstall.sh: $1" >&2; exit 1; }

if [ ! -f "$manifest" ]; then
    recovery="list and forget the receipt: pkgutil --volume $(quote "$home") --files $receipt; pkgutil --volume $(quote "$home") --forget $receipt"
    fail "no MANIFEST beside this script; refusing to guess what to delete"
fi
. "$share/lifecycle.sh"

# Reads paths on standard input. Every directory between a removed file and the
# home directory, deepest first, so an empty tree three levels deep goes away
# instead of one level of it. rmdir refuses a directory that is not empty, which
# is the whole safety property here.
prune() {
	while IFS= read -r f; do
		d=${f%/*}
		while [ -n "$d" ] && [ "$d" != "$home" ] && [ "$d" != "/" ]; do
			echo "$d"
			d=${d%/*}
		done
	done | sort -ru | while IFS= read -r d; do rmdir -- "$d" 2>/dev/null || true; done
}

# list enumerates the current bootstrap. Refuse other contexts instead of
# inferring GUI absence from a query against an SSH/background namespace.
manager_uid=$(manager manageruid) || fail "launchd manager query failed; payload retained"
manager_name=$(manager managername) || fail "launchd manager query failed; payload retained"
[ "$manager_uid" = "$uid" ] && [ "$manager_name" = Aqua ] ||
    fail "run from this user's graphical login session; payload retained"
agent_state() {
    jobs=$(manager list) || return 1
    # The native list command documents PID, status, label columns. Unknown
    # formats and query errors cannot establish absence.
    printf '%s\n' "$jobs" | awk '
        NR == 1 { if (NF != 3 || $1 != "PID" || $2 != "Status" || $3 != "Label") bad=1; next }
        NF < 3 || $1 !~ /^(-|[0-9]+)$/ || $2 !~ /^-?[0-9]+$/ { bad=1 }
        NF == 3 && $3 == "com.openabstractions.jobd" { found=1 }
        END { if (bad || NR == 0) exit 2; print found ? "present" : "absent" }
    '
}
recovery="from Terminal in this user's desktop session: launchctl bootout $service; $rerun"
state=$(agent_state) || state=unknown
if [ "$state" = present ]; then
    # ExitTimeOut bounds launchd's cooperative interval; escalation is possible.
    manager bootout "$service" || fail "LaunchAgent bootout failed; payload retained"
    state=$(agent_state) || state=unknown
fi
[ "$state" = absent ] || fail "LaunchAgent registration state is $state; payload retained"
echo "ok    LaunchAgent absence verified (graceful exit is not independently established)"

# The package installs into the current user's home domain, and its receipt is
# on that volume. A receipt on / would come from a system-domain install. Only a
# "No receipt" answer establishes absence; any other pkgutil failure stops here
# with the payload and this script still in place.
receipt_on() {
    out=$(pkgutil --volume "$1" --pkg-info "$receipt" 2>&1) && { echo present; return 0; }
    case "$out" in *"No receipt"*) echo absent; return 0;; esac
    printf '%s\n' "$out" >&2
    return 1
}
forget_on() {
    recovery="$2pkgutil --volume $(quote "$1") --forget $receipt; then $rerun"
    pkgutil --volume "$1" --forget "$receipt" || fail "package receipt on $1 could not be forgotten; payload retained"
    [ "$(receipt_on "$1")" = absent ] || fail "package receipt on $1 remains after forget; payload retained"
    echo "ok    package receipt forgotten on $1"
}
recovery="check the receipt with pkgutil --volume $(quote "$home") --pkg-info $receipt, then $rerun"
home_receipt=$(receipt_on "$home") || fail "package receipt query failed on $home; payload retained"
if [ "$home_receipt" = present ]; then
    forget_on "$home" ""
else
    recovery="check the receipt with pkgutil --volume / --pkg-info $receipt, then $rerun"
    root_receipt=$(receipt_on /) || fail "package receipt query failed on /; payload retained"
    if [ "$root_receipt" = present ]; then
        forget_on / "sudo "
    else
        echo "ok    no package receipt present"
    fi
fi

# This script, its helper and MANIFEST stay until every other file is gone, so
# a failure here can be retried by running this script again.
recovery="from Terminal in this user's desktop session: $rerun"
failed=0
while IFS= read -r f; do
    case "$f" in /*) ;; *) continue;; esac
    case "$f" in "$self"|"$share/lifecycle.sh"|"$manifest") continue;; esac
    rm -f -- "$f" 2>/dev/null || :
    if [ -e "$f" ] || [ -L "$f" ]; then echo "uninstall.sh: could not remove $f" >&2; failed=1; fi
done < "$manifest"
[ "$failed" = 0 ] || fail "some installed files remain"
grep '^/' "$manifest" | prune
echo "ok    removed installed programs, LaunchAgent plist and share files"

# The runtime unlinks each socket when it stops and deliberately keeps the lock
# beside it (abstraction-identity/listen). With the LaunchAgent verified absent,
# a lock whose socket is gone belongs to nobody. A socket that is still present
# may have a listener outside the LaunchAgent, so it and its lock are retained.
# The directory is Go's os.TempDir, the one the runtime used: $TMPDIR, else /tmp.
user=${USER:-$(id -un)}
dir=${TMPDIR:-/tmp}
dir=${dir%/}
for lock in "$dir"/openabstractions-*-"$user".sock.lock; do
    [ -f "$lock" ] || continue
    if [ -e "${lock%.lock}" ]; then
        retained_extra="$retained_extra        ${lock%.lock} and its .lock   socket still present at removal
"
        continue
    fi
    rm -f -- "$lock" || fail "could not remove runtime lock $lock"
done
echo "ok    removed runtime socket lock files"

recovery="rm -f -- $(quote "$share/lifecycle.sh") $(quote "$manifest") $(quote "$self")"
rm -f -- "$share/lifecycle.sh" "$manifest" "$self"
printf '%s\n' "$share/." | prune

echo "ok    removed installed payload, registration and package receipt"
notice
