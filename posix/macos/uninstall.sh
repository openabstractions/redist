#!/bin/sh
# Removes exactly what the package installed, and nothing it did not.
# macOS ships no uninstaller for a .pkg, so the package ships one.
set -eu

share=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest=$share/MANIFEST
home=${HOME:-/}
if [ ! -f "$manifest" ]; then
	echo "uninstall.sh: no MANIFEST beside this script; refusing to guess what to delete." >&2
	exit 1
fi

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

uid=$(id -u)
service=gui/$uid/com.openabstractions.jobd
# list enumerates the current bootstrap. Refuse other contexts instead of
# inferring GUI absence from a query against an SSH/background namespace.
manager_uid=$(launchctl manageruid)
manager_name=$(launchctl managername)
[ "$manager_uid" = "$uid" ] && [ "$manager_name" = Aqua ] || {
    echo "uninstall.sh: run from this user's graphical login session; payload retained" >&2
    exit 1
}
agent_state() {
    jobs=$(launchctl list) || return 1
    # The native list command documents PID, status, label columns. Unknown
    # formats and query errors cannot establish absence.
    printf '%s\n' "$jobs" | awk '
        NR == 1 { if (NF != 3 || $1 != "PID" || $2 != "Status" || $3 != "Label") bad=1; next }
        NF < 3 || $1 !~ /^(-|[0-9]+)$/ || $2 !~ /^-?[0-9]+$/ { bad=1 }
        NF == 3 && $3 == "com.openabstractions.jobd" { found=1 }
        END { if (bad || NR == 0) exit 2; print found ? "present" : "absent" }
    '
}
state=$(agent_state)
if [ "$state" = present ]; then
    # ExitTimeOut bounds launchd's cooperative interval; escalation is possible.
    launchctl bootout "$service"
    state=$(agent_state)
fi
[ "$state" = absent ] || {
    echo "uninstall.sh: LaunchAgent remains registered; payload retained" >&2
    exit 1
}
echo "ok    LaunchAgent absence verified (graceful exit is not independently established)"

grep '^/' "$manifest" | while IFS= read -r f; do rm -f -- "$f"; done
grep '^/' "$manifest" | prune

if ! pkgutil --forget com.openabstractions.abstraction; then
    echo "uninstall.sh: files removed, but package receipt cleanup failed; retry receipt removal" >&2
    exit 1
fi

rm -f -- "$manifest" "$share/FILES" "$share/uninstall.sh"
echo "$share/." | prune

echo "ok    removed. Two things were deliberately left:"
echo "        ~/.abstraction                                 your job store"
echo "        ~/Library/Application Support/abstraction      what jobd setup recorded"
echo "      Remove them yourself if you want them gone:"
echo "        rm -rf ~/.abstraction \"\$HOME/Library/Application Support/abstraction\""
