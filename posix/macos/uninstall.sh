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

launchctl bootout "gui/$(id -u)/com.openabstractions.jobd" 2>/dev/null || true

grep '^/' "$manifest" | while IFS= read -r f; do rm -f -- "$f"; done
grep '^/' "$manifest" | prune

pkgutil --forget com.openabstractions.abstraction >/dev/null 2>&1 || true

rm -f -- "$manifest" "$share/FILES" "$share/uninstall.sh"
echo "$share/." | prune

echo "ok    removed. Two things were deliberately left:"
echo "        ~/.abstraction                                 your job store"
echo "        ~/Library/Application Support/abstraction      what jobd setup recorded"
echo "      Remove them yourself if you want them gone:"
echo "        rm -rf ~/.abstraction \"\$HOME/Library/Application Support/abstraction\""
