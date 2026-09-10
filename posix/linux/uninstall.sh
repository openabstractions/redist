#!/bin/sh
# Removes exactly what install.sh recorded, and nothing it did not.
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

systemd=no
if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
	systemd=yes
	systemctl --user disable --now abstraction-jobd.timer 2>/dev/null || true
	systemctl --user stop abstraction-jobd.service 2>/dev/null || true
fi

grep '^/' "$manifest" | while IFS= read -r f; do rm -f -- "$f"; done
grep '^/' "$manifest" | prune

if [ "$systemd" = yes ]; then
	systemctl --user daemon-reload
fi

rm -f -- "$manifest" "$share/uninstall.sh"
echo "$share/." | prune

echo "ok    removed. Two things were deliberately left:"
echo "        ~/.abstraction            your job store and anything still in it"
echo "        ~/.config/abstraction     what jobd setup recorded about this machine"
echo "      Remove them yourself if you want them gone:  rm -rf ~/.abstraction ~/.config/abstraction"
