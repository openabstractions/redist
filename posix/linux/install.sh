#!/bin/sh
# Abstraction, per user, no root. Installs into your home directory and
# registers a systemd *user* timer, matching the Windows package, which is
# per-user with no elevation for the same reason: a supervisor that finishes
# your downloads runs as you, and nothing here needs to outlive your account.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
payload=$here/payload
share=$HOME/.local/share/abstraction
bin=$HOME/.local/bin

if [ "$(id -u)" = 0 ]; then
	echo "install.sh: this package is per-user. Run it as the person who will use it, not as root." >&2
	exit 1
fi
if [ ! -d "$payload" ]; then
	echo "install.sh: no payload beside this script. Unpack the tarball and run it from inside." >&2
	exit 1
fi

# Check existing registrations before replacing any executable or manifest.
. "$payload/.local/share/abstraction/lifecycle.sh"
command -v timeout >/dev/null 2>&1 || { echo "install.sh: timeout is required" >&2; exit 1; }
managed=no
if command -v systemctl >/dev/null 2>&1 && manager show-environment >/dev/null 2>&1; then
    managed=yes
    stop_installed
elif [ -f "$share/MANIFEST" ] && grep -q '^timer yes$' "$share/MANIFEST"; then
    echo "install.sh: registered user manager unavailable; payload retained" >&2
    exit 1
fi
mkdir -p "$share"
manifest=$share/MANIFEST
: > "$manifest"

( cd "$payload" && find . -type f -print ) | sed 's|^\./||' | sort | while read -r rel; do
	dst=$HOME/$rel
	mkdir -p "$(dirname -- "$dst")"
	cp -- "$payload/$rel" "$dst"
	case $rel in
	.local/bin/* | *.sh) chmod 755 "$dst" ;;
	*) chmod 644 "$dst" ;;
	esac
	echo "$dst" >> "$manifest"
done

n=$(wc -l < "$manifest" | tr -d ' ')
echo "ok    $n files under $HOME"

timer=no
if [ "$managed" = yes ]; then
	manager daemon-reload
	# Record manager ownership before a partial registration can fail.
    echo "timer yes" >> "$manifest"
    manager enable --now abstraction-jobd.timer abstraction-runtime.service
    manager is-active --quiet abstraction-runtime.service
    # Startup includes listener initialization; poll read-only readiness within one budget.
    timeout --kill-after=2s 15s sh -c '
        until "$1" status --timeout 1s; do sleep 0.2; done
    ' sh "$bin/openabstractions"
    echo "ok    user runtime started; status probe completed"
	timer=yes
	echo "ok    abstraction-jobd.timer enabled: once 30s after login, then every 5 minutes"
else
	echo "note  no systemd user manager on this machine, so nothing sweeps unfinished"
	echo "note  transfers in the background. dl and jobctl work without it; a transfer"
	echo "note  interrupted after dl exits stays unfinished until you run: jobd once"
fi
echo "timer $timer" >> "$manifest"

case ":$PATH:" in
*":$bin:"*) : ;;
*)
	echo "note  $bin is not on your PATH. Add this to your shell profile:"
	echo "note      export PATH=\"\$HOME/.local/bin:\$PATH\""
	echo "note  Deliberately not written for you: an installer that edits a shell"
	echo "note  profile is an installer nobody can fully remove."
	;;
esac

echo
echo "UNSIGNED. Nothing in this package is signed, and nothing verifies where it"
echo "came from. Check the SHA256SUMS published beside it against what you have."
echo
echo "To remove everything this put on the machine, run exactly:"
echo "    $share/uninstall.sh"
