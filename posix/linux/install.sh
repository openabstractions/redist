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
manifest=$share/MANIFEST

if [ "$(id -u)" = 0 ]; then
	echo "install.sh: this package is per-user. Run it as the person who will use it, not as root." >&2
	exit 1
fi
if [ ! -d "$payload" ]; then
	echo "install.sh: no payload beside this script. Unpack the tarball and run it from inside." >&2
	exit 1
fi


# MANIFEST is an ownership ledger, not permission to delete arbitrary user paths.
valid_path() (
    f=$1
    case "$f" in
        "$HOME/.local/bin/jobd"|"$HOME/.local/bin/jobctl"|"$HOME/.local/bin/dl"|"$HOME/.local/bin/openabstractions"|"$HOME/.config/systemd/user/abstraction-jobd.service"|"$HOME/.config/systemd/user/abstraction-jobd.timer"|"$HOME/.config/systemd/user/abstraction-runtime.service"|"$HOME/.local/share/abstraction/"*) ;;
        *) echo "unsafe installation path; payload retained" >&2; exit 1;;
    esac
    case "$f" in */../*|*/./*|*//*|*/..|*/.|*/MANIFEST|*/MANIFEST.*) echo "noncanonical installation path" >&2; exit 1;; esac
    [ ! -L "$f" ] && { [ ! -e "$f" ] || [ -f "$f" ]; } || { echo "nonregular installation path" >&2; exit 1; }
    d=${f%/*}
    while [ "$d" != "$HOME" ]; do
        [ ! -L "$d" ] && { [ ! -e "$d" ] || [ -d "$d" ]; } || { echo "unsafe installation ancestor" >&2; exit 1; }
        d=${d%/*}
        [ -n "$d" ] && [ "$d" != / ] || exit 1
    done
)
valid_hash() {
    [ "$1" = - ] && return 0
    [ ${#1} = 64 ] || return 1
    case "$1" in *[!0123456789abcdef]*) return 1;; esac
}
validate_manifest() {
    [ ! -L "$manifest" ] || { echo "symlink MANIFEST refused" >&2; return 1; }
    [ ! -e "$manifest" ] && return 0
    [ -f "$manifest" ] || return 1
    while IFS= read -r entry || [ -n "$entry" ]; do
        case "$entry" in
            /*) valid_path "$entry" || return 1;;
            'sha256 '*|'retired '*) item=${entry#* }; hash=${item%% *}; path=${item#* }
                valid_hash "$hash" && [ "$path" != "$item" ] && valid_path "$path" || return 1;;
            'timer yes'|'timer no'|'') ;;
            *) echo "malformed installation MANIFEST; payload retained" >&2; return 1;;
        esac
    done < "$manifest"
}
file_hash() (
    output=$(sha256sum < "$1") || { echo "checksum failed; payload retained" >&2; exit 1; }
    digest=${output%% *}
    [ "$digest" != - ] && valid_hash "$digest" || { echo "invalid checksum output" >&2; exit 1; }
    printf '%s\n' "$digest"
)
[ -n "$HOME" ] && [ "$HOME" != / ] && [ "$(CDPATH= cd -- "$HOME" && pwd -P)" = "$HOME" ] || { echo "canonical user home required" >&2; exit 1; }
valid_path "$share/uninstall.sh"
validate_manifest

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
# Check with the candidate writer after the predecessor has stopped and before
# replacing payload or its removal manifest. Startup checks again under ownership.
candidate=$payload/.local/bin/openabstractions
if ! timeout --kill-after=2s 20s "$candidate" storage check; then
    echo "install.sh: candidate cannot safely open retained runtime state; installed payload retained, services remain stopped" >&2
    exit 1
fi
# Prepare every candidate byte and backup before replacing installed files.
# The ledger commits last; traps undo replacement failures before activation.
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
mkdir -p "$share"
stage=$(mktemp -d "$share/.install.XXXXXX")
committed=no
ledger_changing=no
: > "$stage/changed"
cleanup_install() {
    status=$?
    trap - EXIT INT TERM
    if [ "$committed" = no ]; then
        restored=yes
        while IFS= read -r rel; do
            dst=$HOME/$rel
            if [ -f "$stage/backup/$rel" ]; then
                mv -f -- "$stage/backup/$rel" "$dst" || restored=no
            else
                rm -f -- "$dst" || restored=no
            fi
        done < "$stage/changed"
        if [ "$ledger_changing" = yes ]; then
            if [ -f "$stage/previous-manifest" ]; then
                mv -f -- "$stage/previous-manifest" "$manifest" || restored=no
            else
                rm -f -- "$manifest" || restored=no
            fi
        fi
        if [ "$restored" != yes ]; then
            echo "installation rollback failed; backups retained at $stage" >&2
            exit 1
        fi
    fi
    rm -rf -- "$stage"
    exit "$status"
}
trap cleanup_install EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[ ! -f "$manifest" ] || cp -p -- "$manifest" "$stage/previous-manifest"
( cd "$payload" && find . -type f -print ) > "$stage/raw-files"
sed 's|^\./||' "$stage/raw-files" > "$stage/unsorted-files"
LC_ALL=C sort "$stage/unsorted-files" > "$stage/files"
: > "$stage/MANIFEST"
while IFS= read -r rel; do
    dst=$HOME/$rel
    valid_path "$dst"
    mkdir -p "$stage/new/$(dirname -- "$rel")" "$stage/backup/$(dirname -- "$rel")"
    cp -- "$payload/$rel" "$stage/new/$rel"
    case $rel in .local/bin/*|*.sh) chmod 755 "$stage/new/$rel";; *) chmod 644 "$stage/new/$rel";; esac
    if [ -f "$dst" ]; then cp -p -- "$dst" "$stage/backup/$rel"; fi
    digest=$(file_hash "$stage/new/$rel")
    printf '%s\nsha256 %s %s\n' "$dst" "$digest" "$dst" >> "$stage/MANIFEST"
done < "$stage/files"
# Preserve retired ownership separately. Old path-only ledgers supply no hash;
# those files remain user-owned on uninstall and are reported explicitly.
old_hash() (
    wanted=$1; answer=-
    while IFS= read -r entry || [ -n "$entry" ]; do
        case "$entry" in 'sha256 '*) item=${entry#* }; hash=${item%% *}; path=${item#* }
            if [ "$path" = "$wanted" ]; then
                [ "$answer" = - ] || [ "$answer" = "$hash" ] || exit 1
                answer=$hash
            fi;; esac
    done < "$manifest"
    printf '%s\n' "$answer"
)
if [ -f "$manifest" ]; then
    while IFS= read -r entry || [ -n "$entry" ]; do
        case "$entry" in
            /*) path=$entry; hash=$(old_hash "$path");;
            'retired '*) item=${entry#* }; hash=${item%% *}; path=${item#* };;
            *) continue;;
        esac
        rel=${path#"$HOME/"}
        if ! grep -F -x -- "$rel" "$stage/files" >/dev/null; then
            printf 'retired %s %s\n' "$hash" "$path" >> "$stage/MANIFEST"
        fi
    done < "$manifest"
fi
printf 'timer %s\n' "$managed" >> "$stage/MANIFEST"
while IFS= read -r rel; do
    dst=$HOME/$rel
    valid_path "$dst"
    mkdir -p "$(dirname -- "$dst")"
    printf '%s\n' "$rel" >> "$stage/changed"
    mv -f -- "$stage/new/$rel" "$dst"
done < "$stage/files"
ledger_changing=yes
mv -f -- "$stage/MANIFEST" "$manifest"
committed=yes
n=$(wc -l < "$stage/files" | tr -d ' ')
echo "ok    $n files under $HOME"

timer=no
if [ "$managed" = yes ]; then
	manager daemon-reload
	# Record manager ownership before a partial registration can fail.
    # Manager ownership was committed with the candidate ledger.
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
