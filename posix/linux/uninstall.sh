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


# MANIFEST is an ownership ledger, not permission to delete arbitrary user paths.
valid_path() (
    f=$1
    case "$f" in
        "$HOME/.local/bin/openabstractions"|"$HOME/.config/systemd/user/abstraction-runtime.service"|"$HOME/.local/share/abstraction/"*) ;;
        # Retired by 0.2.0 (docs/REMOVED.md). A predecessor's ledger still names
        # them, and they are removed only when their recorded bytes match.
        "$HOME/.local/bin/jobd"|"$HOME/.local/bin/jobctl"|"$HOME/.local/bin/dl"|"$HOME/.config/systemd/user/abstraction-jobd.service"|"$HOME/.config/systemd/user/abstraction-jobd.timer") ;;
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

. "$share/lifecycle.sh"
command -v timeout >/dev/null 2>&1 || { echo "uninstall.sh: timeout is required" >&2; exit 1; }
systemd=no
if command -v systemctl >/dev/null 2>&1 && manager show-environment >/dev/null 2>&1; then
    systemd=yes
    stop_installed
    disable_retired
    load=$(manager show abstraction-runtime.service --property=LoadState --value)
    if [ "$load" != not-found ]; then manager disable abstraction-runtime.service; fi
elif grep -q '^timer yes$' "$manifest"; then
    echo "uninstall.sh: registered user manager unavailable; payload retained" >&2
    exit 1
fi

# Validate the full ledger above before any destructive operation. Active legacy
# entries retain their removal behavior. Retired entries require matching bytes.
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
removed=$(mktemp)
trap 'rm -f -- "$removed"' EXIT
while IFS= read -r entry || [ -n "$entry" ]; do
    case "$entry" in
        /*) rm -f -- "$entry"; printf '%s\n' "$entry" >> "$removed";;
        'retired '*) item=${entry#* }; hash=${item%% *}; path=${item#* }
            if [ -f "$path" ]; then
                actual=-
                if [ "$hash" != - ]; then actual=$(file_hash "$path"); fi
                if [ "$hash" != - ] && [ "$actual" = "$hash" ]; then
                    rm -f -- "$path"; printf '%s\n' "$path" >> "$removed"
                else
                    echo "preserved retired file (modified or no original hash): $path" >&2
                fi
            fi;;
    esac
done < "$manifest"
prune < "$removed"

if [ "$systemd" = yes ]; then
	manager daemon-reload
fi

rm -f -- "$manifest" "$share/uninstall.sh"
echo "$share/." | prune

echo "ok    removed installed programs and registrations; user data retained:"
echo "        ~/.local/share/openabstractions/runtime-v1    managed runtime state"
echo "        ~/.cache/openabstractions                     runtime logs/cache"
echo "        ~/.abstraction                                legacy job store"
echo "        ~/.config/abstraction                         configuration"
echo "      XDG directory overrides and configured external stores keep their own locations."
echo "      Remove retained data separately only when you intend to discard it."
