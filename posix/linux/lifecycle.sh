# Shared by the tarball installer and installed uninstaller.
# timeout bounds manager IPC; systemd owns and stops the service cgroup.
manager() { timeout --kill-after=2s 20s systemctl --user "$@"; }
stop_unit() {
    unit=$1
    load=$(manager show "$unit" --property=LoadState --value) || return 1
    [ "$load" != not-found ] || return 0
    manager stop "$unit" || return 1
    state=$(manager show "$unit" --property=ActiveState --value) || return 1
    case "$state" in inactive|failed) ;; *) echo "still active: $unit ($state)" >&2; return 1;; esac
    case "$unit" in *.service)
        pid=$(manager show "$unit" --property=MainPID --value) || return 1
        [ "$pid" = 0 ] || { echo "still running: $unit" >&2; return 1; }
        result=$(manager show "$unit" --property=Result --value) || return 1
        case "$result" in success) echo "ok    $unit stopped without manager escalation";;
        *) echo "note  $unit stopped; manager result=$result (graceful completion not established)" >&2;; esac
    esac
}
stop_installed() {
    # Stop triggers before workers, then prevent registration from restarting.
    stop_unit abstraction-jobd.timer &&
    stop_unit abstraction-jobd.service &&
    stop_unit abstraction-runtime.service
}
