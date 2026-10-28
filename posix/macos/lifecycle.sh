#!/bin/sh
# Current source bytes of the two conditional login templates. The payload
# builder writes authored text with LF; the runtime's private renderers have a
# parity receiver against these same sources. This is current ownership, not a
# historical installation pin.
login_template_check() {
    case "$1" in
        com.openabstractions.runtime-login) expected=f2073cc800cd04b21b13bc30484f38d3f3e6caea1dde1c37fa21f390f922fcf9;;
        com.openabstractions.panel) expected=96da072a7821e25920902fc5395d473947ce919d0f02877f0c4fdb2671b77ae9;;
        *) echo "unknown login template" >&2; return 1;;
    esac
    template=$share/$1.plist
    [ -f "$template" ] && [ ! -L "$template" ] || return 1
    [ "$(stat -f %u "$template")" = "$uid" ] || return 1
    [ "$(stat -f %l "$template")" = 1 ] || return 1
    actual=$(shasum -a 256 < "$template") || return 1
    [ "${actual%% *}" = "$expected" ] || { echo "login template differs: $1" >&2; return 1; }
}

# A late-created trigger is owned only at its exact rendered bytes. Absence is
# legitimate; changed/linked files are retained and stop the package operation.
login_trigger_check() (
    label=$1
    login_template_check "$label" || return 1
    trigger=$home/Library/LaunchAgents/$label.plist
    for dir in "$home" "$home/.local" "$home/.local/share" "$share" "$home/Library" "$home/Library/LaunchAgents"; do
        [ -e "$dir" ] || [ -L "$dir" ] || continue
        [ -d "$dir" ] && [ ! -L "$dir" ] && [ "$(stat -f %u "$dir")" = "$uid" ] || return 1
        mode=$(stat -f %Lp "$dir") || return 1
        case "$mode" in ''|*[!0-7]*) return 1;; esac
        [ $((0$mode & 0022)) -eq 0 ] || return 1
    done
    lock=$trigger.lock
    if [ -e "$lock" ] || [ -L "$lock" ]; then
        [ -f "$lock" ] && [ ! -L "$lock" ] && [ ! -s "$lock" ] && [ "$(stat -f %u "$lock")" = "$uid" ] && [ "$(stat -f %l "$lock")" = 1 ] || return 1
    fi
    [ -e "$trigger" ] || [ -L "$trigger" ] || return 0
    [ -f "$trigger" ] && [ ! -L "$trigger" ] || return 1
    [ "$(stat -f %u "$trigger")" = "$uid" ] || return 1
    [ "$(stat -f %l "$trigger")" = 1 ] || return 1
    rendered=$(mktemp "$share/.login-check.XXXXXX") || return 1
    login_bin=$(printf '%s' "$home/.local/bin" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' | sed 's/[\\&|]/\\&/g')
    sed "s|@BIN@|$login_bin|g" "$template" > "$rendered" || { rm -f -- "$rendered"; return 1; }
    result=0
    cmp -s "$rendered" "$trigger" || result=$?
    rm -f -- "$rendered"
    [ "$result" = 0 ] || { echo "foreign login trigger retained: $label" >&2; return 1; }
)

# Bounds only the launchctl command this invocation owns. launchd owns service
# shutdown (ExitTimeOut); no service PID is inferred or signalled here.
manager() (
    state=$(mktemp -d "${TMPDIR:-/tmp}/oa-launchctl.XXXXXX") || exit 1
    command_pid= watchdog=
    cleanup() {
        if [ -n "$command_pid" ]; then kill -KILL "$command_pid" 2>/dev/null || :; wait "$command_pid" 2>/dev/null || :; fi
        if [ -n "$watchdog" ]; then kill -KILL "$watchdog" 2>/dev/null || :; wait "$watchdog" 2>/dev/null || :; fi
        rm -f "$state/expired"; rmdir "$state"
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    /bin/launchctl "$@" & command_pid=$!
    # The watchdog is stopped with SIGKILL and counts short ticks. A catchable
    # signal can land in a forked sleep before it execs, where the inherited
    # trap swallows it and the sleep runs its whole length while this function
    # waits; that stalled a fixture run for 20 s. A killed watchdog leaves at
    # most one tick running, with no caller output attached.
    (
        exec </dev/null >/dev/null 2>&1
        n=0; ticks=200
        while [ "$n" -lt "$ticks" ]; do sleep 0.1; n=$((n + 1)); done
        : > "$state/expired"
        kill -TERM "$command_pid" 2>/dev/null || :
        n=0; ticks=20
        while [ "$n" -lt "$ticks" ]; do sleep 0.1; n=$((n + 1)); done
        kill -KILL "$command_pid" 2>/dev/null || :
    ) & watchdog=$!
    code=0; wait "$command_pid" || code=$?
    command_pid=
    kill -KILL "$watchdog" 2>/dev/null || :; wait "$watchdog" 2>/dev/null || :; watchdog=
    if [ -f "$state/expired" ]; then echo "launchctl timed out; lifecycle completion unverified" >&2; exit 124; fi
    exit "$code"
)

# launchctl bootout can return while list still reports the removed job. The
# caller supplies agent_state(label), which refuses unknown list formats. Poll
# read-only for up to three seconds; any query failure remains a refusal.
await_agent_absent() {
    awaited_label=$1
    awaited_polls=0
    while :; do
        awaited_state=$(agent_state "$awaited_label") || { echo unknown; return 1; }
        case "$awaited_state" in
            absent) echo absent; return 0;;
            present) ;;
            *) echo "$awaited_state"; return 1;;
        esac
        if [ "$awaited_polls" -ge 30 ]; then echo present; return 1; fi
        sleep 0.1
        awaited_polls=$((awaited_polls + 1))
    done
}
