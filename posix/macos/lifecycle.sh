#!/bin/sh
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
