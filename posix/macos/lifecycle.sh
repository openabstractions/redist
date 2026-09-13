#!/bin/sh
# Bounds only the launchctl command this invocation owns. launchd owns service
# shutdown (ExitTimeOut); no service PID is inferred or signalled here.
manager() (
    state=$(mktemp -d "${TMPDIR:-/tmp}/oa-launchctl.XXXXXX") || exit 1
    command_pid= watchdog=
    cleanup() {
        if [ -n "$command_pid" ]; then kill -KILL "$command_pid" 2>/dev/null || :; wait "$command_pid" 2>/dev/null || :; fi
        if [ -n "$watchdog" ]; then kill "$watchdog" 2>/dev/null || :; wait "$watchdog" 2>/dev/null || :; fi
        rm -f "$state/expired"; rmdir "$state"
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    /bin/launchctl "$@" & command_pid=$!
    (
        sleeper=
        trap 'if [ -n "$sleeper" ]; then kill "$sleeper" 2>/dev/null || :; wait "$sleeper" 2>/dev/null || :; fi; exit 0' TERM INT
        sleep 20 & sleeper=$!; wait "$sleeper" || exit 0
        : > "$state/expired"
        kill -TERM "$command_pid" 2>/dev/null || :
        sleep 2 & sleeper=$!; wait "$sleeper" || exit 0
        kill -KILL "$command_pid" 2>/dev/null || :
    ) & watchdog=$!
    code=0; wait "$command_pid" || code=$?
    command_pid=
    kill "$watchdog" 2>/dev/null || :; wait "$watchdog" 2>/dev/null || :; watchdog=
    if [ -f "$state/expired" ]; then echo "launchctl timed out; lifecycle completion unverified" >&2; exit 124; fi
    exit "$code"
)
