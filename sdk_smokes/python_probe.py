"""Installed Windows Python SDK selection and read-only config call."""

import os
import sys


def main():
    if len(sys.argv) != 3 or any(os.environ.get(name) for name in (
            "ABSTRACTION_RUNTIME_ENDPOINT", "ABSTRACTION_IPC_LIBRARY", "ABSTRACTION_IPC_PREFIX")):
        raise SystemExit("usage: python_probe.py EXPECTED_SID EXPECTED_PROGRAM (no endpoint override)")

    from abstraction.facade.client import Machine, ResolutionError
    from abstraction.ipc import Library

    library = Library()
    selected = library.select_runtime(timeout=5.0)
    if (selected.principal_kind != 1 or selected.principal != sys.argv[1]
            or os.path.normcase(selected.program) != os.path.normcase(sys.argv[2])):
        raise RuntimeError("installed selection did not name the expected Windows account and program")
    try:
        editor = Machine(library=library, timeout=10.0).resolve_config_editor()
    except ResolutionError as error:
        if error.status == "runtime_unavailable":
            raise RuntimeError("typed runtime_unavailable during default config discovery") from error
        raise
    snapshot = editor.read_user()
    if not snapshot.revision:
        raise RuntimeError("config ReadUser returned no revision")
    print("PASS Python installed selection, default discovery and config ReadUser")


if __name__ == "__main__":
    main()
