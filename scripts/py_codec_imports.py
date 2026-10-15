"""Import every generated OA codec of a Python wheel set installed together, offline.

A generated client (_codec.py) reads types off the codecs of the packages it
requires when it is imported: abstraction.asks names
abstraction.rights.api._codec.PermissionSelection. A packed package whose
dependency lacks such a type installs and then fails on import, which 0.4.0
found only in the private workspace. With --wheels this installs every
wheel in DIR into one temporary directory with `pip install --no-index`,
resolving each wheel's requirements among those wheels alone, and imports
every _codec module the set installed, in an isolated interpreter that sees
only that directory. redist's candidate workflow runs it on the wheel set it
builds from pypi.tsv (python job); scripts/python_roster.py uses the same
import against the private sources.

  python3 scripts/py_codec_imports.py --wheels DIR    install DIR/*.whl together and import their codecs
  python3 scripts/py_codec_imports.py --help          this text
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

# Runs in an isolated interpreter (-I): only the directories it is given import.
CODEC_IMPORT = ("import importlib, os, sys\n"
                "sys.path[:0] = sys.argv[1].split(os.pathsep)\n"
                "for name in sys.argv[2:]:\n"
                "    importlib.import_module(name)\n")


def codec_modules(directory):
    """Dotted names of the _codec.py modules under directory (a package source or site directory)."""
    directory = Path(directory)
    return sorted(".".join(path.relative_to(directory).with_suffix("").parts)
                  for path in directory.rglob("_codec.py")
                  if "build" not in path.relative_to(directory).parts and path.relative_to(directory).parts[0] == "abstraction")


def import_codecs(path, modules):
    """None when every module imports with only path (a list of directories) on sys.path; else the last error line."""
    # -B: an import of package source writes no __pycache__ into it.
    result = subprocess.run([sys.executable, "-I", "-B", "-c", CODEC_IMPORT, os.pathsep.join(map(str, path)), *modules],
                            capture_output=True, text=True)
    if result.returncode:
        return (result.stderr.strip().splitlines() or ["exit %d" % result.returncode])[-1]
    return None


def wheel_set_findings(wheels):
    """Install every wheel in the directory together, offline, and import every codec it installed."""
    files = sorted(Path(wheels).glob("*.whl"))
    if not files:
        return ["no wheels in " + str(wheels)]
    with tempfile.TemporaryDirectory(prefix="py-codec-imports-") as tmp:
        target = Path(tmp) / "site"
        result = subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-index",
                                 "--no-compile", "--find-links", str(wheels), "--target", str(target),
                                 *map(str, files)], capture_output=True, text=True)
        if result.returncode:
            reason = (result.stderr.strip().splitlines() or ["exit %d" % result.returncode])[-1]
            return ["the wheel set does not install together from %s alone: %s" % (wheels, reason)]
        modules = codec_modules(target)
        if not modules:
            return ["the wheel set installed no generated codec"]
        reason = import_codecs([target], modules)
        if reason:
            return ["the wheel set's codecs do not import together: " + reason]
        print("imported %d codecs from %d wheels" % (len(modules), len(files)))
    return []


def main(argv):
    if any(a in ("-h", "--help") for a in argv):
        print(__doc__.strip())
        return 0
    if len(argv) != 2 or argv[0] != "--wheels":
        print("py_codec_imports.py takes --wheels DIR; --help explains it", file=sys.stderr)
        return 2
    problems = wheel_set_findings(argv[1])
    for line in problems:
        print("FAIL  " + line)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
