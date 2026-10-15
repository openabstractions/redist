"""Validate release source rosters and emit exact NUL-delimited shell fields.

Bash treats a tab as whitespace even with IFS set to tab. These rows are
validated before any build and are then read one NUL-terminated field at a
time; an empty or extra TSV column can never shift provenance fields.
"""

import argparse
import csv
from pathlib import Path
import re


HEADERS = {
    "tools.tsv": ("path", "module", "package", "feature", "subsystem"),
    "npm.tsv": ("package", "repository", "commit", "directory"),
    "pypi.tsv": ("package", "repository", "commit", "directory"),
}
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def rows(text: str, name: str) -> list[tuple[str, ...]]:
    if name not in HEADERS:
        raise ValueError("unknown release TSV roster: " + name)
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith(">")]
    parsed = list(csv.reader(lines, delimiter="\t", quoting=csv.QUOTE_NONE, strict=True))
    header = HEADERS[name]
    if not parsed or tuple(parsed[0]) != header or len(parsed) < 2:
        raise ValueError(name + " has an invalid header or empty release roster")
    result = []
    identities = set()
    for fields in parsed[1:]:
        if (len(fields) != len(header) or any(not field or field != field.strip()
                                              or any(character in field for character in "\t\r\n\0\"")
                                              for field in fields)):
            raise ValueError(name + " has an empty, extra or malformed field")
        if fields[0] in identities:
            raise ValueError(name + " has a duplicate row: " + fields[0])
        identities.add(fields[0])
        if name in ("npm.tsv", "pypi.tsv") and not COMMIT.fullmatch(fields[2]):
            raise ValueError(name + " has a non-commit source pin")
        result.append(tuple(fields))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roster", type=Path)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path, help="write exact NUL-delimited columns")
    destination.add_argument("--console-names", action="store_true", help="print tools.tsv console program names")
    args = parser.parse_args(argv)
    parsed = rows(args.roster.read_text(encoding="utf-8"), args.roster.name)
    if args.console_names:
        if args.roster.name != "tools.tsv":
            parser.error("--console-names requires tools.tsv")
        for path, _, _, _, subsystem in parsed:
            if subsystem == "console":
                print(path.removesuffix(".exe"))
        return
    if args.output.exists():
        raise FileExistsError("release TSV output already exists: " + str(args.output))
    args.output.write_bytes(b"".join(field.encode("utf-8") + b"\0" for row in parsed for field in row))


if __name__ == "__main__":
    main()
