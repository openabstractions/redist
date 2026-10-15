#!/usr/bin/env python3
"""Build and check an exact-source OA pure Python wheel, without network access."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
from pathlib import Path
import re
import tomllib
import zipfile


DIST = re.compile(r"abstraction-[a-z0-9-]+\Z")
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def metadata(source: Path, license_file: Path) -> tuple[str, str, dict[str, bytes]]:
    if source.is_symlink() or license_file.is_symlink() or not license_file.is_file():
        raise ValueError("pure wheel input is a link or missing license")
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError("pure wheel source contains a link: " + path.as_posix())
    project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    name, version = project["name"], project["version"]
    if not isinstance(name, str) or not DIST.fullmatch(name) or version != "0.0.0":
        raise ValueError("pure wheel source has an unreviewed distribution or version")
    packages = {path.relative_to(source).as_posix(): path.read_bytes()
                for path in (source / "abstraction").rglob("*.py") if path.is_file()}
    if not packages or not all(path.startswith("abstraction/") for path in packages):
        raise ValueError("pure wheel source has no abstraction package")
    for path in source.rglob("*"):
        if path.is_file() and path.name != "pyproject.toml" and path.suffix not in (".py", ".md"):
            raise ValueError("pure wheel source has unlisted package data: " + path.as_posix())
    dist_info = name.replace("-", "_") + "-0.0.0.dist-info"
    lines = ["Metadata-Version: 2.1", f"Name: {name}", "Version: 0.0.0",
             f"Summary: {project.get('description', '')}",
             f"Requires-Python: {project['requires-python']}", "License-File: LICENSE"]
    for dependency in project.get("dependencies", []):
        if not isinstance(dependency, str) or not dependency.startswith("abstraction-"):
            raise ValueError("pure wheel has an unreviewed dependency")
        lines.append("Requires-Dist: " + dependency)
    extras = project.get("optional-dependencies", {})
    if not isinstance(extras, dict):
        raise ValueError("pure wheel optional dependencies are invalid")
    for extra, dependencies in sorted(extras.items()):
        if not re.fullmatch(r"[a-z][a-z0-9-]*", extra) or not isinstance(dependencies, list):
            raise ValueError("pure wheel has an unreviewed extra")
        lines.append("Provides-Extra: " + extra)
        for dependency in dependencies:
            if not isinstance(dependency, str) or not dependency.startswith("abstraction-"):
                raise ValueError("pure wheel has an unreviewed optional dependency")
            lines.append(f'Requires-Dist: {dependency}; extra == "{extra}"')
    packages[f"{dist_info}/METADATA"] = ("\n".join(lines) + "\n").encode()
    packages[f"{dist_info}/WHEEL"] = (
        "Wheel-Version: 1.0\nGenerator: py_pure_wheels\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    ).encode()
    packages[f"{dist_info}/LICENSE"] = license_file.read_bytes()
    if not packages[f"{dist_info}/LICENSE"]:
        raise ValueError("pure wheel has an empty license")
    rows = [[path, record_hash(data), str(len(data))] for path, data in sorted(packages.items())]
    rows.append([f"{dist_info}/RECORD", "", ""])
    stream = io.StringIO()
    csv.writer(stream, lineterminator="\n").writerows(rows)
    packages[f"{dist_info}/RECORD"] = stream.getvalue().encode()
    return name, version, packages


def build(source: Path, license_file: Path, output: Path) -> Path:
    name, version, files = metadata(source, license_file)
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    if target.exists():
        raise FileExistsError(target)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    check(target)
    return target


def check(path: Path) -> None:
    match = re.fullmatch(r"(abstraction_[a-z0-9_]+)-0\.0\.0-py3-none-any\.whl", path.name)
    if not match:
        raise ValueError("unreviewed pure wheel filename")
    dist_info = match[1] + "-0.0.0.dist-info"
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError("duplicate or corrupt pure wheel member")
        if not any(name.startswith("abstraction/") and name.endswith(".py") for name in names):
            raise ValueError("pure wheel has no Python package")
        wheel = archive.read(dist_info + "/WHEEL").decode()
        metadata = archive.read(dist_info + "/METADATA").decode()
        if "Tag: py3-none-any\n" not in wheel or f"Name: {match[1].replace('_', '-')}\n" not in metadata:
            raise ValueError("pure wheel metadata differs from filename")
        records = list(csv.reader(io.StringIO(archive.read(dist_info + "/RECORD").decode())))
        if len(records) != len(names) or {row[0] for row in records} != set(names):
            raise ValueError("pure wheel RECORD file set differs")
        for name, digest, size in records:
            if name == dist_info + "/RECORD":
                if digest or size:
                    raise ValueError("pure wheel RECORD self-entry is invalid")
            elif digest != record_hash(archive.read(name)) or size != str(len(archive.read(name))):
                raise ValueError("pure wheel RECORD member differs: " + name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="exact public repository's py/ directory")
    parser.add_argument("--license", type=Path, help="exact public repository's LICENSE")
    parser.add_argument("--output", type=Path, help="wheel output directory")
    parser.add_argument("--check", type=Path, help="verify an existing pure wheel")
    args = parser.parse_args()
    if args.check:
        if args.source or args.license or args.output:
            parser.error("--check cannot be combined with build inputs")
        check(args.check)
    elif args.source and args.license and args.output:
        print(build(args.source, args.license, args.output))
    else:
        parser.error("build requires --source, --license and --output")


if __name__ == "__main__":
    main()
