#!/usr/bin/env python3
"""Build and check an exact-source OA pure Python wheel, without network access."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import fnmatch
import hashlib
import io
from pathlib import Path
import re
import tomllib
import zipfile


DIST = re.compile(r"abstraction-[a-z0-9-]+\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def metadata(source: Path, license_file: Path, release_version: str | None = None) -> tuple[str, str, dict[str, bytes]]:
    if release_version is not None and not VERSION.fullmatch(release_version):
        raise ValueError("pure wheel release version must be X.Y.Z")
    if source.is_symlink() or license_file.is_symlink() or not license_file.is_file():
        raise ValueError("pure wheel input is a link or missing license")
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError("pure wheel source contains a link: " + path.as_posix())
    document = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))
    project = document["project"]
    name, version = project["name"], project["version"]
    if not isinstance(name, str) or not DIST.fullmatch(name) or version != "0.0.0":
        raise ValueError("pure wheel source has an unreviewed distribution or version")
    packages = {path.relative_to(source).as_posix(): path.read_bytes()
                for path in (source / "abstraction").rglob("*.py") if path.is_file()}
    find = document.get('tool', {}).get('setuptools', {}).get('packages', {}).get('find', {})
    include, exclude = find.get('include', []), find.get('exclude', [])
    if any(not isinstance(patterns, list) or any(not isinstance(p, str) for p in patterns)
           for patterns in (include, exclude)):
        raise ValueError('pure wheel package discovery patterns are invalid')
    extra_directories = set()
    for path in source.rglob('*.py'):
        parts = path.relative_to(source).parts
        if len(parts) < 2 or parts[0] == 'abstraction' or not all(part.isidentifier() for part in parts[:-1]):
            continue
        package = '.'.join(parts[:-1])
        if (any(fnmatch.fnmatchcase(package, p) for p in include)
                and not any(fnmatch.fnmatchcase(package, p) for p in exclude)):
            packages[path.relative_to(source).as_posix()] = path.read_bytes()
            extra_directories.add(path.parent)
    modules = document.get('tool', {}).get('setuptools', {}).get('py-modules', [])
    if (not isinstance(modules, list) or
            any(not isinstance(module, str) or not re.fullmatch(r'abstraction_[a-z0-9_]+', module) for module in modules) or
            len(modules) != len(set(modules))):
        raise ValueError('pure wheel has invalid declared Python modules')
    for module in modules:
        path = source / (module + '.py')
        if not path.is_file():
            raise ValueError('pure wheel declared Python module is missing: ' + module)
        packages[path.name] = path.read_bytes()
    if not packages:
        raise ValueError("pure wheel source has no abstraction package or declared module")
    # Package discovery selects runtime payload; nonselected fixture folders
    # remain outside the wheel, including appmodel/testdata.
    data = list((source / "abstraction").rglob("*"))
    data.extend(path for directory in extra_directories for path in directory.iterdir())
    for path in data:
        if path.is_file() and path.name != "pyproject.toml" and path.suffix not in (".py", ".md"):
            raise ValueError("pure wheel source has unlisted package data: " + path.as_posix())
    version = release_version if release_version is not None else version
    def dependency_version(dependency, extra=None):
        if release_version is None:
            return dependency + (f'; extra == "{extra}"' if extra else '')
        parts = dependency.split(';')
        match = re.fullmatch(r'(abstraction-[a-z0-9]+(?:-[a-z0-9]+)*(?:\[[a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*\])?)(\s*==\s*0\.0\.0)?', parts[0].strip())
        if len(parts) > 2 or not match:
            raise ValueError('pure wheel has an ambiguous release dependency')
        marker = parts[1].strip() if len(parts) == 2 else ''
        if len(parts) == 2:
            try:
                tree = ast.parse(marker, mode='eval')
            except SyntaxError as error:
                raise ValueError('pure wheel has an invalid dependency marker') from error
            allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Name, ast.Load,
                       ast.Constant, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn)
            variables = {'python_version', 'python_full_version', 'os_name', 'sys_platform',
                         'platform_release', 'platform_system', 'platform_version', 'platform_machine',
                         'platform_python_implementation', 'implementation_name', 'implementation_version', 'extra'}
            if any(not isinstance(node, allowed) or isinstance(node, ast.Name) and node.id not in variables
                   or isinstance(node, ast.Constant) and not isinstance(node.value, str) for node in ast.walk(tree)):
                raise ValueError('pure wheel has an invalid dependency marker')
            if not isinstance(tree.body, (ast.Compare, ast.BoolOp)) or any(
                    isinstance(node, ast.BoolOp) and any(not isinstance(value, (ast.Compare, ast.BoolOp)) for value in node.values)
                    or isinstance(node, ast.Compare) and (len(node.ops) != 1 or
                    {type(node.left), type(node.comparators[0])} != {ast.Name, ast.Constant})
                    for node in ast.walk(tree)):
                raise ValueError('pure wheel has an ambiguous dependency marker')
        requirement = match[1] + ('==' + release_version if match[2] else '')
        if extra:
            marker = '(' + marker + ') and ' if marker else ''
            marker += f'extra == "{extra}"'
        return requirement + ('; ' + marker if marker else '')
    dist_info = name.replace("-", "_") + "-" + version + ".dist-info"
    lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}",
             f"Summary: {project.get('description', '')}",
             f"Requires-Python: {project['requires-python']}", "License-File: LICENSE"]
    for dependency in project.get("dependencies", []):
        if not isinstance(dependency, str) or not dependency.startswith("abstraction-"):
            raise ValueError("pure wheel has an unreviewed dependency")
        lines.append("Requires-Dist: " + dependency_version(dependency))
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
            lines.append('Requires-Dist: ' + dependency_version(dependency, extra))
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


def build(source: Path, license_file: Path, output: Path, version: str | None = None) -> Path:
    name, version, files = metadata(source, license_file, version)
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    if target.exists():
        raise FileExistsError(target)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    check(target, version)
    return target


def check(path: Path, version: str | None = None) -> None:
    version = '0.0.0' if version is None else version
    if version is not None and not VERSION.fullmatch(version):
        raise ValueError("pure wheel release version must be X.Y.Z")
    match = re.fullmatch(r"(abstraction_[a-z0-9_]+)-([0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl", path.name)
    if not match:
        raise ValueError("unreviewed pure wheel filename")
    if not VERSION.fullmatch(match[2]) or version is not None and match[2] != version:
        raise ValueError("pure wheel filename differs from release version")
    dist_info = match[1] + "-" + match[2] + ".dist-info"
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError("duplicate or corrupt pure wheel member")
        if not any((name.startswith("abstraction/") or re.fullmatch(r'abstraction_[a-z0-9_]+\.py', name))
                   and name.endswith(".py") for name in names):
            raise ValueError("pure wheel has no Python package")
        wheel = archive.read(dist_info + "/WHEEL").decode()
        metadata = archive.read(dist_info + "/METADATA").decode()
        if ("Tag: py3-none-any\n" not in wheel or f"Name: {match[1].replace('_', '-')}\n" not in metadata
                or [line for line in metadata.splitlines() if line.startswith('Version: ')] != ['Version: ' + match[2]]):
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
    parser.add_argument("--version", help="explicit release version; omitted preserves legacy source version")
    args = parser.parse_args()
    if args.check:
        if args.source or args.license or args.output:
            parser.error("--check cannot be combined with build inputs")
        check(args.check, args.version)
    elif args.source and args.license and args.output:
        print(build(args.source, args.license, args.output, args.version))
    else:
        parser.error("build requires --source, --license and --output")


if __name__ == "__main__":
    main()
