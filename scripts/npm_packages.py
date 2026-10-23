#!/usr/bin/env python3
"""Assemble the platform package and pack every OpenAbstractions npm tarball.

A JavaScript adopter's native client ships inside its npm package (VISION.md,
2026-09-22). `@openabstractions/ipc` declares one optional dependency per
qualified platform; each platform package carries the shared C ABI library and
the Node addon built on that platform, at the runtime's version. This script
assembles that package from a built library and addon, then packs it beside
`@openabstractions/ipc`, `@openabstractions/facade`,
`@openabstractions/inference`, `@openabstractions/asks`, `@openabstractions/logging`, `@openabstractions/rights`,
`@openabstractions/router`,
`@openabstractions/storage-content` and `@openabstractions/opencode`.

No arguments prints this help. Nothing here reaches the network, and nothing
here publishes: `npm publish` needs the owner's organization and consent.

  py scripts/npm_packages.py --version 0.2.0 --output DIR \\
      --library <built shared library> --addon <built oa_ipc_node.node>

Versions come from --version alone. The package.json files in source keep
0.0.0, and every @openabstractions dependency of a packed package is rewritten
to the packed version. A tarball missing a file its package.json names is
refused by name. A package with a package-lock.json (the OpenCode adopter)
gets npm-shrinkwrap.json from its own shrinkwrap.js before packing; npm pack
runs with --ignore-scripts, and the packed shrinkwrap must name the packed
version and exactly the lock's packages. The closing lines print the registry
checks to run after the owner publishes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from windows_native import NativeDependencyError, validate_portable_windows_dll

ROOT = Path(__file__).resolve().parent.parent
ADDON_FILE = "oa_ipc_node.node"
# npm's own version grammar, restricted to the releases this project produces.
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")
SOURCES = {
    "ipc": "openabstractions-flat/abstraction-identity/javascript",
    "facade": "openabstractions-flat/abstraction-facade/javascript",
    "inference": "openabstractions-flat/abstraction-inference/javascript",
    "asks": "openabstractions-flat/abstraction-asks/javascript",
    "logging": "openabstractions-flat/abstraction-logging/javascript",
    "rights": "openabstractions-flat/abstraction-rights/javascript",
    "router": "openabstractions-flat/abstraction-router/javascript",
    "storage": "openabstractions-flat/abstraction-storage/javascript",
    "opencode": "adopters/opencode",
}
PLATFORM_README = """# OpenAbstractions native IPC client for {identity}

The shared C ABI library and the Node addon `@openabstractions/ipc` loads on
{identity}. It is an optional dependency of that package and has no API of its
own: `@openabstractions/ipc` resolves `{library}` and `{addon}` from here.

The client library is the application's own code. It decides which runtime the
application trusts, and that decision does not come from the installation being
judged, so it ships with the client rather than with the runtime.

This package carries binaries built on {identity} at version {version}. A
platform without hardware qualification has no package.
"""


class Refused(Exception):
    """A condition the caller must fix; printed without a traceback."""


def platform_libraries(ipc):
    """The platform table the connectors resolve against, read from their platform.js."""
    table_file = ipc / "platform.js"
    body = re.search(r"platformLibraries\s*=\s*Object\.freeze\(\{(.*?)\}\)",
                     table_file.read_text(encoding="utf-8"), re.S)
    if body is None:
        raise Refused(f"{table_file} no longer declares platformLibraries")
    table = dict(re.findall(r"'([^']+)'\s*:\s*'([^']+)'", body.group(1)))
    if not table:
        raise Refused(f"{table_file} declares no qualified platform")
    return table


def host_platform():
    """This host's platform identity, in the connectors' os-cpu spelling."""
    system = {"win32": "win32", "linux": "linux", "darwin": "darwin"}.get(sys.platform)
    machine = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}
    import platform as host
    return f"{system}-{machine.get(host.machine().lower(), host.machine().lower())}"


def read_package(directory):
    return json.loads((directory / "package.json").read_text(encoding="utf-8"))


def package_roster(manifest):
    """Package names pinned by the release source manifest."""
    packages = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.startswith("@openabstractions/"):
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            raise Refused(f"{manifest}: malformed package row: {line}")
        packages.append(fields[0])
    if len(packages) != len(set(packages)):
        raise Refused(f"{manifest}: duplicate JavaScript package row")
    return set(packages)


def validate_package_closure(packages, generated_packages=()):
    """Every OA dependency of a packed package is present in this pack set."""
    names = {data["name"] for data in packages.values()}
    generated = set(generated_packages)
    for data in packages.values():
        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            for dependency in data.get(field, {}):
                if (dependency.startswith("@openabstractions/")
                        and dependency not in names and dependency not in generated):
                    raise Refused(f"{data['name']} declares {dependency}, which is absent from the packed package set")
    return names


def validate_source_roster(packages, manifest, generated_packages=()):
    """The published source manifest must pin every package the assembler packs."""
    packed = validate_package_closure(packages, generated_packages)
    pinned = package_roster(manifest)
    missing = sorted(packed - pinned)
    extra = sorted(pinned - packed)
    if missing or extra:
        details = []
        if missing:
            details.append("missing rows: " + ", ".join(missing))
        if extra:
            details.append("rows not assembled here: " + ", ".join(extra))
        raise Refused(f"{manifest}: JavaScript source roster mismatch ({'; '.join(details)})")


def write_package(directory, data):
    (directory / "package.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")


def repinned(data, version):
    """The same package at one version, with its @openabstractions requirements repinned."""
    data = dict(data)
    data["version"] = version
    for field in ("dependencies", "optionalDependencies", "peerDependencies"):
        if field in data:
            data[field] = {name: (version if name.startswith("@openabstractions/") else requirement)
                           for name, requirement in data[field].items()}
    return data


def assemble_platform(stage, identity, library_file, library, addon, version, license_file, homepage):
    """The platform package directory: its metadata, the two binaries, README and LICENSE."""
    directory = stage / f"ipc-{identity}"
    directory.mkdir(parents=True)
    system, cpu = identity.split("-", 1)
    write_package(directory, {
        "name": f"@openabstractions/ipc-{identity}",
        "version": version,
        "description": f"The OpenAbstractions shared C ABI library and Node addon for {identity}.",
        "license": "Apache-2.0",
        "repository": {"type": "git", "url": "git+https://github.com/openabstractions/abstraction-identity.git",
                       "directory": "javascript"},
        "homepage": homepage,
        "bugs": {"url": "https://github.com/openabstractions/abstraction-identity/issues"},
        "os": [system],
        "cpu": [cpu],
        "files": [library_file, ADDON_FILE, "README.md"],
        "engines": {"node": ">=18"},
    })
    shutil.copyfile(library, directory / library_file)
    shutil.copyfile(addon, directory / ADDON_FILE)
    (directory / "README.md").write_text(
        PLATFORM_README.format(identity=identity, library=library_file, addon=ADDON_FILE, version=version),
        encoding="utf-8", newline="\n")
    shutil.copyfile(license_file, directory / "LICENSE")
    return directory


def stage_source(stage, name, source, version, license_file):
    """One published package, copied out of source at the packed version."""
    directory = stage / name
    shutil.copytree(source, directory, ignore=shutil.ignore_patterns("test", "node_modules", "*.tgz"))
    write_package(directory, repinned(read_package(directory), version))
    shutil.copyfile(license_file, directory / "LICENSE")
    return directory


def write_shrinkwrap(directory):
    """npm-shrinkwrap.json in a staged package that has a lock, written by its own shrinkwrap.js.

    npm never packs a package-lock.json and ignores one inside a dependency, so a
    published package pins its third-party closure only as npm-shrinkwrap.json.
    The generator refuses a lock entry without sha512 integrity. Returns True when
    the package carries a shrinkwrap."""
    if not (directory / "package-lock.json").is_file():
        return False
    if not (directory / "shrinkwrap.js").is_file():
        raise Refused(f"{read_package(directory)['name']} has a package-lock.json and no shrinkwrap.js to publish it")
    result = subprocess.run(["node", "shrinkwrap.js"], cwd=directory, capture_output=True, text=True)
    if result.returncode != 0:
        raise Refused(f"{read_package(directory)['name']}: {result.stderr.strip() or result.stdout.strip()}")
    return True


def verify_shrinkwrap(name, tarball, directory):
    """The packed npm-shrinkwrap.json names the packed version and exactly the staged lock's packages."""
    data = read_package(directory)
    lock = json.loads((directory / "package-lock.json").read_text(encoding="utf-8"))
    with tarfile.open(tarball, "r:gz") as archive:
        try:
            member = archive.extractfile("package/npm-shrinkwrap.json")
        except KeyError:
            member = None
        if member is None:
            raise Refused(f"{name}: {tarball.name} carries no npm-shrinkwrap.json")
        wrap = json.load(member)
    if wrap.get("version") != data["version"] or wrap.get("packages", {}).get("", {}).get("version") != data["version"]:
        raise Refused(f"{name}: npm-shrinkwrap.json names version {wrap.get('version')}, the package {data['version']}")
    packed = {key: value for key, value in wrap.get("packages", {}).items() if key}
    locked = {key: value for key, value in lock.get("packages", {}).items() if key}
    if packed != locked:
        differ = sorted(set(packed) ^ set(locked)) or sorted(k for k in packed if packed[k] != locked[k])
        raise Refused(f"{name}: npm-shrinkwrap.json differs from package-lock.json at " + ", ".join(differ[:5]))


def required_entries(directory):
    """Every path a tarball must carry: package.json, LICENSE, README and each `files` entry."""
    data = read_package(directory)
    required = ["package.json", "LICENSE"]
    if (directory / "README.md").exists():
        required.append("README.md")
    excluded = set()
    for entry in data.get("files", []):
        unsupported = _unsupported_files_syntax(entry)
        if unsupported:
            raise Refused(f"{data['name']}: package.json files entry {entry} uses {unsupported}, which npm_packages does not expand")
    for entry in data.get("files", []):
        if entry.startswith("!"):
            # npm: a negated entry removes the files it matches from the package.
            excluded.update(_files_entry_matches(directory, entry[1:]))
    for entry in data.get("files", []):
        if entry.startswith("!"):
            continue
        matches = [path for path in _files_entry_matches(directory, entry) if path not in excluded]
        if not matches:
            raise Refused(f"{data['name']}: package.json names {entry}, which the staged package does not have")
        if any(ch in entry for ch in "*?["):
            required.extend(matches)
        elif (directory / _files_entry_pattern(entry)).is_dir():
            required.append(_files_entry_pattern(entry) + "/")
        else:
            required.append(_files_entry_pattern(entry))
    return data["name"], required


def _files_entry_pattern(entry):
    """npm anchors a leading "/" and strips a leading "./" at the package root; a dotfile keeps its name."""
    pattern = entry.strip()
    while pattern.startswith("./") or pattern.startswith("/"):
        pattern = pattern[2:] if pattern.startswith("./") else pattern[1:]
    return pattern.rstrip("/")


_UNSUPPORTED_FILES_SYNTAX = (("{", "a brace pattern"), ("?(", "an extglob"), ("*(", "an extglob"),
                             ("+(", "an extglob"), ("@(", "an extglob"), ("!(", "an extglob"),
                             ("[^", "a negated class"), ("\\", "an escape"))


def _unsupported_files_syntax(entry):
    """The minimatch syntax a files entry uses that _files_entry_matches does not implement, or None."""
    body = entry[1:] if entry.startswith("!") else entry
    for token, name in _UNSUPPORTED_FILES_SYNTAX:
        if token in body:
            return name
    return None


def _files_entry_matches(directory, entry):
    """Files one package.json `files` entry selects, as npm does: a glob matches files, a directory its contents."""
    pattern = _files_entry_pattern(entry)
    found = set()
    for path in directory.glob(pattern):
        if path.is_dir():
            found.update(p.relative_to(directory).as_posix() for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            found.add(path.relative_to(directory).as_posix())
    return sorted(found)


def pack(directory, output):
    """npm pack one staged package without lifecycle scripts; returns the tarball path."""
    result = subprocess.run(["npm", "pack", "--json", "--ignore-scripts", "--pack-destination", str(output)],
                            cwd=directory, capture_output=True, text=True,
                            shell=os.name == "nt")
    if result.returncode != 0:
        raise Refused(f"npm pack in {directory}: {result.stderr.strip() or result.stdout.strip()}")
    return output / json.loads(result.stdout)[0]["filename"]


def test_opencode_package(directory):
    """Check the declared dependency and server-hook contract before offline packing."""
    smoke = subprocess.run(
        ["node", "--input-type=module", "-e",
         """const {tool}=await import('@opencode-ai/plugin');
if(typeof tool!=='function'||typeof tool.schema?.object!=='function') process.exit(1);
const {default:{server:plugin}}=await import('@openabstractions/opencode/server');
const hooks=await plugin({client:{app:{log:async()=>{}}}}, {tools:{selection_policy:true}});
if(typeof hooks.config!=='function'||typeof hooks.tool.openabstractions_selection_policy.execute!=='function') process.exit(2);"""],
        cwd=directory, capture_output=True, text=True,
    )
    if smoke.returncode != 0:
        details = smoke.stderr.strip() or smoke.stdout.strip()
        raise Refused(f"OpenCode adopter declared dependency smoke failed in {directory}: {details}")


def contents(tarball):
    with tarfile.open(tarball, "r:gz") as archive:
        return sorted(member.name for member in archive.getmembers() if member.isfile())


def verify(name, tarball, required):
    """Refuse a tarball that misses a required file, and return its listing."""
    carried = contents(tarball)
    inside = {path[len("package/"):] for path in carried if path.startswith("package/")}
    for entry in required:
        if entry.endswith("/"):
            if not any(path.startswith(entry) for path in inside):
                raise Refused(f"{name}: {tarball.name} carries nothing under {entry}")
        elif entry not in inside:
            raise Refused(f"{name}: {tarball.name} is missing {entry}")
    return carried


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def run(args):
    if not VERSION.match(args.version):
        raise Refused("--version must be MAJOR.MINOR.PATCH with an optional prerelease suffix")
    sources = {name: Path(getattr(args, name) or ROOT / path).resolve()
               for name, path in SOURCES.items()}
    for name, path in sources.items():
        if not (path / "package.json").is_file():
            raise Refused(f"no {name} package at {path}")
    manifest = Path(args.npm_manifest).resolve() if args.npm_manifest else next(
        (path for path in (ROOT / "npm.tsv", ROOT / "research/org-edits/redist/npm.tsv") if path.is_file()),
        ROOT / "npm.tsv",
    )
    package_data = {name: read_package(path) for name, path in sources.items()}
    table = platform_libraries(sources["ipc"])
    generated_packages = {f"@openabstractions/ipc-{identity}" for identity in table}
    validate_source_roster(package_data, manifest, generated_packages)
    test_opencode_package(sources["opencode"])
    identity = args.platform or host_platform()
    if identity not in table:
        raise Refused(f"{identity} has no qualified platform package; "
                      "the connectors name " + ", ".join(sorted(table)))
    library, addon = Path(args.library).resolve(), Path(args.addon).resolve()
    for label, path in (("--library", library), ("--addon", addon)):
        if not path.is_file():
            raise Refused(f"{label} must name an existing file: {path}")
    if addon.name != ADDON_FILE:
        raise Refused(f"--addon must be the built {ADDON_FILE}, not {addon.name}")
    if identity.startswith("win32-"):
        try:
            validate_portable_windows_dll(library, identity)
        except NativeDependencyError as exc:
            raise Refused(str(exc)) from exc
    license_file = Path(args.license or ROOT / "LICENSE").resolve()
    if not license_file.is_file():
        raise Refused(f"--license must name an existing file: {license_file}")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    packed = []
    with tempfile.TemporaryDirectory(prefix="oa-npm-") as temporary:
        stage = Path(temporary)
        homepage = read_package(sources["ipc"])["homepage"]
        staged = [assemble_platform(stage, identity, table[identity], library, addon,
                                    args.version, license_file, homepage)]
        staged += [stage_source(stage, name, sources[name], args.version, license_file)
                   for name in SOURCES]
        shrinkwrapped = []
        for directory in staged:
            wrapped = write_shrinkwrap(directory)
            name, required = required_entries(directory)
            tarball = pack(directory, output)
            packed.append((name, tarball, verify(name, tarball, required)))
            if wrapped:
                verify_shrinkwrap(name, tarball, directory)
                shrinkwrapped.append(name)

    expected = {data["name"] for data in package_data.values()} | {f"@openabstractions/ipc-{identity}"}
    actual = [name for name, _, _ in packed]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise Refused("packed package roster differs from the pinned source packages and selected IPC platform")

    for name, tarball, carried in packed:
        print(f"\n{name} {args.version}")
        print(f"  {tarball.name}  {tarball.stat().st_size} bytes  sha256 {digest(tarball)}")
        for path in carried:
            print(f"    {path}")
    print(f"\n{len(packed)} tarballs in {output}. Nothing was published.")
    print(post_publication_checks(shrinkwrapped, args.version))
    return 0


def post_publication_checks(shrinkwrapped, version):
    """The checks to run against the registry once the owner has published these tarballs."""
    lines = ["After publication, each of these must print true:"]
    lines += [f"  npm view {name}@{version} _hasShrinkwrap" for name in shrinkwrapped]
    return "\n".join(lines) if shrinkwrapped else "After publication: no package carries a shrinkwrap to check."


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", metavar="X.Y.Z", help="the version every packed package carries")
    p.add_argument("--output", metavar="DIR", help="directory receiving the tarballs")
    p.add_argument("--library", metavar="PATH", help="the built shared C ABI library for this platform")
    p.add_argument("--addon", metavar="PATH", help=f"the built {ADDON_FILE} for this platform")
    p.add_argument("--platform", metavar="OS-CPU",
                   help="the platform package to assemble; default: this host")
    # A release job builds from separate repository checkouts rather than this
    # tree's layout. One script serves both routes, so it names its sources.
    for name, path in SOURCES.items():
        p.add_argument(f"--{name}", metavar="DIR", help=f"the {name} package directory; default: {path}")
    p.add_argument("--npm-manifest", metavar="FILE",
                   help="the source pin manifest; default: npm.tsv in the release checkout or its private source path")
    p.add_argument("--license", metavar="FILE", help="the licence copied into every package; default: LICENSE")
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if not (args.version and args.output and args.library and args.addon):
        p.print_help()
        return 0
    return run(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refused as refusal:
        print(f"REFUSED {refusal}", file=sys.stderr)
        sys.exit(2)
