#!/usr/bin/env python3
"""Assemble the platform package and pack every OpenAbstractions npm tarball.

A JavaScript adopter's native client ships inside its npm package (VISION.md,
2026-09-22). `@openabstractions/ipc` declares one optional dependency per
qualified platform; each platform package carries the shared C ABI library and
the Node addon built on that platform, at the runtime's version. This script
assembles that package from a built library and addon, then packs it beside
`@openabstractions/ipc`, `@openabstractions/facade`,
`@openabstractions/inference` and `@openabstractions/opencode`.

No arguments prints this help. Nothing here reaches the network, and nothing
here publishes: `npm publish` needs the owner's organization and consent.

  py scripts/npm_packages.py --version 0.2.0 --output DIR \\
      --library <built shared library> --addon <built oa_ipc_node.node>

Versions come from --version alone. The package.json files in source keep
0.0.0, and every @openabstractions dependency of a packed package is rewritten
to the packed version. A tarball missing a file its package.json names is
refused by name.
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

ROOT = Path(__file__).resolve().parent.parent
ADDON_FILE = "oa_ipc_node.node"
# npm's own version grammar, restricted to the releases this project produces.
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")
SOURCES = {
    "ipc": "openabstractions-flat/abstraction-identity/javascript",
    "facade": "openabstractions-flat/abstraction-facade/javascript",
    "inference": "openabstractions-flat/abstraction-inference/javascript",
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


def required_entries(directory):
    """Every path a tarball must carry: package.json, LICENSE, README and each `files` entry."""
    data = read_package(directory)
    required = ["package.json", "LICENSE"]
    if (directory / "README.md").exists():
        required.append("README.md")
    for entry in data.get("files", []):
        if (directory / entry).is_dir():
            required.append(entry.rstrip("/") + "/")
        elif (directory / entry).exists():
            required.append(entry)
        else:
            raise Refused(f"{data['name']}: package.json names {entry}, which the staged package does not have")
    return data["name"], required


def pack(directory, output):
    """npm pack one staged package; returns the tarball path."""
    result = subprocess.run(["npm", "pack", "--json", "--pack-destination", str(output)],
                            cwd=directory, capture_output=True, text=True,
                            shell=os.name == "nt")
    if result.returncode != 0:
        raise Refused(f"npm pack in {directory}: {result.stderr.strip() or result.stdout.strip()}")
    return output / json.loads(result.stdout)[0]["filename"]


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
    table = platform_libraries(sources["ipc"])
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
                   for name in ("ipc", "facade", "inference", "opencode")]
        for directory in staged:
            name, required = required_entries(directory)
            tarball = pack(directory, output)
            packed.append((name, tarball, verify(name, tarball, required)))

    for name, tarball, carried in packed:
        print(f"\n{name} {args.version}")
        print(f"  {tarball.name}  {tarball.stat().st_size} bytes  sha256 {digest(tarball)}")
        for path in carried:
            print(f"    {path}")
    print(f"\n{len(packed)} tarballs in {output}. Nothing was published.")
    return 0


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
