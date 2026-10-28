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
import struct
import subprocess
import sys
import tarfile
import tempfile
from windows_native import NativeDependencyError, validate_portable_windows_dll
from file_boundary import extended_path

ROOT = Path(__file__).resolve().parent.parent
ADDON_FILE = "oa_ipc_node.node"
# Source declarations for the client-owned component. Each platform still owes
# its own native artifact and receiving; IPC proof does not qualify AppModel.
FACADE_NATIVE = {
    "prefix": "@openabstractions/facade-native-",
    "addon": "oa_appmodel_node.node",
    "libraries": {"win32-x64": "abstraction_facade_appmodel.dll",
                  "linux-x64": "libabstraction_facade_appmodel.so",
                  "darwin-x64": "libabstraction_facade_appmodel.dylib",
                  "darwin-arm64": "libabstraction_facade_appmodel.dylib"},
    "repository": "openabstractions/abstraction-facade",
    "python": "abstraction-facade-native",
    "python_directory": "py-native",
    "javascript": "@openabstractions/facade",
    "javascript_directory": "javascript",
}
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
    "config": "openabstractions-flat/abstraction-config/javascript",
    "credentials": "openabstractions-flat/abstraction-credentials/javascript",
    "download": "openabstractions-flat/abstraction-download/javascript",
    "job": "openabstractions-flat/abstraction-job/javascript",
    "model": "openabstractions-flat/abstraction-model/javascript",
    "resource": "openabstractions-flat/abstraction-resource/javascript",
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


def generated_package_names(ipc):
    """The native families assembled here rather than pinned as JS sources."""
    return ({f"@openabstractions/ipc-{identity}" for identity in platform_libraries(ipc)}
            | {FACADE_NATIVE["prefix"] + identity for identity in FACADE_NATIVE["libraries"]})


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


def facade_posix_machines(data):
    """Inspect only native format/CPU identity, not deployment or ABI portability."""
    if data.startswith(b'\x7fELF'):
        if (len(data) < 64 or data[4:7] != b'\x02\x01\x01'
                or struct.unpack_from('<HH', data, 16) != (3, 62)):
            raise Refused('facade native ELF is not an x64 shared object')
        return {'linux-x64'}
    cpus = {0x01000007: 'darwin-x64', 0x0100000c: 'darwin-arm64'}
    def thin(blob):
        if len(blob) < 32 or blob[:4] != b'\xcf\xfa\xed\xfe':
            raise Refused('facade native Mach-O header differs')
        cpu, _, kind = struct.unpack_from('<III', blob, 4)
        if cpu not in cpus or kind not in (6, 8):
            raise Refused('facade native Mach-O CPU or shared object kind differs')
        return cpus[cpu]
    if data[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
        if len(data) < 8:
            raise Refused('facade native universal header is truncated')
        count = struct.unpack_from('>I', data, 4)[0]
        wide = data[:4] == b'\xca\xfe\xba\xbf'
        entry_size = 32 if wide else 20
        if not 1 <= count <= 2 or 8 + count * entry_size > len(data):
            raise Refused('facade native universal slice inventory differs')
        machines, ranges = set(), []
        for index in range(count):
            entry = 8 + index * entry_size
            cpu = struct.unpack_from('>I', data, entry)[0]
            offset, size = struct.unpack_from('>QQ' if wide else '>II', data, entry + 8)
            if (offset < 8 + count * entry_size or size < 32 or offset + size > len(data)
                    or any(offset < end and start < offset + size for start, end in ranges)):
                raise Refused('facade native universal slice bounds differ')
            machine = thin(data[offset:offset + size])
            if cpus.get(cpu) != machine or machine in machines:
                raise Refused('facade native universal CPU inventory differs')
            machines.add(machine); ranges.append((offset, offset + size))
        return machines
    return {thin(data)}


def assemble_facade_native(stage, identity, library, addon, version, license_file, homepage):
    """One declared AppModel family, with its direct Node entry and C ABI."""
    library_file = FACADE_NATIVE["libraries"].get(identity)
    if library_file is None:
        raise Refused(f"{identity} has no facade native package declaration")
    for path, expected in ((library, library_file), (addon, FACADE_NATIVE["addon"])):
        if path.name != expected or not path.is_file():
            raise Refused(f"facade native input must be the built {expected}")
    if identity.startswith('win32-'):
        try:
            validate_portable_windows_dll(library, identity)
        except NativeDependencyError as exc:
            raise Refused(str(exc)) from exc
    else:
        library_machines = facade_posix_machines(library.read_bytes())
        addon_machines = facade_posix_machines(addon.read_bytes())
        if identity not in library_machines or library_machines != addon_machines:
            raise Refused('facade native library/addon platform identity differs')
    directory = stage / f"facade-native-{identity}"
    directory.mkdir(parents=True)
    addon_file = FACADE_NATIVE["addon"]
    write_package(directory, {
        "name": FACADE_NATIVE["prefix"] + identity,
        "version": version,
        "description": f"The client-owned OpenAbstractions AppModel native binding for {identity}.",
        "license": "Apache-2.0",
        "repository": {"type": "git", "url": "git+https://github.com/openabstractions/abstraction-facade.git",
                       "directory": "javascript"},
        "homepage": homepage,
        "os": [identity.split("-", 1)[0]],
        "cpu": [identity.split("-", 1)[1]],
        "main": "./" + addon_file,
        "exports": {".": "./" + addon_file, "./package.json": "./package.json",
                    "./" + library_file: "./" + library_file},
        "files": [addon_file, library_file, "README.md"],
        "engines": {"node": ">=18"},
    })
    for path in (library, addon):
        shutil.copyfile(path, directory / path.name)
    shutil.copyfile(license_file, directory / "LICENSE")
    (directory / "README.md").write_text(
        f"# OpenAbstractions AppModel native client for {identity}\n\n"
        f"Optional client-owned native files for @openabstractions/facade at {version}.\n"
        "The addon and shared C ABI library use one implementation. Nothing is built or downloaded on installation.\n",
        encoding="utf-8", newline="\n")
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
        else:
            # Keep the actual archive spelling, including literal entries whose
            # case differs. Use the same case policy for directory recognition.
            folders = [path.relative_to(directory).as_posix() + "/"
                       for path in directory.glob(_files_entry_pattern(entry), case_sensitive=False)
                       if path.is_dir()]
            required.extend(sorted(folders) or matches)
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
    # A leading !(...) is an extglob, rather than an exclusion prefix.
    body = entry[1:] if entry.startswith("!") and not entry.startswith("!(") else entry
    for token, name in _UNSUPPORTED_FILES_SYNTAX:
        if token in body:
            return name
    return None


def _files_entry_matches(directory, entry):
    """Files one package.json `files` entry selects, as npm does: a glob matches files, a directory its contents."""
    pattern = _files_entry_pattern(entry)
    found = set()
    # npm's ignore-walk uses Minimatch nocase:true on every platform.
    for path in directory.glob(pattern, case_sensitive=False):
        if path.is_dir():
            found.update(p.relative_to(directory).as_posix() for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            found.add(path.relative_to(directory).as_posix())
    return sorted(found)


def pack(directory, output, environment=None):
    """npm pack one staged package without lifecycle scripts; returns the tarball path."""
    options = {} if environment is None else {'env':environment}
    result = subprocess.run(["npm", "pack", "--offline", "--json", "--ignore-scripts", "--pack-destination", str(output)],
                            cwd=directory, capture_output=True, text=True,
                            shell=os.name == "nt", **options)
    if result.returncode != 0:
        raise Refused(f"npm pack in {directory}: {result.stderr.strip() or result.stdout.strip()}")
    return output / json.loads(result.stdout)[0]["filename"]


def test_opencode_package(directory, environment=None):
    """Check the declared dependency and server-hook contract before offline packing."""
    smoke = subprocess.run(
        ["node", "--no-global-search-paths", "--input-type=module", "-e",
         """const {tool}=await import('@opencode-ai/plugin');
if(typeof tool!=='function'||typeof tool.schema?.object!=='function') process.exit(1);
const {default:{server:plugin}}=await import('@openabstractions/opencode/server');
const hooks=await plugin({client:{app:{log:async()=>{}}}}, {tools:{selection_policy:true}});
if(typeof hooks.config!=='function'||typeof hooks.tool.openabstractions_selection_policy.execute!=='function') process.exit(2);"""],
        cwd=directory, capture_output=True, text=True, env=environment,
    )
    if smoke.returncode != 0:
        details = smoke.stderr.strip() or smoke.stdout.strip()
        raise Refused(f"OpenCode adopter declared dependency smoke failed in {directory}: {details}")


def contents(tarball):
    with tarfile.open(tarball, "r:gz") as archive:
        return sorted(member.name for member in archive.getmembers() if member.isfile())


def cache_files(cache):
    """Exact regular cache inputs; a linked tree is never copied into receiving."""
    result = {}
    cache = extended_path(cache)
    if not cache.is_dir() or (cache.is_symlink() or cache.is_junction()):
        raise ValueError('dependency cache is absent or linked')
    def refuse(error):
        raise error
    for current, directories, files in os.walk(cache, onerror=refuse):
        for name in directories + files:
            path = Path(current) / name
            if (path.is_symlink() or path.is_junction()):
                raise ValueError('dependency cache contains a link')
        for name in files:
            path = Path(current) / name
            if not path.is_file():
                raise ValueError('dependency cache contains a special file')
            result[path.relative_to(cache).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not result:
        raise ValueError('dependency cache is empty')
    return result


def npm_content_cache(cache, *, environment):
    """Use npm's own configured-cache to pacote-cache projection."""
    npm = Path(shutil.which('npm') or '')
    definitions = npm.parent / 'node_modules/npm/node_modules/@npmcli/config/lib/definitions'
    result = subprocess.run(['node', '-e',
        "console.log(require(process.argv[1]).flatten({cache:process.argv[2]}).cache)",
        str(definitions), str(cache)], env=environment, check=True, capture_output=True, text=True)
    return Path(result.stdout.strip())


def verify_cached_archives(cache, packages, *, environment):
    """npm's own content-addressed cache reader verifies each locked integrity."""
    npm = Path(shutil.which('npm') or '')
    cacache = npm.parent / 'node_modules/npm/node_modules/cacache'
    if not cacache.is_dir():
        raise ValueError('npm content-cache verifier is absent')
    script = """const fs=require('fs');const c=require(process.argv[1]);
const rows=JSON.parse(fs.readFileSync(0,'utf8'));
Promise.all(Object.values(rows).map(x=>c.get.byDigest(process.argv[2],x.integrity))).catch(e=>{console.error(e.message);process.exitCode=1});"""
    effective_cache = npm_content_cache(cache, environment=environment)
    result = subprocess.run(['node', '-e', script, str(cacache), str(effective_cache)],
                            input=json.dumps(packages), text=True, capture_output=True, env=environment)
    if result.returncode:
        raise ValueError('locked dependency cache is incomplete or corrupt: ' + result.stderr.strip())


def copy_dependency_cache(bundle, destination, packages, *, environment):
    """Admit the exact lock-bound cache before any receiving npm install."""
    bundle = Path(bundle)
    filesystem = extended_path(bundle)
    receipt = json.loads((filesystem / 'receipt.json').read_text(encoding='utf-8'))
    source = filesystem / 'source'
    if source.is_symlink() or source.is_junction():
        raise ValueError('dependency cache source is linked')
    for name, key in (('package.json', 'manifest_sha256'), ('package-lock.json', 'lock_sha256'), ('shrinkwrap.js', 'validator_sha256')):
        if (source / name).is_symlink() or (source / name).is_junction():
            raise ValueError('dependency cache source is linked')
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != receipt[key]:
            raise ValueError('dependency cache source binding differs')
    lock = json.loads((source / 'package-lock.json').read_text(encoding='utf-8'))
    if {key: value for key, value in lock['packages'].items() if key} != packages:
        raise ValueError('dependency cache source lock differs')
    if packages != receipt['packages'] or cache_files(bundle / 'cache') != receipt['files']:
        raise ValueError('dependency cache lock or byte inventory differs')
    verify_cached_archives(bundle / 'cache', packages, environment=environment)
    shutil.copytree(extended_path(bundle / 'cache'), extended_path(destination))
    if cache_files(destination) != receipt['files']:
        raise ValueError('copied dependency cache differs')
    verify_cached_archives(destination, packages, environment=environment)


def external_lock_identities(packages, own_versions=None):
    """Compare npm's resolved package identities; placement may be duplicated."""
    result = set()
    own_versions = own_versions or {}
    for location, entry in packages.items():
        if not location:
            continue
        if not location.startswith('node_modules/') or entry.get('link'):
            raise Refused('offline resolver returned an unsupported package location')
        name = location.rsplit('node_modules/', 1)[-1]
        if name.startswith('@openabstractions/'):
            if name not in own_versions or entry.get('version') != own_versions[name]:
                raise Refused('offline resolver changed a local archive identity: ' + name)
            continue
        version, integrity = entry.get('version'), entry.get('integrity')
        if not isinstance(version, str) or not isinstance(integrity, str):
            raise Refused('offline resolver omitted an external version or integrity')
        result.add((name, version, integrity))
    return result


def resolve_packed_dependencies(packed, target, environment, packages):
    """Constrain npm's normal offline resolver to the complete frozen closure."""
    dependencies, optional, own_versions = {}, {}, {}
    for name, path, _ in packed:
        dependencies[name] = 'file:' + path.resolve().as_posix()
        with tarfile.open(path, 'r:gz') as archive:
            own_versions[name] = json.load(archive.extractfile('package/package.json'))['version']
    for location, entry in packages.items():
        if location.count('node_modules/') == 1:
            name = location.removeprefix('node_modules/')
            (optional if entry.get('optional') else dependencies)[name] = entry['version']
    write_package(target, {'name':'oa-owned-packed-receiving', 'version':'0.0.0', 'private':True,
                           'dependencies':dependencies, 'optionalDependencies':optional})
    result = subprocess.run(['npm', 'install', '--package-lock-only', '--offline', '--ignore-scripts',
                             '--no-audit', '--no-fund', '--prefix', str(target)],
                            cwd=target, env=environment, capture_output=True, text=True, shell=os.name == 'nt')
    if result.returncode:
        raise Refused('offline locked dependency resolution failed: ' + (result.stderr.strip() or result.stdout.strip()))
    resolved = json.loads((target / 'package-lock.json').read_text(encoding='utf-8'))
    expected = external_lock_identities(packages)
    actual = external_lock_identities(resolved['packages'], own_versions)
    if actual != expected:
        raise Refused('offline external dependency closure differs from the frozen lock: '
                      + str(len(expected - actual)) + ' missing, ' + str(len(actual - expected)) + ' extra')
    return own_versions


def test_packed_packages(packed, identity, dependency_cache=None):
    """Install this exact archive set offline, then import its declared APIs."""
    pins = {str(path): digest(path) for _, path, _ in packed}
    names = []
    for expected, path, _ in packed:
        with tarfile.open(path, 'r:gz') as archive:
            data = json.load(archive.extractfile('package/package.json'))
        if data['name'] != expected:
            raise Refused('packed import input name differs')
        if expected in ('@openabstractions/ipc-' + identity, FACADE_NATIVE['prefix'] + identity):
            continue  # Binary payload package: its source-owned IPC loader resolves it.
        exports = data.get('exports')
        if exports is not None and not isinstance(exports, (str, dict)):
            raise Refused(expected + ': invalid public exports')
        if isinstance(exports, dict) and any(key.startswith('.') for key in exports) and '.' not in exports:
            raise Refused(expected + ': no declared public root import')
        names.append(expected)
    if len(names) != len(set(names)):
        raise Refused('duplicate packed import package')
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() not in ('NODE_PATH', 'NODE_OPTIONS', 'ABSTRACTION_IPC_NODE',
                       'ABSTRACTION_IPC_LIBRARY', 'ABSTRACTION_IPC_PREFIX', 'BUN_BE_BUN')
                   and not key.upper().startswith('NPM_CONFIG_')}
    with tempfile.TemporaryDirectory(prefix='oa-npm-import-') as temporary:
        target = Path(temporary).resolve()
        # Node resolves transitive dependencies through every ancestor.  Refuse
        # ambient module directories before allowing any package child to run.
        for parent in target.parents:
            modules = parent / 'node_modules'
            if modules.exists() or modules.is_symlink():
                raise Refused('ambient ancestor node_modules: ' + str(modules))
        # The offline receiving child needs only the explicit archive set,
        # never a person's npm configuration, credential helpers or cache.
        for name in ('user.npmrc', 'global.npmrc'):
            (target / name).write_text('', encoding='utf-8')
        home = target / 'home'; home.mkdir()
        environment.update(HOME=str(home), USERPROFILE=str(home),
            npm_config_userconfig=str(target / 'user.npmrc'),
            npm_config_globalconfig=str(target / 'global.npmrc'),
            npm_config_cache=str(target / 'npm-cache'), npm_config_update_notifier='false')
        if dependency_cache is not None:
            opencode = [path for name, path, _ in packed if name == '@openabstractions/opencode']
            if len(opencode) != 1:
                raise Refused('dependency cache requires the packed OpenCode lock')
            with tarfile.open(opencode[0], 'r:gz') as archive:
                wrap = json.load(archive.extractfile('package/npm-shrinkwrap.json'))
            packages = {key: value for key, value in wrap['packages'].items() if key}
            try:
                copy_dependency_cache(
                    Path(dependency_cache), target / 'npm-cache', packages, environment=environment)
            except (OSError, ValueError, KeyError) as error:
                raise Refused('dependency cache admission failed: ' + str(error)) from error
            own_versions = resolve_packed_dependencies(packed, target, environment, packages)
            admitted_root = {name:(target / name).read_bytes() for name in ('package.json','package-lock.json')}
        install_args = (['npm', 'install', '--offline', '--ignore-scripts', '--no-save', '--no-audit', '--no-fund', '--prefix', str(target)]
                        if dependency_cache is not None else
                        ['npm', 'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund',
                         '--no-package-lock', '--prefix', str(target), *pins])
        install = subprocess.run(install_args, cwd=target, env=environment,
            capture_output=True, text=True, shell=os.name == 'nt')
        if install.returncode:
            raise Refused('packed package set does not install offline: ' + (install.stderr.strip() or install.stdout.strip()))
        if dependency_cache is not None:
            if any((target / name).read_bytes() != value for name, value in admitted_root.items()):
                raise Refused('offline installation changed the admitted root manifest or lock')
            installed_lock = json.loads((target / 'package-lock.json').read_text(encoding='utf-8'))
            if external_lock_identities(installed_lock['packages'], own_versions) != external_lock_identities(packages):
                raise Refused('offline installation changed the frozen external closure')
        script = '''import {createRequire} from 'node:module';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {realpathSync} from 'node:fs';
import {sep} from 'node:path';
const names=JSON.parse(process.argv[1]);
const boundary=realpathSync(process.cwd())+sep+'node_modules'+sep;
const require=createRequire(import.meta.url);
const nativeName='@openabstractions/facade-native-'+process.argv[2];
const nativePath=process.argv[3]==='1'?require.resolve(nativeName):null;
if(nativePath && (!realpathSync(nativePath).startsWith(boundary) || require.cache[nativePath])) throw Error('foreign or preloaded AppModel native payload');
for(const name of names) {
 if(!realpathSync(fileURLToPath(import.meta.resolve(name))).startsWith(boundary)) throw Error('import escaped installed archive target');
 await import(name);
}
if(names.includes('@openabstractions/ipc')) {
 const ipc=await import('@openabstractions/ipc');
 if(dirname(ipc.addonPath())!==dirname(require.resolve('@openabstractions/ipc-'+process.argv[2]+'/package.json'))) throw Error('foreign native payload');
}
if(nativePath) {
 await import('@openabstractions/facade/protocol');
 if(require.cache[nativePath]) throw Error('pure facade import loaded native code');
 const {createAppModel}=await import('@openabstractions/facade/appmodel-core');
 if(require.cache[nativePath]) throw Error('AppModel module import loaded native code eagerly');
 const app=createAppModel({instance:'offline-package-receiving'});
 try {
  if(!require.cache[nativePath] || require(nativeName).abiVersion()!==2) throw Error('AppModel did not load its declared ABI2 package');
  app.kind({name:'item',schema:{type:'object'}});
  const context=app.context({context:'owned-fixture',read:()=>({entities:[],collections:{}})});
  if(!context.ref.epoch || !context.revision) throw Error('native context receiving failed');
  context.close();
 } finally { app.close(); app.dispose(); }
}'''
        has_facade_native = any(name == FACADE_NATIVE['prefix'] + identity for name, _, _ in packed)
        checked = subprocess.run(['node', '--no-global-search-paths', '--input-type=module', '-e', script,
                                  json.dumps(names), identity, '1' if has_facade_native else '0'],
            cwd=target, env=environment, capture_output=True, text=True)
        if checked.returncode:
            raise Refused('packed public package import failed: ' + (checked.stderr.strip() or checked.stdout.strip()))
        if has_facade_native:
            # Each child has a fresh module cache. Mutate only this disposable
            # installed fixture; the input archives remain immutable below.
            native_directory = target / 'node_modules' / (FACADE_NATIVE['prefix'] + identity)
            facade_manifest = target / 'node_modules/@openabstractions/facade/package.json'
            original_manifest = facade_manifest.read_bytes()
            refusal_script = '''await import('@openabstractions/facade');
await import('@openabstractions/facade/protocol');
const {createAppModel}=await import('@openabstractions/facade/appmodel-core');
try { createAppModel({instance:'owned-refusal-fixture'}); throw Error('accepted unavailable native family'); }
catch(error) { if(!error.message.startsWith('AppModel native component unavailable:')) throw error; }
'''
            def refuse():
                result = subprocess.run(['node', '--no-global-search-paths', '--input-type=module', '-e', refusal_script],
                    cwd=target, env=environment, capture_output=True, text=True)
                if result.returncode:
                    raise Refused('packed native routing refusal failed: ' + (result.stderr.strip() or result.stdout.strip()))
            held = native_directory.with_name(native_directory.name + '.held')
            native_directory.rename(held)
            try:
                refuse()
            finally:
                held.rename(native_directory)
            try:
                for dependencies in ({FACADE_NATIVE['prefix'] + 'win32-arm64': '0.0.0'}, {}):
                    metadata = json.loads(original_manifest)
                    metadata['optionalDependencies'] = dependencies
                    facade_manifest.write_text(json.dumps(metadata), encoding='utf-8')
                    refuse()
            finally:
                facade_manifest.write_bytes(original_manifest)
            native_manifest = native_directory / 'package.json'
            original_native = native_manifest.read_bytes()
            old_abi = native_directory / 'owned-old-abi.cjs'
            try:
                # A test-owned old-ABI module exercises the normal package
                # lookup, without claiming an old native binary was executed.
                old_abi.write_text('module.exports={abiVersion:()=>1,sessionActivation(){},callbackFault(){},defaultBounds(){throw Error("must not read layout")},create(){throw Error("must not create")}};', encoding='utf-8')
                metadata = json.loads(original_native)
                metadata['main'] = './' + old_abi.name
                metadata['exports']['.'] = './' + old_abi.name
                native_manifest.write_text(json.dumps(metadata), encoding='utf-8')
                refuse()
            finally:
                native_manifest.write_bytes(original_native)
                old_abi.unlink()
        if '@openabstractions/opencode' in names:
            test_opencode_package(target, environment)
    if pins != {str(path): digest(path) for _, path, _ in packed}:
        raise Refused('packed import inputs changed')


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


def facade_native_members(archive):
    """The single declared native family, shared by packing and final receiving."""
    members = archive.getmembers()
    names = [item.name for item in members]
    if (len(names) != 5 or len(names) != len(set(names)) or names.count('package/package.json') != 1
            or any(not item.isfile() for item in members)):
        raise Refused("facade native archive member inventory differs")
    data = json.load(archive.extractfile("package/package.json"))
    name = data.get('name') if isinstance(data, dict) else None
    identity = name.removeprefix(FACADE_NATIVE['prefix']) if isinstance(name, str) else ''
    library = FACADE_NATIVE['libraries'].get(identity)
    if library is None:
        raise Refused('facade native archive declaration differs')
    required = {"package.json", "LICENSE", "README.md", FACADE_NATIVE["addon"], library}
    if set(names) != {"package/" + name for name in required}:
        raise Refused('facade native archive member inventory differs')
    if (data.get("name") != FACADE_NATIVE["prefix"] + identity
            or data.get("os") != [identity.split('-', 1)[0]] or data.get("cpu") != [identity.split('-', 1)[1]]
            or data.get("main") != "./" + FACADE_NATIVE["addon"]
            or data.get("exports") != {'.': './' + FACADE_NATIVE['addon'], './package.json': './package.json', './' + library: './' + library}
            or data.get("files") != [FACADE_NATIVE["addon"], library, "README.md"]
            or "scripts" in data):
        raise Refused("facade native archive declaration differs")
    return data, {name: archive.getmember("package/" + name) for name in required}


def verify_facade_native(tarball, directory):
    """The native archive is exactly its staged declaration and byte inputs."""
    data = read_package(directory)
    with tarfile.open(tarball, "r:gz") as archive:
        declared, members = facade_native_members(archive)
        if declared != data:
            raise Refused("facade native archive declaration differs")
        for name, member in members.items():
            if name == "package.json":
                continue
            source = directory / name
            if member.size != source.stat().st_size:
                raise Refused("facade native archive byte count differs: " + name)
            value = hashlib.sha256()
            with archive.extractfile(member) as stream:
                for block in iter(lambda: stream.read(1 << 20), b""):
                    value.update(block)
            if value.hexdigest() != digest(source):
                raise Refused("facade native archive hash differs: " + name)
    return sorted("package/" + name for name in members)


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
    generated_packages = generated_package_names(sources["ipc"])
    validate_source_roster(package_data, manifest, generated_packages)
    identity = args.platform or host_platform()
    if identity not in table:
        raise Refused(f"{identity} has no qualified platform package; "
                      "the connectors name " + ", ".join(sorted(table)))
    facade_inputs = (getattr(args, "facade_library", None), getattr(args, "facade_addon", None))
    if any(facade_inputs) and not all(facade_inputs):
        raise Refused("facade native packaging requires both --facade-library and --facade-addon")
    facade_native = None
    facade_pins = {}
    if all(facade_inputs):
        if identity not in FACADE_NATIVE["libraries"]:
            raise Refused(f"{identity} has no facade native package declaration")
        dependency = FACADE_NATIVE["prefix"] + identity
        if dependency not in package_data["facade"].get("optionalDependencies", {}):
            raise Refused("facade source does not declare its selected native optional dependency")
        facade_native = tuple(Path(value).resolve() for value in facade_inputs)
        for path, filename in zip(facade_native, (FACADE_NATIVE["libraries"][identity], FACADE_NATIVE["addon"])):
            if not path.is_file() or path.name != filename:
                raise Refused("facade native packaging requires the built " + filename)
            facade_pins[path] = (path.stat().st_size, digest(path))
    test_opencode_package(sources["opencode"])
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
        if facade_native:
            staged.append(assemble_facade_native(stage, identity, *facade_native,
                          args.version, license_file, read_package(sources["facade"])["homepage"]))
        staged += [stage_source(stage, name, sources[name], args.version, license_file)
                   for name in SOURCES]
        shrinkwrapped = []
        for directory in staged:
            wrapped = write_shrinkwrap(directory)
            name, required = required_entries(directory)
            tarball = pack(directory, output)
            packed.append((name, tarball, verify(name, tarball, required)))
            if name.startswith(FACADE_NATIVE["prefix"]):
                verify_facade_native(tarball, directory)
            if wrapped:
                verify_shrinkwrap(name, tarball, directory)
                shrinkwrapped.append(name)

    expected = {data["name"] for data in package_data.values()} | {f"@openabstractions/ipc-{identity}"}
    if facade_native:
        expected.add(FACADE_NATIVE["prefix"] + identity)
    actual = [name for name, _, _ in packed]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise Refused("packed package roster differs from the pinned source packages and selected IPC platform")
    if identity == host_platform():
        test_packed_packages(packed, identity, getattr(args, 'dependency_cache', None))
    else:
        print('packed import not run for incompatible host platform: ' + identity)
    if facade_pins != {path: (path.stat().st_size, digest(path)) for path in facade_pins}:
        raise Refused("facade native producer inputs changed during packing")

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
    p.add_argument("--facade-library", metavar="PATH", help="the same-source qualified AppModel shared C ABI library")
    p.add_argument("--facade-addon", metavar="PATH", help="the same-source qualified oa_appmodel_node.node; requires --facade-library")
    p.add_argument("--dependency-cache", metavar="DIR", help="explicit lock-bound test cache prepared by the OpenCode dependency owner")
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
