#!/usr/bin/env python3
"""Build a client-owned platform wheel from its built native library.

A Python adopter's native client ships inside its wheel (PACKAGING-2026-09-22,
`research/adoption/comfyui/PACKAGING-2026-09-22.md`): one PyPI distribution,
`abstraction-ipc`, built as a binary wheel per platform tag, each carrying the
matching `abstraction_ipc.dll` / `libabstraction_ipc.so` /
`libabstraction_ipc.dylib` as package data. `pip install abstraction-ipc`
resolves the one wheel that matches the running platform automatically, no
environment variable and no second package name required. This script
assembles that wheel from a built shared C ABI library and the pure-Python
`abstraction.ipc` package, unchanged.

No arguments prints this help. Nothing here reaches the network, and nothing
here publishes: uploading to PyPI needs the owner's organization and consent.

  py scripts/py_wheels.py --version 0.2.0 --output DIR \\
      --library <built shared library> --platform win_amd64

  py scripts/py_wheels.py --check DIR/abstraction_ipc-0.2.0-py3-none-win_amd64.whl

Versions come from --version alone. The source pyproject.toml keeps 0.0.0.
--family abstraction-facade-native selects the optional Facade application-local
component and its py-native source; the default family remains abstraction-ipc.
A wheel missing a file its RECORD names, or carrying one it does not name, is
refused by name; so is a wheel whose bundled library does not match its
platform tag.
"""
import argparse
import base64
import hashlib
import json
import platform as host_platform_module
import re
import shutil
import sys
import zipfile
from pathlib import Path
try:
    from .windows_native import NativeDependencyError, validate_portable_windows_dll
    from .npm_packages import FACADE_NATIVE
except ImportError:  # direct script invocation from scripts/
    from windows_native import NativeDependencyError, validate_portable_windows_dll
    from npm_packages import FACADE_NATIVE

ROOT = Path(__file__).resolve().parent.parent
NAME = "abstraction-ipc"
# The wheel filename normalizes runs of non-alphanumeric characters to `_`
# (PEP 427); "abstraction-ipc" already has exactly one run to normalize.
WHEEL_NAME = "abstraction_ipc"
DEFAULT_PACKAGE = "openabstractions-flat/abstraction-identity/py"
# npm's own version grammar reused verbatim: the two packagers share one
# --version value for one release, so they accept the same strings.
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
WHEEL_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.whl\Z")
RECEIPT_FIELDS = {"schema", "candidate_source", "candidate_version", "run_id", "run_attempt", "platform", "wheels"}
WHEEL_FIELDS = {"distribution", "repository", "commit", "directory", "filename", "bytes", "sha256"}
MAX_NATIVE_WHEEL_BYTES = 128 * 1024 * 1024
MAX_NATIVE_UNPACKED_BYTES = 256 * 1024 * 1024

# The six platform tags the PACKAGING decision names, and the native library
# filename each one's wheel carries. packaging.tags would compute the same
# strings for a CPython interpreter on each of these platforms; they are
# fixed here rather than derived because this script targets a library built
# for a platform this process is not necessarily running on.
PLATFORM_LIBRARIES = {
    "win_amd64": "abstraction_ipc.dll",
    "win_arm64": "abstraction_ipc.dll",
    "manylinux_2_28_x86_64": "libabstraction_ipc.so",
    "manylinux_2_28_aarch64": "libabstraction_ipc.so",
    "macosx_11_0_arm64": "libabstraction_ipc.dylib",
    "macosx_11_0_x86_64": "libabstraction_ipc.dylib",
}


# One assembler and receipt grammar for the two client-owned native families.
NATIVE_FAMILIES = {
    NAME: {"wheel": WHEEL_NAME, "package": DEFAULT_PACKAGE,
           "module": "abstraction/ipc", "directory": "py", "libraries": PLATFORM_LIBRARIES},
    FACADE_NATIVE['python']: {
        "wheel": FACADE_NATIVE['python'].replace('-', '_'),
        "repository": FACADE_NATIVE['repository'], "candidate_projection": True,
        "package": 'openabstractions-flat/' + FACADE_NATIVE['repository'].split('/')[1] + '/' + FACADE_NATIVE['python_directory'],
        "module": FACADE_NATIVE['python'].replace('-', '_'), "directory": FACADE_NATIVE['python_directory'],
        "libraries": {
            "win_amd64": FACADE_NATIVE['libraries']['win32-x64'],
            "win_arm64": FACADE_NATIVE['libraries']['win32-x64'],
            "manylinux_2_28_x86_64": FACADE_NATIVE['libraries']['linux-x64'],
            "manylinux_2_28_aarch64": FACADE_NATIVE['libraries']['linux-x64'],
            "macosx_11_0_arm64": FACADE_NATIVE['libraries']['darwin-arm64'],
            "macosx_11_0_x86_64": FACADE_NATIVE['libraries']['darwin-x64']}},
}


def native_family(distribution):
    try:
        return NATIVE_FAMILIES[distribution]
    except (KeyError, TypeError) as exc:
        raise Refused("unrecognized native wheel family") from exc


class Refused(Exception):
    """A condition the caller must fix; printed without a traceback."""


class ValidatedWheelInputs(dict):
    """Receipt accepted against a selected successful Windows producer run."""


def pure_wheel_version(candidate_version):
    """Current trains are lockstep; pre-0.8 receipts retain their legacy version."""
    if not isinstance(candidate_version, str) or not VERSION.fullmatch(candidate_version):
        raise Refused('invalid candidate wheel version')
    release = tuple(int(part) for part in candidate_version.split('-', 1)[0].split('.'))
    return candidate_version if release >= (0, 8, 0) else '0.0.0'


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused(f"duplicate wheel receipt key: {key}")
        result[key] = value
    return result


def load_wheel_inputs(path, *, candidate_source, candidate_version, run_id, run_attempt):
    """Read the selected Windows Python artifact's strict same-run receipt."""
    try:
        receipt = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Refused("Windows wheel receipt is unreadable") from exc
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS or type(receipt["schema"]) is not int or receipt["schema"] != 1:
        raise Refused("Windows wheel receipt has an invalid schema")
    if (not isinstance(candidate_source, str) or not COMMIT.fullmatch(candidate_source)
            or receipt["candidate_source"] != candidate_source
            or not isinstance(candidate_version, str) or not VERSION.fullmatch(candidate_version)
            or receipt["candidate_version"] != candidate_version
            or type(run_id) is not int or run_id <= 0 or receipt["run_id"] != run_id
            or type(run_attempt) is not int or run_attempt <= 0 or receipt["run_attempt"] != run_attempt
            or receipt["platform"] != "win32-x64"):
        raise Refused("Windows wheel receipt differs from selected candidate run")
    if type(receipt["run_id"]) is not int or type(receipt["run_attempt"]) is not int:
        raise Refused("Windows wheel receipt run identity is invalid")
    if not isinstance(receipt["wheels"], list) or not receipt["wheels"]:
        raise Refused("Windows wheel receipt has no wheels")
    distributions, filenames = set(), set()
    for entry in receipt["wheels"]:
        if not isinstance(entry, dict):
            raise Refused("Windows wheel receipt entry is not an object")
        native = isinstance(entry.get("distribution"), str) and entry["distribution"] in NATIVE_FAMILIES
        fields = WHEEL_FIELDS | ({"native_library_sha256"} if native else set())
        if set(entry) != fields:
            raise Refused("Windows wheel receipt entry has unexpected fields")
        distribution, filename = entry["distribution"], entry["filename"]
        if (not isinstance(distribution, str) or not re.fullmatch(r"abstraction-[a-z0-9-]+", distribution)
                or distribution in distributions or not isinstance(filename, str)
                or not WHEEL_BASENAME.fullmatch(filename) or filename in filenames
                or not isinstance(entry["repository"], str)
                or not re.fullmatch(r"openabstractions/[A-Za-z0-9._-]+", entry["repository"])
                or not isinstance(entry["commit"], str) or not COMMIT.fullmatch(entry["commit"])
                or entry["directory"] not in ("py", "python", "py-native")
                or (native and entry["directory"] != native_family(distribution)["directory"])
                or (not native and entry["directory"] == "py-native")
                or type(entry["bytes"]) is not int
                or not 0 < entry["bytes"] < 2 * 1024 * 1024 * 1024
                or not isinstance(entry["sha256"], str) or not SHA256.fullmatch(entry["sha256"])
                or (native and (not isinstance(entry["native_library_sha256"], str)
                                or not SHA256.fullmatch(entry["native_library_sha256"])))):
            raise Refused("Windows wheel receipt entry is invalid or duplicated")
        version = candidate_version if native else pure_wheel_version(candidate_version)
        platform = 'win_amd64' if native else 'any'
        if filename != f"{distribution.replace('-', '_')}-{version}-py3-none-{platform}.whl":
            raise Refused('Windows wheel filename differs from selected candidate version')
        distributions.add(distribution)
        filenames.add(filename)
    return ValidatedWheelInputs(receipt)


def verify_native_receipt_wheel(receipt, wheel_dir, *, repository, commit, directory="py", distribution=NAME):
    """Check one pinned native wheel and return its path, exact DLL bytes and receipt entry."""
    if (not isinstance(receipt, ValidatedWheelInputs)
            or not isinstance(receipt.get("candidate_version"), str)
            or not VERSION.fullmatch(receipt["candidate_version"])):
        raise Refused("native wheel requires a selected and validated Windows receipt")
    family = native_family(distribution)
    native = [entry for entry in receipt["wheels"] if entry["distribution"] == distribution]
    if len(native) != 1 or not isinstance(repository, str) or not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise Refused("Windows wheel receipt needs exactly one pinned native family wheel")
    entry = native[0]
    if (entry["repository"], entry["commit"], entry["directory"]) != (repository, commit, directory):
        raise Refused("native wheel source differs from selected pypi.tsv pin")
    filename = f"{family['wheel']}-{receipt['candidate_version']}-py3-none-win_amd64.whl"
    if entry["filename"] != filename or entry["bytes"] > MAX_NATIVE_WHEEL_BYTES:
        raise Refused("native wheel filename or size is not the selected Windows candidate")
    path = Path(wheel_dir) / filename
    if path.resolve().parent != Path(wheel_dir).resolve():
        raise Refused("native wheel path leaves the selected wheel directory")
    if path.is_symlink() or not path.is_file() or path.stat().st_size != entry["bytes"]:
        raise Refused("native wheel file is missing or differs in size")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != entry["sha256"]:
        raise Refused("native wheel bytes differ from the selected receipt")
    try:
        with zipfile.ZipFile(path) as archive:
            if sum(item.file_size for item in archive.infolist()) > MAX_NATIVE_UNPACKED_BYTES:
                raise Refused("native wheel expands beyond the review limit")
            dll = archive.read(f"{family['module']}/_native/{family['libraries']['win_amd64']}")
    except (zipfile.BadZipFile, KeyError) as exc:
        raise Refused("native wheel lacks a readable fixed DLL") from exc
    version, platform_tag, _ = check(path)
    if version != receipt["candidate_version"] or platform_tag != "win_amd64":
        raise Refused("native wheel metadata differs from the selected candidate")
    if hashlib.sha256(dll).hexdigest() != entry["native_library_sha256"]:
        raise Refused("native DLL bytes differ from the selected receipt")
    return path, dll, entry


def host_platform():
    """This host's platform tag, in the table above's spelling."""
    system = sys.platform
    machine = host_platform_module.machine().lower()
    if machine not in ("amd64", "x86_64", "arm64", "aarch64"):
        raise Refused(f"no platform tag is defined for {system}/{machine}")
    arm = machine in ("arm64", "aarch64")
    if system == "win32":
        return "win_arm64" if arm else "win_amd64"
    if system == "darwin":
        return "macosx_11_0_arm64" if arm else "macosx_11_0_x86_64"
    if system == "linux":
        return "manylinux_2_28_aarch64" if arm else "manylinux_2_28_x86_64"
    raise Refused(f"no platform tag is defined for {system}/{machine}")


def read_metadata(package, distribution=NAME):
    """name, version placeholder and description, read out of pyproject.toml.

    A hand-rolled reader rather than tomllib on a `[project]` table this
    project's own pyproject.toml files keep to one line per scalar field, so
    a change to a field this script does not expect fails loudly instead of
    silently reading nothing.
    """
    text = (package / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^\[project\]\s*$(.*?)^\[', text + "\n[", re.S)
    body = match.group(1) if match else ""
    fields = dict(re.findall(r'(?m)^(\w[\w-]*)\s*=\s*"([^"]*)"\s*$', body))
    if fields.get("name") != distribution:
        raise Refused(f"{package}/pyproject.toml names {fields.get('name')!r}, expected {distribution!r}")
    requires_python = fields.get("requires-python")
    if not requires_python:
        raise Refused(f"{package}/pyproject.toml carries no requires-python")
    return fields.get("description", ""), requires_python


def record_hash(data):
    """The wheel RECORD's own digest spelling: unpadded URL-safe base64 sha256."""
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def stage_package(stage, package, distribution=NAME):
    """Copy this family's Python package into the wheel root, unchanged."""
    module = native_family(distribution)["module"]
    source = package / module
    if not (source / "__init__.py").is_file():
        raise Refused(f"{source} has no __init__.py; not a package to stage")
    destination = stage / module
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    if (destination / "_native").exists():
        raise Refused(f"{source} already carries _native/; a source checkout must not")
    return destination


def write_wheel(output_dir, wheel_name, files):
    """Zip `files` (path -> bytes) into `output_dir/wheel_name`, RECORD included, sorted."""
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / wheel_name
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[path])
    return target


def assemble(version, platform_tag, library, package, license_file, output, *, distribution=NAME):
    """Build one platform wheel; returns (path, files-added-to-the-zip)."""
    family = native_family(distribution)
    wheel_basename = family["wheel"]
    library_filename = family["libraries"].get(platform_tag)
    if library_filename is None:
        raise Refused(f"{platform_tag} has no qualified platform wheel; "
                      "this script names " + ", ".join(sorted(PLATFORM_LIBRARIES)))
    if library.name != library_filename:
        raise Refused(f"--library must be the built {library_filename} for {platform_tag}, not {library.name}")
    if platform_tag.startswith("win_"):
        try:
            validate_portable_windows_dll(library, platform_tag)
        except NativeDependencyError as exc:
            raise Refused(str(exc)) from exc
    if not license_file.is_file():
        raise Refused(f"--license must name an existing file: {license_file}")
    description, requires_python = read_metadata(package, distribution)

    stage = output.parent / f".py_wheels-stage-{wheel_basename}-{platform_tag}"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    try:
        ipc_dir = stage_package(stage, package, distribution)
        native_dir = ipc_dir / "_native"
        native_dir.mkdir()
        shutil.copyfile(library, native_dir / library_filename)

        dist_info = f"{wheel_basename}-{version}.dist-info"
        metadata = (
            "Metadata-Version: 2.1\n"
            f"Name: {distribution}\n"
            f"Version: {version}\n"
            f"Summary: {description}\n"
            f"Requires-Python: {requires_python}\n"
            "License-File: LICENSE\n"
        )
        wheel = (
            "Wheel-Version: 1.0\n"
            "Generator: py_wheels\n"
            "Root-Is-Purelib: false\n"
            f"Tag: py3-none-{platform_tag}\n"
        )
        files = {}
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                files[str(path.relative_to(stage)).replace("\\", "/")] = path.read_bytes()
        files[f"{dist_info}/METADATA"] = metadata.encode("utf-8")
        files[f"{dist_info}/WHEEL"] = wheel.encode("utf-8")
        files[f"{dist_info}/LICENSE"] = license_file.read_bytes()

        record_lines = [f"{path},{record_hash(data)},{len(data)}" for path, data in sorted(files.items())]
        record_lines.append(f"{dist_info}/RECORD,,")
        files[f"{dist_info}/RECORD"] = ("\n".join(record_lines) + "\n").encode("utf-8")

        wheel_name = f"{wheel_basename}-{version}-py3-none-{platform_tag}.whl"
        target = write_wheel(output, wheel_name, files)
        return target, sorted(files)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def check(wheel_path):
    """Validate a built wheel's filename, RECORD and platform tag; return its listing."""
    candidates = [(name, value) for name, value in NATIVE_FAMILIES.items()
                  if wheel_path.name.startswith(value["wheel"] + "-")]
    if len(candidates) != 1:
        raise Refused("unrecognized native wheel family")
    distribution, family = candidates[0]
    wheel_basename = family["wheel"]
    match = re.fullmatch(rf"{wheel_basename}-([^-]+)-py3-none-([^-]+)\.whl", wheel_path.name)
    if not match:
        raise Refused(f"{wheel_path.name} is not named {wheel_basename}-VERSION-py3-none-PLATFORM.whl")
    version, platform_tag = match.groups()
    library_filename = family["libraries"].get(platform_tag)
    if library_filename is None:
        raise Refused(f"{wheel_path.name}: {platform_tag} is not a qualified platform wheel tag; "
                      "this script names " + ", ".join(sorted(PLATFORM_LIBRARIES)))
    dist_info = f"{wheel_basename}-{version}.dist-info"
    with zipfile.ZipFile(wheel_path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise Refused(f"{wheel_path.name} carries a duplicate entry")
        contents = {name: archive.read(name) for name in names}
    wheel_text = contents.get(f"{dist_info}/WHEEL")
    if wheel_text is None:
        raise Refused(f"{wheel_path.name} carries no {dist_info}/WHEEL")
    tag_match = re.search(r"(?m)^Tag:\s*(\S+)\s*$", wheel_text.decode("utf-8"))
    if not tag_match or tag_match.group(1) != f"py3-none-{platform_tag}":
        raise Refused(f"{wheel_path.name}: WHEEL Tag does not read py3-none-{platform_tag}")
    metadata = contents.get(f"{dist_info}/METADATA")
    if metadata is None:
        raise Refused(f"{wheel_path.name} carries no {dist_info}/METADATA")
    metadata_lines = metadata.decode("utf-8").splitlines()
    if metadata_lines.count(f"Name: {distribution}") != 1 or metadata_lines.count(f"Version: {version}") != 1:
        raise Refused(f"{wheel_path.name}: METADATA name or version differs")
    record_bytes = contents.get(f"{dist_info}/RECORD")
    if record_bytes is None:
        raise Refused(f"{wheel_path.name} carries no {dist_info}/RECORD")
    record_path = f"{dist_info}/RECORD"
    listed = set()
    for line in record_bytes.decode("utf-8").splitlines():
        if not line:
            continue
        path, digest, size = line.rsplit(",", 2)
        listed.add(path)
        if path == record_path:
            continue
        data = contents.get(path)
        if data is None:
            raise Refused(f"{wheel_path.name}: RECORD names {path}, which the archive does not carry")
        if record_hash(data) != digest:
            raise Refused(f"{wheel_path.name}: {path} does not match its RECORD digest")
        if len(data) != int(size):
            raise Refused(f"{wheel_path.name}: {path} does not match its RECORD size")
    missing = set(contents) - listed
    if missing:
        raise Refused(f"{wheel_path.name}: RECORD does not name {sorted(missing)}")
    native = f"{family['module']}/_native/{library_filename}"
    if native not in contents or not contents[native]:
        raise Refused(f"{wheel_path.name} carries no non-empty {native}")
    if {name for name in contents if name.startswith(family['module'] + '/_native/')} != {native}:
        raise Refused(f"{wheel_path.name} carries an unexpected native family member")
    if platform_tag.startswith("win_"):
        try:
            validate_portable_windows_dll(contents[native], platform_tag)
        except NativeDependencyError as exc:
            raise Refused(str(exc)) from exc
    if family["module"] + "/__init__.py" not in contents:
        raise Refused(f"{wheel_path.name} carries no {family['module']}/__init__.py")
    return version, platform_tag, sorted(contents)


def run(args):
    if args.check:
        version, platform_tag, contents = check(Path(args.check).resolve())
        print(f"ok    {Path(args.check).name}: {version} {platform_tag}")
        for path in contents:
            print(f"        {path}")
        return 0
    if not VERSION.match(args.version):
        raise Refused("--version must be MAJOR.MINOR.PATCH with an optional prerelease suffix")
    platform_tag = args.platform or host_platform()
    library = Path(args.library).resolve()
    if not library.is_file():
        raise Refused(f"--library must name an existing file: {library}")
    family = native_family(args.family)
    package = Path(args.package or ROOT / family["package"]).resolve()
    if not (package / "pyproject.toml").is_file():
        raise Refused(f"no pyproject.toml at {package}")
    license_file = Path(args.license or ROOT / "LICENSE").resolve()
    output = Path(args.output).resolve()

    target, files = assemble(args.version, platform_tag, library, package, license_file, output, distribution=args.family)
    version, checked_tag, _ = check(target)
    if (version, checked_tag) != (args.version, platform_tag):
        raise Refused(f"{target.name}: built as {version} {checked_tag}, expected {args.version} {platform_tag}")

    print(f"\n{args.family} {args.version} {platform_tag}")
    print(f"  {target.name}  {target.stat().st_size} bytes  sha256 {hashlib.sha256(target.read_bytes()).hexdigest()}")
    for path in files:
        print(f"    {path}")
    print(f"\n1 wheel in {output}. Nothing was published.")
    return 0


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--family", choices=sorted(NATIVE_FAMILIES), default=NAME, help="client-owned native wheel family")
    p.add_argument("--version", metavar="X.Y.Z", help="the version the built wheel carries")
    p.add_argument("--output", metavar="DIR", help="directory receiving the wheel")
    p.add_argument("--library", metavar="PATH", help="the built shared C ABI library for --platform")
    p.add_argument("--platform", metavar="TAG",
                   help="the wheel platform tag to assemble; default: this host. One of "
                        + ", ".join(sorted(PLATFORM_LIBRARIES)))
    p.add_argument("--package", metavar="DIR",
                   help=f"the pure-Python abstraction.ipc package directory; default: {DEFAULT_PACKAGE}")
    p.add_argument("--license", metavar="FILE", help="the licence copied into the wheel; default: LICENSE")
    p.add_argument("--check", metavar="WHEEL", help="validate a built wheel's RECORD and platform tag; no build")
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if not (args.check or (args.version and args.output and args.library)):
        p.print_help()
        return 0
    return run(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refused as refusal:
        print(f"REFUSED {refusal}", file=sys.stderr)
        sys.exit(2)
