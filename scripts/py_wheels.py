#!/usr/bin/env python3
"""Build one platform-tagged `abstraction-ipc` wheel from a built native library.

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
A wheel missing a file its RECORD names, or carrying one it does not name, is
refused by name; so is a wheel whose bundled library does not match its
platform tag.
"""
import argparse
import base64
import hashlib
import platform as host_platform_module
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "abstraction-ipc"
# The wheel filename normalizes runs of non-alphanumeric characters to `_`
# (PEP 427); "abstraction-ipc" already has exactly one run to normalize.
WHEEL_NAME = "abstraction_ipc"
DEFAULT_PACKAGE = "openabstractions-flat/abstraction-identity/py"
# npm's own version grammar reused verbatim: the two packagers share one
# --version value for one release, so they accept the same strings.
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")

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


class Refused(Exception):
    """A condition the caller must fix; printed without a traceback."""


def host_platform():
    """This host's platform tag, in the table above's spelling."""
    system = sys.platform
    machine = host_platform_module.machine().lower()
    arm = machine in ("arm64", "aarch64")
    if system == "win32":
        return "win_arm64" if arm else "win_amd64"
    if system == "darwin":
        return "macosx_11_0_arm64" if arm else "macosx_11_0_x86_64"
    if system == "linux":
        return "manylinux_2_28_aarch64" if arm else "manylinux_2_28_x86_64"
    raise Refused(f"no platform tag is defined for {system}/{machine}")


def read_metadata(package):
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
    if fields.get("name") != NAME:
        raise Refused(f"{package}/pyproject.toml names {fields.get('name')!r}, expected {NAME!r}")
    requires_python = fields.get("requires-python")
    if not requires_python:
        raise Refused(f"{package}/pyproject.toml carries no requires-python")
    return fields.get("description", ""), requires_python


def record_hash(data):
    """The wheel RECORD's own digest spelling: unpadded URL-safe base64 sha256."""
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def stage_package(stage, package):
    """Copy the pure-Python `abstraction.ipc` package into the wheel root, unchanged."""
    source = package / "abstraction" / "ipc"
    if not (source / "__init__.py").is_file():
        raise Refused(f"{source} has no __init__.py; not a package to stage")
    destination = stage / "abstraction" / "ipc"
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
            archive.writestr(path, files[path])
    return target


def assemble(version, platform_tag, library, package, license_file, output):
    """Build one platform wheel; returns (path, files-added-to-the-zip)."""
    library_filename = PLATFORM_LIBRARIES.get(platform_tag)
    if library_filename is None:
        raise Refused(f"{platform_tag} has no qualified platform wheel; "
                      "this script names " + ", ".join(sorted(PLATFORM_LIBRARIES)))
    if library.name != library_filename:
        raise Refused(f"--library must be the built {library_filename} for {platform_tag}, not {library.name}")
    if not license_file.is_file():
        raise Refused(f"--license must name an existing file: {license_file}")
    description, requires_python = read_metadata(package)

    stage = output.parent / f".py_wheels-stage-{platform_tag}"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    try:
        ipc_dir = stage_package(stage, package)
        native_dir = ipc_dir / "_native"
        native_dir.mkdir()
        shutil.copyfile(library, native_dir / library_filename)

        dist_info = f"{WHEEL_NAME}-{version}.dist-info"
        metadata = (
            "Metadata-Version: 2.1\n"
            f"Name: {NAME}\n"
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

        wheel_name = f"{WHEEL_NAME}-{version}-py3-none-{platform_tag}.whl"
        target = write_wheel(output, wheel_name, files)
        return target, sorted(files)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def check(wheel_path):
    """Validate a built wheel's filename, RECORD and platform tag; return its listing."""
    match = re.fullmatch(rf"{WHEEL_NAME}-([^-]+)-py3-none-([^-]+)\.whl", wheel_path.name)
    if not match:
        raise Refused(f"{wheel_path.name} is not named {WHEEL_NAME}-VERSION-py3-none-PLATFORM.whl")
    version, platform_tag = match.groups()
    library_filename = PLATFORM_LIBRARIES.get(platform_tag)
    if library_filename is None:
        raise Refused(f"{wheel_path.name}: {platform_tag} is not a qualified platform wheel tag; "
                      "this script names " + ", ".join(sorted(PLATFORM_LIBRARIES)))
    dist_info = f"{WHEEL_NAME}-{version}.dist-info"
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
    native = f"abstraction/ipc/_native/{library_filename}"
    if native not in contents or not contents[native]:
        raise Refused(f"{wheel_path.name} carries no non-empty {native}")
    if "abstraction/ipc/__init__.py" not in contents:
        raise Refused(f"{wheel_path.name} carries no abstraction/ipc/__init__.py")
    return version, platform_tag, sorted(contents)


def run(args):
    if args.check:
        version, platform_tag, contents = check(Path(args.check).resolve())
        print(f"ok    {Path(args.check).name}: {NAME} {version} {platform_tag}")
        for path in contents:
            print(f"        {path}")
        return 0
    if not VERSION.match(args.version):
        raise Refused("--version must be MAJOR.MINOR.PATCH with an optional prerelease suffix")
    platform_tag = args.platform or host_platform()
    library = Path(args.library).resolve()
    if not library.is_file():
        raise Refused(f"--library must name an existing file: {library}")
    package = Path(args.package or ROOT / DEFAULT_PACKAGE).resolve()
    if not (package / "pyproject.toml").is_file():
        raise Refused(f"no pyproject.toml at {package}")
    license_file = Path(args.license or ROOT / "LICENSE").resolve()
    output = Path(args.output).resolve()

    target, files = assemble(args.version, platform_tag, library, package, license_file, output)
    version, checked_tag, _ = check(target)
    if (version, checked_tag) != (args.version, platform_tag):
        raise Refused(f"{target.name}: built as {version} {checked_tag}, expected {args.version} {platform_tag}")

    print(f"\n{NAME} {args.version} {platform_tag}")
    print(f"  {target.name}  {target.stat().st_size} bytes  sha256 {hashlib.sha256(target.read_bytes()).hexdigest()}")
    for path in files:
        print(f"    {path}")
    print(f"\n1 wheel in {output}. Nothing was published.")
    return 0


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
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
