#!/usr/bin/env python3
"""Build one showcase application's own per-user MSI (installer/apps/app.wxs).

The package installs the files of the release's application ZIP under
%LOCALAPPDATA%\\OpenAbstractions\\apps\\<app-id>, carries the application's
manifest (adopters/<app>/application-manifest.json: the Facade's
ApplicationDescriptor in its wire form, whose paths name {app},
{local_app_data} and {pictures}, which the OpenAbstractions Panel resolves on
the installing machine) as application-manifest.json, and starts the Panel
to register the application after install and to remove its entry before
uninstall; the person confirms both in the Panel (VISION 2026-10-06). The
package is UNSIGNED.

The ZIP's SHA-256 and size are checked against --zip-sha256 and --zip-bytes,
and the members are extracted from those verified bytes. Every member name is
a chain of plain Windows file-name segments: no drive, separator, parent,
reserved device name (CON, NUL, COM1 and the rest, with any extension), and
no trailing dot or space. Two members the file system takes for one name,
such as names that differ only by case on Windows, are refused. Release
values the manifest names as @name@ (such as @records_sha256@) come from
--define name=value; a manifest with an @name@ left over is refused. The upgrade code is derived from the application ID, so
every version of one application upgrades the one before.

Usage:
  build_app.py --app-id ID --title TITLE --publisher NAME --version X.Y.Z
               --zip FILE --zip-sha256 HEX --zip-bytes N --manifest FILE --out DIR
               [--define NAME=VALUE ...] [--wix wix]

Without arguments, prints this text.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
APP_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
MSI_VERSION = re.compile(r"(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DEFINE = re.compile(r"([a-z][a-z0-9_]{0,63})=([0-9A-Za-z._-]{1,256})\Z")
RELEASE_VALUE = re.compile(r"@([a-z][a-z0-9_]{0,63})@")
# One member-name segment: a Windows file name with no drive, separator or
# reserved character, not made of dots alone, and with no trailing dot or
# space.
MEMBER_SEGMENT = re.compile(r'(?!\.+\Z)[^<>:"/\\|?*\x00-\x1f]*[^<>:"/\\|?*\x00-\x1f. ]\Z')
# A reserved device name, with or without an extension (superscript digits
# included, as Windows reserves them).
DEVICE_NAME = re.compile(r"(CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]|CONIN\$|CONOUT\$)(\..*)?\Z", re.I)
MANIFEST_FIELDS = {"name", "program", "title", "start_guidance", "activation"}
MANIFEST_NAME = "application-manifest.json"


def upgrade_code(app_id: str) -> str:
    """The application's fixed MSI upgrade code."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "https://openabstractions.org/apps/" + app_id))


def verified_zip(path: Path, sha256: str, size: int) -> bytes:
    """The archive's bytes, once they are the pinned ones."""
    data = path.read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError(f"{path.name} is not the pinned archive ({len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()})")
    return data


def member_segments(name: str) -> list[str]:
    """A member name's segments, or ValueError when one is no plain Windows
    file name."""
    segments = name.replace("\\", "/").rstrip("/").split("/")
    for segment in segments:
        if not MEMBER_SEGMENT.match(segment) or DEVICE_NAME.match(segment):
            raise ValueError(f"archive member {name!r} is not a plain path inside the payload folder")
    return segments


def extract(data: bytes, into: Path) -> int:
    """Extract every member of the verified archive bytes inside into, a fresh
    folder. Every name is checked before anything is written. Each file is
    created exclusively, so two members the file system takes for one name
    (such as names that differ only by case on Windows) are refused when the
    second is written; the build then fails and the payload is rebuilt."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        targets = [into.joinpath(*member_segments(member.filename)) for member in members]
        count = 0
        for member, target in zip(members, targets):
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with archive.open(member) as source, open(target, "xb") as sink:
                    shutil.copyfileobj(source, sink)
            except FileExistsError as error:
                raise ValueError(f"archive member {member.filename!r} names a file another member already wrote") from error
            count += 1
    return count


def filled_manifest(path: Path, app_id: str, defines: dict[str, str]) -> str:
    """The manifest text with its @name@ release values filled, checked for
    shape; the Panel applies the Facade's full check before it shows it."""
    text = path.read_text(encoding="utf-8")
    missing = sorted({m.group(1) for m in RELEASE_VALUE.finditer(text)} - set(defines))
    if missing:
        raise ValueError("the manifest names release values no --define gives: " + ", ".join(missing))
    text = RELEASE_VALUE.sub(lambda m: defines[m.group(1)], text)
    manifest = json.loads(text)
    if not isinstance(manifest, dict) or not set(manifest) <= MANIFEST_FIELDS or \
            not {"name", "program", "title"} <= set(manifest):
        raise ValueError("the manifest is not an application manifest (name, program, title, start_guidance, activation)")
    if manifest["name"] != app_id:
        raise ValueError(f"the manifest names {manifest['name']!r}, not the application {app_id!r}")
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_app.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app-id")
    parser.add_argument("--title")
    parser.add_argument("--publisher")
    parser.add_argument("--version")
    parser.add_argument("--zip", type=Path)
    parser.add_argument("--zip-sha256")
    parser.add_argument("--zip-bytes", type=int)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--define", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--wix", default="wix")
    args = parser.parse_args(argv)
    required = ("app_id", "title", "publisher", "version", "zip", "zip_sha256", "zip_bytes", "manifest", "out")
    if all(getattr(args, name) is None for name in required):
        parser.print_help()
        return 0
    missing = [name for name in required if getattr(args, name) is None]
    if missing:
        parser.error("missing " + ", ".join("--" + name.replace("_", "-") for name in missing))
    if not APP_ID.match(args.app_id) or not MSI_VERSION.match(args.version) or not SHA256.match(args.zip_sha256):
        parser.error("--app-id, --version (X.Y.Z) or --zip-sha256 is malformed")
    defines = {}
    for define in args.define:
        m = DEFINE.match(define)
        if not m or m.group(1) in defines:
            parser.error(f"--define {define!r} is not one NAME=VALUE of plain characters")
        defines[m.group(1)] = m.group(2)
    out = args.out.resolve()
    try:
        data = verified_zip(args.zip, args.zip_sha256, args.zip_bytes)
        manifest_text = filled_manifest(args.manifest, args.app_id, defines)
        payload = out / "payload"
        if payload.exists():
            shutil.rmtree(payload)
        payload.mkdir(parents=True)
        files = extract(data, payload)
        manifest = out / MANIFEST_NAME
        manifest.write_text(manifest_text, encoding="utf-8", newline="\n")
    except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        print("FAIL ", error)
        return 1
    msi = out / f"{args.app_id}-{args.version}.msi"
    command = [args.wix, "build", "-arch", "x64",
               "-d", f"AppId={args.app_id}", "-d", f"AppTitle={args.title}", "-d", f"Publisher={args.publisher}",
               "-d", f"Version={args.version}", "-d", f"UpgradeCode={upgrade_code(args.app_id)}",
               "-d", f"Payload={payload}", "-d", f"Manifest={manifest}",
               "-o", str(msi), str(HERE / "app.wxs")]
    print(" ".join(command))
    if subprocess.run(command, cwd=out).returncode:
        return 1
    print(f"ok    {msi.name} {msi.stat().st_size} bytes, {files} files, UNSIGNED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
