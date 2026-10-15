#!/usr/bin/env python3
"""Inspect an unpublished OA app/source ZIP pair without executing the app.

The receipt records measured bytes, corresponding-source binding, licence
inventory, and absolute builder paths. A producer can attach this JSON beside
its two ZIPs; a reviewer can inspect local candidates before public pinning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile


WINDOWS_BUILD_PATHS = (
    re.compile(rb"[A-Za-z]:\\(?:Users|a)\\[^\x00\r\n\"']{1,256}", re.I),
    re.compile(rb"[A-Za-z]:\\\\(?:Users|a)\\\\[^\x00\r\n\"']{1,256}", re.I),
    re.compile(rb"[A-Za-z]:/(?:Users|a)/[^\x00\r\n\"']{1,256}", re.I),
)
NOTICE = re.compile(r"(?:^|/)(?:[^/]*licen[cs]e[^/]*|[^/]*copying[^/]*|[^/]*notice[^/]*)$", re.I)
SCANNED_SUFFIXES = frozenset((".exe", ".dll", ".pyd", ".node", ".js", ".cjs", ".mjs",
                              ".json", ".ts", ".tsx", ".py", ".pth", ".cfg", ".ini",
                              ".yaml", ".yml", ".toml", ".ps1", ".bat", ".cmd"))


def digest(path: Path) -> tuple[int, str]:
    sha = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            sha.update(chunk)
            size += len(chunk)
    return size, sha.hexdigest()


def checked_zip(path: Path) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(path)
    names = archive.namelist()
    if len(names) != len(set(names)) or archive.testzip() is not None:
        archive.close()
        raise ValueError(f"duplicate or corrupt ZIP member in {path}")
    return archive


def builder_paths(data: bytes) -> list[str]:
    # Bundlers emit escaped JS literals; native binaries can contain raw paths.
    # Either form may affect relative-file lookups at run time.
    return sorted({match.group().decode("utf-8", "replace")
                   for pattern in WINDOWS_BUILD_PATHS for match in pattern.finditer(data)})


def archive_builder_paths(archive: zipfile.ZipFile) -> dict[str, list[str]]:
    found = {}
    for member in archive.infolist():
        if member.is_dir() or Path(member.filename).suffix.lower() not in SCANNED_SUFFIXES:
            continue
        paths = set()
        with archive.open(member) as stream:
            previous = b""
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                paths.update(builder_paths(previous + chunk))
                previous = chunk[-512:]
        if paths:
            found[member.filename] = sorted(paths)
    return found


def inspect(app: str, binary: Path, source: Path, *, require_clean_paths: bool = False) -> dict[str, object]:
    binary_bytes, binary_sha = digest(binary)
    source_bytes, source_sha = digest(source)
    if not 0 < binary_bytes < (2 << 30) or not 0 < source_bytes < (2 << 30):
        raise ValueError("both app and source ZIPs must fit the release asset limit")
    with checked_zip(source) as source_zip, checked_zip(binary) as binary_zip:
        source_members = source_zip.namelist()
        names = binary_zip.namelist()
        notices = sorted(name for name in names if NOTICE.search(name) and not name.endswith("/"))
        if not notices:
            raise ValueError("app ZIP contains no licence or notice files")
        if app != "comfyui":
            raise ValueError("app must be comfyui")
        manifest = json.loads(binary_zip.read("OA-PROVENANCE.json"))
        if (manifest.get("corresponding_comfyui_source_zip") != source.name
                or manifest.get("corresponding_comfyui_source_zip_sha256") != source_sha):
            raise ValueError("ComfyUI provenance does not bind this source ZIP")
        if manifest.get("variant") != "oa-comfyui-cpu-frontend":
            raise ValueError("ComfyUI app is not the reviewed CPU frontend variant")
        if "OA-LICENSES/OpenAbstractions-LICENSE" not in names or not any(
                name.startswith("ComfyUI-" + manifest["comfyui_source_commit"] + "/")
                for name in source_members):
            raise ValueError("ComfyUI source or OA node licence is missing")
        for name in manifest.get("preserved_notice_paths", []) + manifest.get("added_notice_paths", []):
            if name not in names:
                raise ValueError("ComfyUI recorded license or notice is missing: " + name)
        for path in manifest.get("oa_integration_corresponding_source_paths", []):
            if path.endswith("/"):
                if not any(name.startswith(path) for name in source_members):
                    raise ValueError("OA integration source tree is missing: " + path)
            elif path not in source_members:
                raise ValueError("OA integration source file is missing: " + path)
        if manifest.get("oa_integration") and not {
                "OA-Integration-Source/node/abstraction_downloads/__init__.py",
                "OA-Integration-Source/LICENSE", "OA-Integration-Source/manifest.json"}.issubset(
                    set(manifest.get("oa_integration_corresponding_source_paths", []))):
            raise ValueError("OA integration corresponding source is not recorded in the pair")
        paths = archive_builder_paths(binary_zip)
        identity = {"version": "0.35.0-oa.0.4.0", "upstream_commit": manifest["comfyui_source_commit"],
                    "records_sha256": manifest["private_python_records_sha256"],
                    "integration_sha256": manifest["oa_integration"]["sha256"]}
        if require_clean_paths and paths:
            raise ValueError("app payload embeds unreviewed absolute builder paths: " + ", ".join(paths))
        return {"schema": 1, "status": "unpublished-candidate", "app": app,
                "binary": {"name": binary.name, "bytes": binary_bytes, "sha256": binary_sha},
                "source": {"name": source.name, "bytes": source_bytes, "sha256": source_sha},
                "identity": identity, "binary_member_count": len(names),
                "source_member_count": len(source_members), "license_and_notice_paths": notices,
                "embedded_builder_paths": paths, "unreviewed_builder_paths": paths}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=("comfyui",), required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--require-clean-paths", action="store_true",
                        help="release gate: refuse any embedded absolute builder path")
    parser.add_argument("--output", type=Path, help="write JSON receipt instead of printing it")
    args = parser.parse_args()
    receipt = inspect(args.app, args.binary, args.source, require_clean_paths=args.require_clean_paths)
    serialized = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
