#!/usr/bin/env python3
"""Fetch the pinned WiX 5.0.2 packages from nuget.org and check them.

Each package is downloaded from its nuget.org URL into --dest and refused
unless its size and SHA-256 are the recorded ones. Each extension's DLL is
unpacked beside its package and refused unless its size and SHA-256 are the
recorded ones too. The owner approved these three packages (2026-10-06).

Prints NAME=VALUE lines, and with --env appends them to that file (a GitHub
Actions GITHUB_ENV):
  WIX_SOURCE   the folder holding wix.5.0.2.nupkg
  WIX_NUGET_CONFIG
               nuget.config in that folder, whose only package source is the
               folder (<clear/> first), for
               `dotnet tool install --global wix --version 5.0.2 --configfile`
  WIX_UI_EXT   WixToolset.UI.wixext.dll, for `wix build -ext`
  WIX_BAL_EXT  WixToolset.BootstrapperApplications.wixext.dll, for `wix build -ext`

With --from DIR, the packages are copied from DIR instead of downloaded, and
checked the same way.

Usage:
  wix_packages.py --dest DIR [--env FILE] [--from DIR]

Without arguments, prints this text.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile


def embedded_wixlib(dll: bytes) -> zipfile.ZipFile:
    """The bootstrapper wixlib the extension DLL carries as a resource: a ZIP
    whose end record is the last one in the DLL."""
    end = dll.rfind(b"PK\x05\x06")
    if end < 0:
        raise ValueError("the extension DLL carries no wixlib")
    comment = int.from_bytes(dll[end + 20:end + 22], "little")
    return zipfile.ZipFile(io.BytesIO(dll[:end + 22 + comment]))

NUGET = "https://api.nuget.org/v3-flatcontainer/"
PACKAGES = {
    "wix": {
        "file": "wix.5.0.2.nupkg",
        "url": NUGET + "wix/5.0.2/wix.5.0.2.nupkg",
        "bytes": 4587200,
        "sha256": "f30ef0c74e2a986126539c5780be93ac24e8136eaf723b1937b26272703ae173",
        "env": "WIX_SOURCE",
    },
    "WixToolset.UI.wixext": {
        "file": "wixtoolset.ui.wixext.5.0.2.nupkg",
        "url": NUGET + "wixtoolset.ui.wixext/5.0.2/wixtoolset.ui.wixext.5.0.2.nupkg",
        "bytes": 795434,
        "sha256": "5ef2c707614b9f70b6bbadd2d4abcb4124efee215e9b16bfbc80113079a604c7",
        "dll": "wixext5/WixToolset.UI.wixext.dll",
        "dll_bytes": 773392,
        "dll_sha256": "5ce7f958b6a2b57bcb98c19615c5a3da46976a6e78a6af055fdef99e9e9e8f06",
        "env": "WIX_UI_EXT",
    },
    "WixToolset.Bal.wixext": {
        "file": "wixtoolset.bal.wixext.5.0.2.nupkg",
        "url": NUGET + "wixtoolset.bal.wixext/5.0.2/wixtoolset.bal.wixext.5.0.2.nupkg",
        "bytes": 1689093,
        "sha256": "22422b50a925477e33c2b5f78d2965a9a09c6622d17ba5aa5365b20ec662b7c8",
        "dll": "wixext5/WixToolset.BootstrapperApplications.wixext.dll",
        "dll_bytes": 1688848,
        "dll_sha256": "e542eec71f8e97a3d355b7ac050cafff0822fc8d20ddeabf55c5c40c1e961827",
        "env": "WIX_BAL_EXT",
    },
}


def pinned(data: bytes, size: int, sha256: str, what: str) -> bytes:
    """The bytes, once they are the recorded ones."""
    digest = hashlib.sha256(data).hexdigest()
    if (len(data), digest) != (size, sha256):
        raise ValueError(f"{what} is not the pinned file ({len(data)} bytes, sha256 {digest})")
    return data


def _closed_members(archive: zipfile.ZipFile, *, count: int, total: int) -> dict:
    """Bound a source ZIP without extracting or following any member path."""
    members = archive.infolist()
    if len(members) > count or sum(item.file_size for item in members) > total:
        raise ValueError("WiX source archive exceeds its bounds")
    result = {}
    for item in members:
        name = item.filename
        if (not name or "\\" in name or ":" in name or name.startswith("/")
                or any(part in ("", ".", "..") for part in name.split("/"))
                or (item.external_attr >> 16) & 0o170000 == 0o120000):
            raise ValueError("unsafe WiX source member path")
        if name in result:
            raise ValueError("duplicate WiX source member")
        result[name] = item
    return result


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate WiX source JSON member")
        result[key] = value
    return result


def ui_source_resources(package_path: Path, *, architecture: str,
                        required_ids: list[str]) -> dict[str, dict]:
    """Read selected Binary source bytes from the pinned WiX UI package.

    Rows contain data (bytes), sha256, bytes (length), embedded_path and the
    source/override ancestry in wix-ir.json. The caller owns Product.wxs
    variable overrides and Icon inputs. No MSI or signature verdict is read.
    This module is standalone and may be loaded by path in an app producer.
    """
    platforms = {"x64": "X64", "x86": "X86", "arm64": "A64"}
    if architecture not in platforms:
        raise ValueError("unknown WiX UI architecture")
    if (not isinstance(required_ids, list) or not required_ids
            or any(not isinstance(item, str) or not item for item in required_ids)
            or len(required_ids) != len(set(required_ids)) or len(required_ids) > 16):
        raise ValueError("WiX UI resource IDs must be a bounded unique list")
    for name in required_ids:
        if name.startswith("WixUiCa_") and name != "WixUiCa_" + platforms[architecture]:
            raise ValueError("WiX UI custom action architecture differs")
    package = PACKAGES["WixToolset.UI.wixext"]
    path = Path(package_path)
    if path.stat().st_size != package["bytes"]:
        raise ValueError("WiX UI package size differs from its pin")
    data = pinned(path.read_bytes(), package["bytes"], package["sha256"], str(path))
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as outer:
            members = _closed_members(outer, count=32, total=8 << 20)
            if package["dll"] not in members:
                raise ValueError("WiX UI package has no declared DLL")
            dll = pinned(outer.read(members[package["dll"]]), package["dll_bytes"],
                         package["dll_sha256"], package["dll"])
        with embedded_wixlib(dll) as archive:
            members = _closed_members(archive, count=64, total=8 << 20)
            if "wix-ir.json" not in members or members["wix-ir.json"].file_size > 4 << 20:
                raise ValueError("WiX UI source JSON missing or too large")
            tree = json.loads(archive.read(members["wix-ir.json"]),
                              object_pairs_hook=_unique_json_object)
            sections = tree.get("sections")
            if not isinstance(sections, list) or len(sections) > 128:
                raise ValueError("WiX UI sections missing or too numerous")
            symbols = []
            for section in sections:
                rows = section.get("symbols")
                if not isinstance(rows, list) or len(rows) > 10000:
                    raise ValueError("WiX UI symbols missing or too numerous")
                symbols.extend(rows)
            if len(symbols) > 10000:
                raise ValueError("WiX UI symbols exceed their bound")
            declared = {}
            for symbol in symbols:
                if symbol.get("type") != "Binary":
                    continue
                name = symbol["id"]["id"]
                if name in declared:
                    raise ValueError("duplicate WiX UI Binary ID")
                declared[name] = symbol
            result = {}
            for name in required_ids:
                if name not in declared:
                    raise ValueError("unknown WiX UI Binary ID: " + name)
                symbol = declared[name]
                fields = symbol["fields"]
                if not isinstance(fields, list) or len(fields) != 1:
                    raise ValueError("unexpected WiX UI Binary fields")
                field = fields[0]
                embedded = field["data"]
                member = embedded["path"]
                if embedded.get("embed") != "true" or member not in members:
                    raise ValueError("WiX UI Binary has no embedded source member")
                raw = archive.read(members[member])
                result[name] = {"id": name, "data": raw, "bytes": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest(),
                                "embedded_path": member, "source": symbol.get("ln"),
                                "override": field.get("prev")}
            return result
    except (zipfile.BadZipFile, KeyError, TypeError, AttributeError,
            json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise ValueError("invalid WiX UI source resource structure") from error


def nuget_config(folder: Path) -> str:
    """A NuGet configuration whose one package source is the checked folder:
    <clear/> drops nuget.org and every inherited source, so
    `dotnet tool install --configfile` cannot resolve wix from anywhere else."""
    root = ET.Element("configuration")
    sources = ET.SubElement(root, "packageSources")
    ET.SubElement(sources, "clear")
    ET.SubElement(sources, "add", {"key": "oa-pinned-wix", "value": str(folder)})
    ET.indent(root)
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def fetch(name: str, dest: Path, source: Path | None = None) -> dict[str, str]:
    """Place one pinned package in dest and return its NAME=VALUE lines."""
    package = PACKAGES[name]
    if source is None:
        with urllib.request.urlopen(package["url"], timeout=120) as response:
            data = response.read(package["bytes"] + 1)
    else:
        data = (source / package["file"]).read_bytes()
    pinned(data, package["bytes"], package["sha256"], package["file"])
    dest.mkdir(parents=True, exist_ok=True)
    (dest / package["file"]).write_bytes(data)
    if "dll" not in package:
        config = dest / "nuget.config"
        config.write_text(nuget_config(dest.resolve()), encoding="utf-8", newline="\n")
        return {package["env"]: str(dest.resolve()), "WIX_NUGET_CONFIG": str(config.resolve())}
    with zipfile.ZipFile(dest / package["file"]) as archive:
        dll = pinned(archive.read(package["dll"]), package["dll_bytes"], package["dll_sha256"], package["dll"])
    folder = dest / name
    folder.mkdir(exist_ok=True)
    target = folder / Path(package["dll"]).name
    target.write_bytes(dll)
    return {package["env"]: str(target.resolve())}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wix_packages.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", type=Path)
    parser.add_argument("--env", type=Path)
    parser.add_argument("--from", dest="source", type=Path)
    args = parser.parse_args(argv)
    if args.dest is None:
        if args.env is None and args.source is None:
            parser.print_help()
            return 0
        parser.error("--dest is required")
    found: dict[str, str] = {}
    if args.dest.exists() and any(args.dest.iterdir()):
        print(f"FAIL  {args.dest} is not empty")
        return 1
    try:
        for name in PACKAGES:
            found.update(fetch(name, args.dest, args.source))
            print(f"ok    {PACKAGES[name]['file']} {PACKAGES[name]['bytes']} bytes sha256 {PACKAGES[name]['sha256']}")
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print("FAIL ", error)
        shutil.rmtree(args.dest, ignore_errors=True)
        return 1
    lines = "".join(f"{key}={value}\n" for key, value in found.items())
    print(lines, end="")
    if args.env is not None:
        with args.env.open("a", encoding="utf-8") as env:
            env.write(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
