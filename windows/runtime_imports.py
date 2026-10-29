"""Refuse a shipped Windows program or library that imports a Microsoft
Visual C++ runtime DLL it does not carry beside it.

  py -3.12 installer/runtime_imports.py PATH [PATH ...]

Each PATH is a folder (searched recursively), a ZIP (its members) or one
file. Every PE image there (a file that starts with "MZ"), and every member
of a ZIP found in a folder, is read for its import and delay-import tables.
A file that imports a Visual C++ runtime DLL must have that DLL in its own
folder (for a ZIP, among the members of the same folder): a clean Windows
has no such runtime, and the program then fails to start with 0xC0000135
(STATUS_DLL_NOT_FOUND).

The runtime family is matched the way the Windows loader matches module
names, without regard to case: vcruntime140*, msvcp140*, concrt140*,
vcomp140*, vccorlib140*, mfc140*, mfcm140*, vcamp140* (release and debug)
and the debug Universal CRT ucrtbased.dll. Whether the DLL is beside the
file is asked of the filesystem (folder\\<name as imported>); inside a ZIP,
members of the same folder are matched by the loader's rule. The release
Universal CRT (ucrtbase.dll, api-ms-win-crt-*) is part of Windows 10 and
later and is not checked.

A folder link (junction or symbolic link) is reported, not followed, and a
file that starts with "MZ" but is no readable PE image is refused: either
fails the check.

Exit 0: every file carries what it imports. Exit 1: one line per finding.
Exit 2: usage. installer/build.py runs it over the core payload and the
engine bundles it stages; the OpenCode package build runs it over its
payload; scripts/build_node_addon.py runs it over the add-on it builds.
Components staged later (the Lemonade engine, PyTorch's Python and wheels,
TheNoise's engine) are scanned the same way where they are staged.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import struct
import sys
from typing import Callable, NamedTuple
import zipfile

# The Visual C++ runtime family by module name, case-insensitive as the
# loader compares module names.
RUNTIME = re.compile(r"(?:(?:vcruntime140|msvcp140|concrt140|vcomp140|vccorlib140|mfc140|mfcm140|vcamp140)\w*|ucrtbased)\.dll",
                     re.IGNORECASE)


class Malformed(ValueError):
    """A file that starts with "MZ" but whose PE headers cannot be read."""


def imports(data: bytes) -> list[str]:
    """The DLL names a PE image imports, directly or delay-loaded, as the
    import tables spell them. Raises Malformed for a truncated or malformed
    image."""
    if data[:2] != b"MZ":
        return []
    if len(data) < 64:
        raise Malformed("truncated DOS header")
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise Malformed("no PE signature")
        sections, optional_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
        optional = pe + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic not in (0x10B, 0x20B):
            raise Malformed(f"optional header magic {magic:#x}")
        count = struct.unpack_from("<I", data, optional + (108 if magic == 0x20B else 92))[0]
        directories = optional + (112 if magic == 0x20B else 96)
        table = optional + optional_size

        def offset(rva: int) -> int | None:
            for index in range(sections):
                size, address, raw_size, raw = struct.unpack_from("<IIII", data, table + 40 * index + 8)
                if address <= rva < address + max(size, raw_size):
                    return rva - address + raw
            return None

        names = []
        for directory, step, name_field in ((1, 20, 12), (13, 32, 4)):  # imports, delay imports
            if directory >= count:
                continue
            rva = struct.unpack_from("<I", data, directories + 8 * directory)[0]
            at = offset(rva) if rva else None
            while at is not None:
                if at + step > len(data):
                    raise Malformed("an import table runs past the end of the file")
                name_rva = struct.unpack_from("<I", data, at + name_field)[0]
                if not name_rva:
                    break
                name = offset(name_rva)
                if name is None:
                    raise Malformed("an imported name lies outside every section")
                end = data.find(b"\0", name)
                if end < 0:
                    raise Malformed("an imported name runs past the end of the file")
                names.append(data[name:end].decode("ascii", "replace"))
                at += step
        return names
    except struct.error as error:
        raise Malformed(str(error)) from None


def same_module(a: str, b: str) -> bool:
    """The Windows loader's module-name rule: names compare without regard
    to case. Used for ZIP members only; on disk the filesystem answers."""
    return a.upper() == b.upper()


class Shipped(NamedTuple):
    """One file as shipped: its name for messages, its bytes when it is a PE
    image, and how to ask whether a DLL name is beside it."""
    name: str
    data: bytes | None
    beside: Callable[[str], bool]


def pe_bytes(head: bytes, read_all: Callable[[], bytes]) -> bytes | None:
    """A file's bytes when it is a PE image (starts with "MZ"), else None."""
    return read_all() if head == b"MZ" else None


def first_two(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(2)


def on_disk(folder: str) -> Callable[[str], bool]:
    return lambda dll: os.path.isfile(os.path.join(folder, dll))


def zip_members(path: str, prefix: str) -> list[Shipped]:
    """Each member of a ZIP; a member's folder is its folder in the ZIP."""
    found: list[tuple[str, str, bytes | None]] = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            with archive.open(info) as member:
                head = member.read(2)
            folder, _, leaf = info.filename.rpartition("/")
            found.append((folder, leaf, pe_bytes(head, lambda: archive.read(info))))
    leaves: dict[str, list[str]] = {}
    for folder, leaf, _ in found:
        leaves.setdefault(folder, []).append(leaf)

    def among(folder: str) -> Callable[[str], bool]:
        return lambda dll: any(same_module(dll, leaf) for leaf in leaves.get(folder, []))

    return [Shipped(prefix + (folder + "/" if folder else "") + leaf, data, among(folder)) for folder, leaf, data in found]


def shipped_in(path: Path) -> tuple[list[Shipped], list[str]]:
    """Every file under path, and one line per folder link not followed."""
    files: list[Shipped] = []
    links: list[str] = []
    if path.is_dir():
        def walk(folder: str, prefix: str) -> None:
            with os.scandir(folder) as entries:
                for entry in entries:
                    name = prefix + entry.name
                    # DirEntry.is_junction is Python 3.12 and later.
                    if getattr(entry, "is_junction", lambda: False)() or entry.is_symlink():
                        links.append(f"{name} is a link (junction or symbolic link); what it leads to is not checked")
                    elif entry.is_dir():
                        walk(entry.path, name + "/")
                    elif entry.is_file():
                        files.append(Shipped(name, pe_bytes(first_two(entry.path), Path(entry.path).read_bytes), on_disk(folder)))
                        if zipfile.is_zipfile(entry.path):
                            files.extend(zip_members(entry.path, name + "!"))
        walk(str(path), "")
    elif zipfile.is_zipfile(path):
        files.extend(zip_members(str(path), ""))
    else:
        files.append(Shipped(path.name, pe_bytes(first_two(str(path)), path.read_bytes), on_disk(str(path.parent))))
    return files, links


def problems(path: Path) -> list[str]:
    """One line per shipped PE file and runtime DLL it imports without
    carrying, per unreadable PE image and per folder link."""
    files, links = shipped_in(path)
    lines = [f"{path}: {line}" for line in links]
    for item in sorted(files, key=lambda item: item.name):
        if not item.data:
            continue
        try:
            names = imports(item.data)
        except Malformed as error:
            lines.append(f"{path}: {item.name} starts as a PE image but cannot be read ({error})")
            continue
        for dll in sorted({name for name in names if RUNTIME.fullmatch(name)}):
            if not item.beside(dll):
                lines.append(f"{path}: {item.name} imports {dll}, which is not beside it")
    return lines


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", type=Path, help="folders, ZIPs or files to check")
    args = parser.parse_args(argv)
    lines = []
    for path in args.paths:
        if not path.exists():
            parser.error(f"{path} does not exist")
        lines.extend(problems(path))
    for line in lines:
        print("FAIL  " + line)
    if not lines:
        print("ok    every shipped program and library carries the Visual C++ runtime it imports")
    return 1 if lines else 0


if __name__ == "__main__":
    sys.exit(main())
