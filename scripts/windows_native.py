"""Inspect Windows IPC DLL imports before assembling offline packages.

This checks the PE's direct imports, including delayed imports. It does not
prove that every operating-system DLL exists on a particular Windows release.
"""

import re
import struct
from pathlib import Path


class NativeDependencyError(ValueError):
    pass


MACHINES = {"win_amd64": 0x8664, "win32-x64": 0x8664,
            "win_arm64": 0xaa64, "win32-arm64": 0xaa64}
COMPILER_RUNTIME = re.compile(
    r"^(?:msvcp\d+(?:_\d+)?|vcruntime\d+(?:_\d+)?|msvcr\d+|"
    r"ucrtbased|libgcc[^.]*|libstdc\+\+[^.]*|libwinpthread[^.]*)\.dll$",
    re.IGNORECASE,
)
SYSTEM_IMPORTS = {"advapi32.dll", "kernel32.dll", "msi.dll"}
# MinGW's statically linked C++ runtime still uses Windows' UCRT API sets.
# These are Windows 10 system contracts, not bundled compiler DLLs.
SYSTEM_API_SET = {f"api-ms-win-crt-{name}-l1-1-0.dll" for name in (
    "convert", "environment", "filesystem", "heap", "locale", "private",
    "runtime", "stdio", "string", "utility",
)}


def validate_portable_windows_dll(library, platform):
    """Return direct imported DLL names; refuse a wrong-arch or dynamic compiler CRT DLL."""
    expected = MACHINES.get(platform)
    if expected is None:
        raise NativeDependencyError(f"unknown Windows IPC platform {platform}")
    data = library if isinstance(library, bytes) else Path(library).read_bytes()

    def u16(at):
        return struct.unpack_from("<H", data, at)[0]

    def u32(at):
        return struct.unpack_from("<I", data, at)[0]

    try:
        if data[:2] != b"MZ":
            raise NativeDependencyError("IPC library is not a PE DLL")
        pe = u32(0x3c)
        if data[pe:pe + 4] != b"PE\0\0":
            raise NativeDependencyError("IPC library has no PE signature")
        coff = pe + 4
        machine, sections, optional_size, characteristics = (
            u16(coff), u16(coff + 2), u16(coff + 16), u16(coff + 18))
        if machine != expected or not characteristics & 0x2000:
            raise NativeDependencyError(f"IPC library is not a {platform} DLL (machine {machine:#x})")
        optional = coff + 20
        magic = u16(optional)
        if magic not in (0x10b, 0x20b):
            raise NativeDependencyError("IPC library has an unknown PE optional header")
        directories = optional + (112 if magic == 0x20b else 96)
        if optional_size < directories - optional + 14 * 8:
            raise NativeDependencyError("IPC library has a truncated PE data directory")
        section_table = optional + optional_size
        ranges = []
        for index in range(sections):
            entry = section_table + index * 40
            virtual_size, virtual_address, raw_size, raw_pointer = (
                u32(entry + 8), u32(entry + 12), u32(entry + 16), u32(entry + 20))
            ranges.append((virtual_address, max(virtual_size, raw_size), raw_pointer, raw_size))

        def offset(rva, count=1):
            for address, span, raw, raw_size in ranges:
                displacement = rva - address
                if 0 <= displacement and displacement + count <= min(span, raw_size):
                    result = raw + displacement
                    if result + count <= len(data):
                        return result
            raise NativeDependencyError(f"IPC library has invalid PE import RVA {rva:#x}")

        def name(rva):
            start = offset(rva)
            end = data.find(b"\0", start, min(len(data), start + 256))
            if end < 0:
                raise NativeDependencyError("IPC library has an unterminated import name")
            return data[start:end].decode("ascii")

        imports = []
        # Standard import descriptors are 20 bytes. Delay import descriptors
        # are 32 bytes; their name field is the second DWORD.
        for directory_index, entry_size, name_field in ((1, 20, 12), (13, 32, 4)):
            rva, size = u32(directories + directory_index * 8), u32(directories + directory_index * 8 + 4)
            if not rva:
                continue
            if not size or size > 1 << 20:
                raise NativeDependencyError("IPC library has an invalid PE import directory")
            for position in range(0, size, entry_size):
                entry = offset(rva + position, entry_size)
                if data[entry:entry + entry_size] == b"\0" * entry_size:
                    break
                if directory_index == 13 and not u32(entry) & 1:
                    raise NativeDependencyError("IPC library has an unsupported VA-based delay import")
                imports.append(name(u32(entry + name_field)))
            else:
                raise NativeDependencyError("IPC library has no import directory terminator")
        if not imports:
            raise NativeDependencyError("IPC library has no inspectable Windows DLL imports")
    except (IndexError, struct.error, UnicodeDecodeError) as exc:
        raise NativeDependencyError("IPC library has a malformed PE import table") from exc

    compiler = sorted({item for item in imports if COMPILER_RUNTIME.fullmatch(item)})
    if compiler:
        raise NativeDependencyError("IPC library imports unbundled compiler runtimes: " + ", ".join(compiler))
    unknown = sorted({item for item in imports
                      if item.casefold() not in SYSTEM_IMPORTS | SYSTEM_API_SET})
    if unknown:
        raise NativeDependencyError("IPC library imports unqualified DLLs: " + ", ".join(unknown))
    return tuple(imports)
