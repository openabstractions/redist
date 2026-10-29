"""Exact, bounded Node-API build inputs for the Windows addon producer.

The release job may download these inputs only when an owner dispatches it.
Local inspection and app packaging use the same archive pins without network.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request
import zipfile


NODE_VERSION = "22.23.3"
HEADERS_VERSION = "1.9.0"
HEADERS_NAME = f"node-api-headers-{HEADERS_VERSION}.tgz"
HEADERS_URL = f"https://registry.npmjs.org/node-api-headers/-/{HEADERS_NAME}"
HEADERS_SHA256 = "6cbfac49542194ae2c8f1dee5fa2dc00d66bec9cbf3b59e3a4e5f16d14eb0d19"
NODE_WINDOWS_NAME = f"node-v{NODE_VERSION}-win-x64.zip"
NODE_WINDOWS_URL = f"https://nodejs.org/dist/v{NODE_VERSION}/{NODE_WINDOWS_NAME}"
NODE_WINDOWS_SHA256 = "2b0ff57b049cda1bbcea2240eec20467018713c1efe1f7360c2681859b90ed71"
NODE_LIBRARY_NAME = f"node-v{NODE_VERSION}-win-x64.lib"
NODE_LIBRARY_URL = f"https://nodejs.org/dist/v{NODE_VERSION}/win-x64/node.lib"
NODE_LIBRARY_SHA256 = "c243185f2347870cadb637c909bf123fc703dc65dbfa769b17ec45a4b661d782"
NODE_LIBRARY_SIZE = 2_790_906
NODE_LIBRARY_LIMIT = 4 << 20
HEADER_FILES = ("js_native_api.h", "js_native_api_types.h", "node_api.h", "node_api_types.h")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def checked_archive(path: Path, expected: str, limit: int) -> None:
    if not path.is_file() or not 0 < path.stat().st_size <= limit or digest(path) != expected:
        raise ValueError("Node build input is missing, oversized or differs from reviewed SHA-256: " + str(path))


def download(url: str, target: Path, expected: str, limit: int) -> None:
    if target.exists():
        checked_archive(target, expected, limit)
        return
    partial = target.with_name(target.name + ".partial")
    if partial.exists():
        raise FileExistsError("unfinished Node build input already exists: " + str(partial))
    value, size = hashlib.sha256(), 0
    try:
        with urllib.request.urlopen(url, timeout=120) as response, partial.open("xb") as output:
            while block := response.read(1 << 20):
                size += len(block)
                if size > limit:
                    raise ValueError("Node build input exceeds reviewed byte cap: " + url)
                value.update(block)
                output.write(block)
        if value.hexdigest() != expected:
            raise ValueError("Node build input differs from reviewed SHA-256: " + url)
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)


def inspect(root: Path, windows: bool) -> dict:
    """Validate archives and return extracted bytes plus an auditable input receipt."""
    root = Path(root)
    headers = root / HEADERS_NAME
    checked_archive(headers, HEADERS_SHA256, 1 << 20)
    with tarfile.open(headers, "r:gz") as archive:
        include = {name: archive.extractfile("package/include/" + name).read()
                   for name in HEADER_FILES}
        license_text = archive.extractfile("package/LICENSE").read()
    if not all(include.values()) or not license_text.startswith(b"MIT License"):
        raise ValueError("Node-API header archive lacks exact headers or MIT notice")
    receipt = {"nodeVersion": NODE_VERSION, "nodeApiHeadersVersion": HEADERS_VERSION,
               "nodeApiHeadersUrl": HEADERS_URL, "nodeApiHeadersSha256": HEADERS_SHA256}
    if windows:
        bundle = root / NODE_WINDOWS_NAME
        checked_archive(bundle, NODE_WINDOWS_SHA256, 48 << 20)
        library = root / NODE_LIBRARY_NAME
        checked_archive(library, NODE_LIBRARY_SHA256, NODE_LIBRARY_LIMIT)
        if library.stat().st_size != NODE_LIBRARY_SIZE:
            raise ValueError("official Node import library differs from reviewed byte count")
        with zipfile.ZipFile(bundle) as archive:
            member = f"node-v{NODE_VERSION}-win-x64/node.exe"
            if member not in archive.namelist():
                raise ValueError("official Node runtime archive lacks the exact-version executable")
        node_lib = library.read_bytes()
        if not node_lib.startswith(b"!<arch>\n"):
            raise ValueError("official Node import library has an invalid archive header")
        receipt.update({"nodeArchiveUrl": NODE_WINDOWS_URL,
                        "nodeArchiveSha256": NODE_WINDOWS_SHA256,
                        "nodeImportLibraryUrl": NODE_LIBRARY_URL,
                        "nodeImportLibrarySha256": NODE_LIBRARY_SHA256,
                        "nodeImportLibrarySizeBytes": NODE_LIBRARY_SIZE,
                        "nodeShasumsUrl": f"https://nodejs.org/dist/v{NODE_VERSION}/SHASUMS256.txt"})
    else:
        node_lib = None
    return {"headers": include, "license": license_text, "nodeLib": node_lib, "receipt": receipt}


def prepare(root: Path, windows: bool) -> dict:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    download(HEADERS_URL, root / HEADERS_NAME, HEADERS_SHA256, 1 << 20)
    if windows:
        download(NODE_WINDOWS_URL, root / NODE_WINDOWS_NAME, NODE_WINDOWS_SHA256, 48 << 20)
        download(NODE_LIBRARY_URL, root / NODE_LIBRARY_NAME, NODE_LIBRARY_SHA256, NODE_LIBRARY_LIMIT)
    inspected = inspect(root, windows)
    include = root / "node-api-headers/include"
    if include.exists() or (root / "node.lib").exists():
        raise FileExistsError("extracted Node build inputs already exist")
    include.mkdir(parents=True)
    for name, data in inspected["headers"].items():
        (include / name).write_bytes(data)
    (include.parent / "LICENSE").write_bytes(inspected["license"])
    if windows:
        (root / "node.lib").write_bytes(inspected["nodeLib"])
    (root / "receipt.json").write_text(json.dumps(inspected["receipt"], sort_keys=True) + "\n", encoding="utf-8")
    return inspected["receipt"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--windows", action="store_true")
    args = parser.parse_args(argv)
    print(json.dumps(prepare(args.output_root, args.windows), sort_keys=True))


if __name__ == "__main__":
    main()
