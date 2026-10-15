"""Derive the reviewed, tool-free ModelHost bundle from the publisher's ZIP.

The modelhostd `engine pin --json` output owns the archive, kept-file and
bundle pins. The release producer obtains it from its same-source executable.
The publisher's full archive is an input only; it never enters an OA package.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import zipfile


SOURCE_NAME = "llama-b10825-bin-win-vulkan-x64.zip"
BUNDLE_NAME = "llama-b10825-oa-win-vulkan-x64.zip"
RECEIPT_NAME = "llama-b10825-oa-win-vulkan-x64.receipt.json"
SOURCE_URL = "https://github.com/ggml-org/llama.cpp/releases/download/b10825/" + SOURCE_NAME
SOURCE_COMMIT = "9e0e220594af405a62835dc3a27495729fd8506b"
SOURCE_SIZE = 35_227_898
SOURCE_SHA256 = "8907e5f3b74cb57d93fd94e187a87d85be24dc64e3b0ff2bc1b287da17b31446"
SHA = re.compile(r"[0-9a-f]{64}\Z")
FLAT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate ModelHost pin key: " + key)
        result[key] = value
    return result


def pin(path: Path) -> dict:
    """Parse only the provider's complete, shipping pin format."""
    value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    if (not isinstance(value, dict)
            or set(value) != {"schema", "release", "program", "archive", "bundle", "files"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["release"] != "b10825" or value["program"] != "llama-server.exe"):
        raise ValueError("invalid ModelHost engine pin document")
    source, bundle, files = value["archive"], value["bundle"], value["files"]
    if (not isinstance(source, dict)
            or set(source) != {"name", "url", "source_commit", "size_bytes", "sha256"}
            or source != {"name": SOURCE_NAME, "url": SOURCE_URL,
                          "source_commit": SOURCE_COMMIT, "size_bytes": SOURCE_SIZE,
                          "sha256": SOURCE_SHA256}
            or not isinstance(bundle, dict)
            or set(bundle) != {"name", "size_bytes", "sha256"}
            or bundle["name"] != BUNDLE_NAME
            or type(bundle["size_bytes"]) is not int or bundle["size_bytes"] <= 0
            or not isinstance(bundle["sha256"], str) or not SHA.fullmatch(bundle["sha256"])
            or not isinstance(files, list) or len(files) != 24):
        raise ValueError("ModelHost engine pin differs from reviewed source or lacks bundle pin")
    names = set()
    for entry in files:
        if (not isinstance(entry, dict) or set(entry) != {"path", "size_bytes", "sha256"}
                or not isinstance(entry["path"], str) or not FLAT.fullmatch(entry["path"])
                or type(entry["size_bytes"]) is not int or entry["size_bytes"] <= 0
                or not isinstance(entry["sha256"], str) or not SHA.fullmatch(entry["sha256"])
                or entry["path"] in names):
            raise ValueError("invalid ModelHost kept-file pin")
        name = entry["path"]
        if name.endswith(".exe") and name != "llama-server.exe":
            raise ValueError("ModelHost bundle includes an unreviewed command-line tool")
        names.add(name)
    if "LICENSE-LLVM-OpenMP" not in names or "llama-server.exe" not in names:
        raise ValueError("ModelHost bundle lacks its server or LLVM notice")
    return value


def measured(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    return size, digest.hexdigest()


def verify_source(path: Path, identity: dict) -> None:
    path = Path(path)
    archive = identity["archive"]
    if path.name != archive["name"] or not path.is_file() or measured(path) != (archive["size_bytes"], archive["sha256"]):
        raise ValueError("publisher ModelHost ZIP differs from reviewed b10825 source")
    with zipfile.ZipFile(path) as source:
        names = source.namelist()
        if len(names) != 52 or len(set(names)) != 52 or any(not FLAT.fullmatch(name) for name in names):
            raise ValueError("publisher ModelHost ZIP has an unreviewed member roster")
        for entry in identity["files"]:
            try:
                data = source.read(entry["path"])
            except KeyError as error:
                raise ValueError("publisher ModelHost ZIP lacks a pinned file") from error
            if (len(data), hashlib.sha256(data).hexdigest()) != (entry["size_bytes"], entry["sha256"]):
                raise ValueError("publisher ModelHost kept file differs: " + entry["path"])


def receipt_bytes(identity: dict) -> bytes:
    receipt = {"schema": 1, "derivation": "sorted-root-zip-stored-1980-unix0644-v1",
               "source": identity["archive"], "bundle": identity["bundle"],
               "files": sorted(identity["files"], key=lambda entry: entry["path"])}
    return (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def verify_bundle(bundle: Path, receipt: Path, identity: dict) -> dict:
    bundle, receipt = Path(bundle), Path(receipt)
    expected = identity["bundle"]
    if (bundle.name != expected["name"] or not bundle.is_file()
            or measured(bundle) != (expected["size_bytes"], expected["sha256"])):
        raise ValueError("reduced ModelHost bundle differs from provider pin")
    if receipt.name != RECEIPT_NAME or not receipt.is_file() or receipt.read_bytes() != receipt_bytes(identity):
        raise ValueError("ModelHost bundle derivation receipt differs from provider pin")
    entries = sorted(identity["files"], key=lambda entry: entry["path"])
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != [entry["path"] for entry in entries]:
            raise ValueError("reduced ModelHost bundle includes an unreviewed member")
        for entry in entries:
            data = archive.read(entry["path"])
            if (len(data), hashlib.sha256(data).hexdigest()) != (entry["size_bytes"], entry["sha256"]):
                raise ValueError("reduced ModelHost member differs: " + entry["path"])
    return {"bundle": expected, "source": identity["archive"], "files": len(entries)}


def derive(source: Path, bundle: Path, receipt: Path, identity: dict) -> dict:
    verify_source(source, identity)
    bundle, receipt = Path(bundle), Path(receipt)
    if bundle.name != BUNDLE_NAME or receipt.name != RECEIPT_NAME:
        raise ValueError("ModelHost derived output filename differs from provider pin")
    bundle.parent.mkdir(parents=True, exist_ok=True)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    partial = bundle.with_name(bundle.name + ".partial")
    if partial.exists():
        raise FileExistsError("unfinished ModelHost bundle exists: " + str(partial))
    try:
        with zipfile.ZipFile(source) as publisher, zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_STORED) as output:
            for entry in sorted(identity["files"], key=lambda item: item["path"]):
                info = zipfile.ZipInfo(entry["path"], date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                output.writestr(info, publisher.read(entry["path"]))
        if measured(partial) != (identity["bundle"]["size_bytes"], identity["bundle"]["sha256"]):
            raise ValueError("derived ModelHost bundle differs from provider's reviewed digest")
        partial.replace(bundle)
        receipt.write_bytes(receipt_bytes(identity))
        return verify_bundle(bundle, receipt, identity)
    finally:
        partial.unlink(missing_ok=True)


def fetch(source: Path, identity: dict) -> None:
    source = Path(source)
    if source.exists():
        verify_source(source, identity)
        return
    source.parent.mkdir(parents=True, exist_ok=True)
    partial = source.with_name(source.name + ".partial")
    if source.name != SOURCE_NAME or partial.exists():
        raise ValueError("invalid or unfinished publisher ModelHost archive path")
    count = 0
    try:
        with urllib.request.urlopen(identity["archive"]["url"], timeout=120) as response, partial.open("xb") as output:
            while block := response.read(1 << 20):
                count += len(block)
                if count > identity["archive"]["size_bytes"]:
                    raise ValueError("ModelHost source download exceeds reviewed byte count")
                output.write(block)
        if count != identity["archive"]["size_bytes"]:
            raise ValueError("ModelHost source download has the wrong byte count")
        partial.replace(source)
        verify_source(source, identity)
    except Exception:
        source.unlink(missing_ok=True)
        raise
    finally:
        partial.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("fetch", "derive", "verify"))
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    identity = pin(args.pin)
    if args.operation == "fetch":
        if args.source is None:
            parser.error("fetch requires --source")
        fetch(args.source, identity)
        result = {"source": identity["archive"]}
    elif args.operation == "derive":
        if args.source is None or args.bundle is None or args.receipt is None:
            parser.error("derive requires --source, --bundle and --receipt")
        result = derive(args.source, args.bundle, args.receipt, identity)
    else:
        if args.bundle is None or args.receipt is None:
            parser.error("verify requires --bundle and --receipt")
        result = verify_bundle(args.bundle, args.receipt, identity)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
