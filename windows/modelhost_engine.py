"""Derive the reviewed, tool-free ModelHost bundle from the publisher's ZIP.

The modelhostd `engine pin --json` output owns the archive, kept-file, runtime
and bundle pins. The release producer obtains it from its same-source
executable. The publisher's full archive is an input only; it never enters an
OA package.

The publisher's build links the Microsoft Visual C++ runtime, which a clean
Windows lacks (0xC0000135 in Windows Sandbox). The bundle carries that
runtime app-locally: derive reads the pin's runtime files from --runtime, the
build toolchain's redistributable folder (VC/Redist/MSVC/<version>/x64/
<folder>), and checks each against the pin's size and SHA-256.
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
# The runtime DLLs the publisher's build imports (dumpbin /dependents).
RUNTIME_FILES = {"msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"}


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
            or set(value) != {"schema", "release", "program", "archive", "bundle", "files", "runtime"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["release"] != "b10825" or value["program"] != "llama-server.exe"):
        raise ValueError("invalid ModelHost engine pin document")
    source, bundle, files, runtime = value["archive"], value["bundle"], value["files"], value["runtime"]
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
            or not isinstance(files, list) or len(files) != 24 + len(RUNTIME_FILES)
            or not isinstance(runtime, dict) or set(runtime) != {"name", "version", "folder", "files"}
            or not all(isinstance(runtime[key], str) and runtime[key] for key in ("name", "version", "folder"))
            or not isinstance(runtime["files"], list) or set(runtime["files"]) != RUNTIME_FILES
            or len(runtime["files"]) != len(RUNTIME_FILES)):
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
    if not RUNTIME_FILES <= names:
        raise ValueError("ModelHost bundle pin lacks a runtime file it names")
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
            if entry["path"] in RUNTIME_FILES:
                continue
            try:
                data = source.read(entry["path"])
            except KeyError as error:
                raise ValueError("publisher ModelHost ZIP lacks a pinned file") from error
            if (len(data), hashlib.sha256(data).hexdigest()) != (entry["size_bytes"], entry["sha256"]):
                raise ValueError("publisher ModelHost kept file differs: " + entry["path"])


def receipt_bytes(identity: dict) -> bytes:
    receipt = {"schema": 1, "derivation": "sorted-root-zip-stored-1980-unix0644-v1",
               "source": identity["archive"], "bundle": identity["bundle"], "runtime": identity["runtime"],
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


def runtime_bytes(folder: Path, identity: dict) -> dict:
    """The pinned runtime files, read from the toolchain's redistributable
    folder and checked against the pin."""
    folder = Path(folder)
    if folder.name != identity["runtime"]["folder"] or not folder.is_dir():
        raise ValueError("the runtime folder is not the pinned " + identity["runtime"]["folder"])
    pinned = {entry["path"]: entry for entry in identity["files"] if entry["path"] in RUNTIME_FILES}
    result = {}
    for name, entry in pinned.items():
        data = (folder / name).read_bytes()
        if (len(data), hashlib.sha256(data).hexdigest()) != (entry["size_bytes"], entry["sha256"]):
            raise ValueError("the runtime file differs from the pin: " + name)
        result[name] = data
    return result


def runtime_asset(path: Path, identity: dict | None = None) -> dict:
    """The release-input projection of EnginePin.Runtime, beside app pins."""
    value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    if not isinstance(value, dict) or set(value) != {"schema", "release_tag", "archive", "runtime"} or type(value["schema"]) is not int or value["schema"] != 1:
        raise ValueError("invalid runtime asset pin")
    archive, runtime = value["archive"], value["runtime"]
    if (not isinstance(runtime, dict) or set(runtime) != {"name", "version", "folder", "files"}
            or not all(isinstance(runtime[key], str) and runtime[key] for key in ("name", "version", "folder"))
            or not FLAT.fullmatch(runtime["folder"]) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", runtime["version"])
            or not isinstance(runtime["files"], list) or len(runtime["files"]) != 3):
        raise ValueError("invalid runtime asset file pins")
    names = set()
    for entry in runtime["files"]:
        if (not isinstance(entry, dict) or set(entry) != {"path", "size_bytes", "sha256"}
                or entry["path"] not in RUNTIME_FILES or entry["path"] in names
                or type(entry["size_bytes"]) is not int or entry["size_bytes"] <= 0
                or not isinstance(entry["sha256"], str) or not SHA.fullmatch(entry["sha256"])):
            raise ValueError("invalid runtime asset member")
        names.add(entry["path"])
    name = "vc-runtime-" + runtime["version"] + "-win-x64.zip"
    tag = value["release_tag"]
    if (not isinstance(tag, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag)
            or not isinstance(archive, dict) or set(archive) != {"name", "url", "size_bytes", "sha256"}
            or archive["name"] != name
            or archive["url"] != "https://github.com/openabstractions/redist/releases/download/" + tag + "/" + name
            or type(archive["size_bytes"]) is not int or archive["size_bytes"] <= 0
            or not isinstance(archive["sha256"], str) or not SHA.fullmatch(archive["sha256"])):
        raise ValueError("invalid runtime release asset")
    if identity is not None:
        expected = dict(identity["runtime"])
        expected["files"] = sorted((entry for entry in identity["files"] if entry["path"] in RUNTIME_FILES), key=lambda entry: entry["path"])
        if runtime != expected:
            raise ValueError("runtime asset differs from the same-source provider pin")
    return value


def runtime_asset_bytes(path: Path, asset: dict) -> dict:
    expected = asset["archive"]
    if Path(path).name != expected["name"] or measured(path) != (expected["size_bytes"], expected["sha256"]):
        raise ValueError("runtime ZIP differs from its release input pin")
    files = sorted(asset["runtime"]["files"], key=lambda entry: entry["path"])
    prefix = asset["runtime"]["folder"] + "/"
    result = {}
    with zipfile.ZipFile(path) as archive:
        if archive.namelist() != [prefix + entry["path"] for entry in files]:
            raise ValueError("runtime ZIP member roster differs from its pin")
        for entry in files:
            info = archive.getinfo(prefix + entry["path"])
            if info.is_dir() or ((info.external_attr >> 16) & 0o170000) not in (0, 0o100000):
                raise ValueError("runtime ZIP member is not a regular file")
            with archive.open(info) as stream:
                data = stream.read(entry["size_bytes"] + 1)
            if (len(data), hashlib.sha256(data).hexdigest()) != (entry["size_bytes"], entry["sha256"]):
                raise ValueError("runtime ZIP member differs: " + entry["path"])
            result[entry["path"]] = data
    return result


def build_runtime_asset(path: Path, runtime: Path, identity: dict, asset: dict) -> dict:
    supplied = runtime_bytes(runtime, identity)
    path = Path(path)
    if path.name != asset["archive"]["name"]:
        raise ValueError("runtime output filename differs from its asset pin")
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".partial")
    if partial.exists():
        raise FileExistsError("unfinished runtime asset exists")
    try:
        with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_STORED) as output:
            for name, data in sorted(supplied.items()):
                info = zipfile.ZipInfo(asset["runtime"]["folder"] + "/" + name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o100644 << 16
                output.writestr(info, data)
        if measured(partial) != (asset["archive"]["size_bytes"], asset["archive"]["sha256"]):
            raise ValueError("built runtime asset differs from its pin")
        publish_archive(partial, path)
        runtime_asset_bytes(path, asset)
        return asset["archive"]
    finally:
        partial.unlink(missing_ok=True)


def prepare_runtime_asset(path: Path, folder: Path, asset: dict) -> dict:
    expected = asset["archive"]
    fetch_file(path, expected, lambda source: runtime_asset_bytes(source, asset), "runtime release input")
    supplied = runtime_asset_bytes(path, asset)
    folder = Path(folder)
    if folder.name != asset["runtime"]["folder"] or folder.is_symlink() or folder.is_junction():
        raise ValueError("runtime output folder differs from its pin")
    folder.mkdir(parents=True, exist_ok=True)
    if list(folder.iterdir()):
        if ({entry.name for entry in folder.iterdir()} != set(supplied)
                or any(entry.is_symlink() or not entry.is_file() for entry in folder.iterdir())
                or any((folder / name).read_bytes() != data for name, data in supplied.items())):
            raise ValueError("existing runtime folder differs from its pin")
    else:
        for name, data in supplied.items():
            with (folder / name).open("xb") as output:
                output.write(data)
    return expected


def runtime_projections(asset: dict) -> dict[str, bytes]:
    """Private provider projections; the release input row owns these bytes."""
    header = "// Code generated from vc_runtime_asset.json by installer/modelhost_engine.py; DO NOT EDIT.\n\n"
    files = sorted(asset["runtime"]["files"], key=lambda entry: entry["path"])
    rows = "".join('\t\t{Name: "' + entry["path"] + '", Size: ' + str(entry["size_bytes"]) + ', SHA256: "' + entry["sha256"] + '"},\n' for entry in files)
    archive = asset["archive"]
    name = 'const llamaRuntimeArchive = "' + archive["name"] + '"\n\n'
    server = header + "package server\n\n" + name + "func llamaRuntimeFiles() []ManifestFile {\n\treturn []ManifestFile{\n" + rows + "\t}\n}\n"
    setup = (header + 'package setup\n\nimport "github.com/openabstractions/abstraction-provider-lemonade/go/server"\n\n'
             + 'const llamaRuntimeVersion = "' + asset["runtime"]["version"] + '"\n'
             + 'const llamaRuntimeURL = "' + archive["url"] + '"\n\n'
             + 'var llamaRuntimeInput = backendRuntime{\n'
             + '\tName:   "' + archive["name"] + '",\n'
             + '\tSize:   ' + str(archive["size_bytes"]) + ',\n'
             + '\tSHA256: "' + archive["sha256"] + '",\n'
             + '\tPrefix: "' + asset["runtime"]["folder"] + '/",\n'
             + '\tFiles: []server.ManifestFile{\n' + rows + '\t},\n}\n')
    return {"server/runtime_pin_generated.go": server.encode("utf-8"),
            "setup/runtime_pin_generated.go": setup.encode("utf-8"),
            "cmd/lemonaded/runtime_pin_generated.go": (header + "package main\n\n" + name.rstrip() + "\n").encode("utf-8")}


def derive(source: Path, bundle: Path, receipt: Path, identity: dict, runtime: Path) -> dict:
    verify_source(source, identity)
    supplied = runtime_bytes(runtime, identity)
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
                output.writestr(info, supplied[entry["path"]] if entry["path"] in supplied else publisher.read(entry["path"]))
        if measured(partial) != (identity["bundle"]["size_bytes"], identity["bundle"]["sha256"]):
            raise ValueError("derived ModelHost bundle differs from provider's reviewed digest")
        partial.replace(bundle)
        receipt.write_bytes(receipt_bytes(identity))
        return verify_bundle(bundle, receipt, identity)
    finally:
        partial.unlink(missing_ok=True)


def publish_archive(partial: Path, destination: Path) -> None:
    """Publish an already bounded archive through the existing archive owner."""
    partial.replace(destination)


def fetch_file(source: Path, expected: dict, verify, label: str) -> None:
    source = Path(source)
    if source.exists():
        verify(source)
        return
    source.parent.mkdir(parents=True, exist_ok=True)
    partial = source.with_name(source.name + ".partial")
    if source.name != expected["name"] or partial.exists():
        raise ValueError("invalid or unfinished publisher ModelHost archive path")
    count = 0
    try:
        with urllib.request.urlopen(expected["url"], timeout=120) as response, partial.open("xb") as output:
            while block := response.read(1 << 20):
                count += len(block)
                if count > expected["size_bytes"]:
                    raise ValueError(label + " download exceeds reviewed byte count")
                output.write(block)
        if count != expected["size_bytes"]:
            raise ValueError("ModelHost source download has the wrong byte count")
        publish_archive(partial, source)
        verify(source)
    except Exception:
        source.unlink(missing_ok=True)
        raise
    finally:
        partial.unlink(missing_ok=True)


def fetch(source: Path, identity: dict) -> None:
    fetch_file(source, identity["archive"], lambda path: verify_source(path, identity), "ModelHost source")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("fetch", "derive", "verify", "runtime-build", "runtime", "runtime-projections"))
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--runtime-pin", type=Path, help="pinned runtime release input metadata")
    parser.add_argument("--runtime-asset", type=Path, help="pinned runtime release input ZIP")
    parser.add_argument("--projection-root", type=Path, help="runtime-projections: Lemonade provider Go source root")
    parser.add_argument("--runtime", type=Path, help="derive: the toolchain's x64 runtime folder the pin names, "
                        "VC\\Redist\\MSVC\\<version>\\x64\\<folder>")
    args = parser.parse_args(argv)
    identity = pin(args.pin)
    if args.operation == "runtime-projections":
        if args.runtime_pin is None or args.projection_root is None:
            parser.error("runtime-projections requires --runtime-pin and --projection-root")
        asset = runtime_asset(args.runtime_pin, identity)
        for name, data in runtime_projections(asset).items():
            (args.projection_root / name).write_bytes(data)
        result = {"runtime_projections": sorted(runtime_projections(asset))}
    elif args.operation in ("runtime-build", "runtime"):
        if args.runtime_pin is None or args.runtime_asset is None or args.runtime is None:
            parser.error("runtime operations require --runtime-pin, --runtime-asset and --runtime")
        asset = runtime_asset(args.runtime_pin, identity)
        if args.operation == "runtime-build":
            result = build_runtime_asset(args.runtime_asset, args.runtime, identity, asset)
        else:
            result = prepare_runtime_asset(args.runtime_asset, args.runtime, asset)
    elif args.operation == "fetch":
        if args.source is None:
            parser.error("fetch requires --source")
        fetch(args.source, identity)
        result = {"source": identity["archive"]}
    elif args.operation == "derive":
        if args.source is None or args.bundle is None or args.receipt is None or args.runtime is None:
            parser.error("derive requires --source, --bundle, --receipt and --runtime")
        result = derive(args.source, args.bundle, args.receipt, identity, args.runtime)
    else:
        if args.bundle is None or args.receipt is None:
            parser.error("verify requires --bundle and --receipt")
        result = verify_bundle(args.bundle, args.receipt, identity)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
