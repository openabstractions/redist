#!/usr/bin/env python3
"""Build one extension's own per-user MSI (installer/apps/extension.wxs).

An extension is a folder another application loads from its own folder,
such as a ComfyUI custom node. adopters/<app>/extension.json describes it:

  {"id": "comfyui",                      roster id and HKCU record name
   "title": "OpenAbstractions for ComfyUI",
   "folder": "comfyui-openabstractions",  the folder it becomes
   "payload": "node",                     its source folder, beside the file
   "generated": ["application-manifest.json"],
                                          files it writes in that folder at
                                          run time, removed on uninstall
   "host": {"name": "ComfyUI Desktop",
            "config": "ComfyUI/config.json",
                                          relative to the roaming AppData
            "key": "basePath",            top-level JSON string: its folder
            "subfolder": "custom_nodes",  the folder receiving the extension
            "download": "https://..."},   its maker's download page
   "python_setup": {"venv": ".venv",      optional: a venv in the host's folder
                    "script": "setup.py"},
                                          and a payload script install runs
                                          with that venv's pythonw.exe -I -B
   "generated_folders": ["helper"],       optional: folders it fills at run
                                          time, emptied and removed on
                                          uninstall
   "include": [{"from": "abstraction-identity/py/abstraction/ipc",
                "to": "oa_client/abstraction/ipc"}],
                                          optional: repository folders of
                                          OA's own code the payload carries,
                                          from the explicit include root to a
                                          payload folder
   "programs": ["comfyui-connector.exe"]}
                                          optional: programs the build
                                          supplies (--program FILE), placed
                                          at the top of the extension folder

The setup script runs once the files are in place, as the installing
account, and its outcome is ignored: a host whose venv does not exist yet
installs all the same, and the extension does the same work when it first
runs. It is how an extension gives its host's Python program a copy of its
own interpreter (adopters/comfyui/node/oa_interpreter.py).

The payload is every file under the payload folder and each included folder
except Python bytecode, tests (test_*.py, *.test.mjs) and dot files. A
native library (.dll, .so, .dylib, .pyd) in either is refused: an extension
loads the one its host's OpenAbstractions runtime installed. payload.wxs,
written to --out, lists them, and the Python bytecode folder beside each Python package, which
uninstall removes with the files. The custom action hostfolder.c is compiled
with cl from a Visual Studio x64 developer environment unless --action-dll
names an already built one. The upgrade code is derived from the extension
id, in a namespace of its own, so every version of one extension upgrades the
one before and no showcase application package. The package is UNSIGNED.

Each program the description declares is a built file the caller supplies
with --program FILE, whose name is the declared one; a declared program left
out, or one not declared, is refused.

Three options exist for tests only: --test-host-config FILE reads the
application's configuration from FILE instead of the account's roaming
AppData, --test-without-openabstractions drops the requirement for an
installed OpenAbstractions, and --test-without-programs builds without the
declared programs. A release build passes none.

Usage:
  build_extension.py --extension FILE --publisher NAME --version X.Y.Z --out DIR
                     [--action-dll DLL] [--wix wix] [--cl cl]
                     [--include-root VERIFIED_SOURCE_WORKSPACE]
                     [--input-receipt RECEIVED_JSON --action-sha256 HEX --action-bytes N]
                     [--program FILE ...]
                     [--test-host-config FILE] [--test-without-openabstractions]
                     [--test-without-programs]

Without arguments, prints this text.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
from file_boundary import ordinary_path  # noqa: E402

_app_path = HERE/'build_app.py'
_app_spec = importlib.util.spec_from_file_location('oa_extension_app_owner', _app_path)
_app_owner = importlib.util.module_from_spec(_app_spec)
exec(compile(_app_path.read_bytes(), str(_app_path), 'exec'), _app_owner.__dict__)
APP_ID, DEVICE_NAME, MEMBER_SEGMENT, MSI_VERSION = (
    _app_owner.APP_ID, _app_owner.DEVICE_NAME, _app_owner.MEMBER_SEGMENT, _app_owner.MSI_VERSION)

WXS = "http://wixtoolset.org/schemas/v4/wxs"
FIELDS = {"id", "title", "folder", "payload", "generated", "host"}
OPTIONAL_FIELDS = {"python_setup", "generated_folders", "include", "register_application", "prepared_files", "programs", "discovery@1", "package@1", "retained-archive@1", "setup-host@1", "legacy@1"}
PROGRAM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.exe\Z")
INCLUDE_FIELDS = {"from", "to"}
NATIVE_LIBRARY = re.compile(r".*\.(?:dll|so|dylib|pyd)(?:\.[0-9]+)*\Z", re.IGNORECASE)
SETUP_FIELDS = {"venv", "script"}
HOST_FIELDS = {"name", "config", "key", "subfolder", "download"}
# Text Windows Installer would format: a bracket or brace is a property or
# directive, so no value this builder passes into the package may hold one.
PLAIN = re.compile(r"[^\x00-\x1f\[\]{}<>&\"]{1,200}\Z")
KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
DOWNLOAD = re.compile(r"https://[A-Za-z0-9./_~%-]{1,300}\Z")
SKIPPED_DIRECTORIES = {"__pycache__", "node_modules", "testdata"}
COMPILE = ["/nologo", "/W4", "/WX", "/O2", "/MT", "/GS", "/guard:cf", "/Brepro", "/LD"]
LINK = ["/link", "/guard:cf", "/Brepro", "/DYNAMICBASE", "/NXCOMPAT", "msi.lib"]


def upgrade_code(extension_id: str) -> str:
    """The extension's fixed MSI upgrade code."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "https://openabstractions.org/extensions/" + extension_id))


def plain_name(value: object, what: str) -> str:
    if not isinstance(value, str) or not MEMBER_SEGMENT.match(value) or DEVICE_NAME.match(value):
        raise ValueError(f"{what} is not one plain Windows file name")
    return value


def plain_text(value: object, what: str) -> str:
    if not isinstance(value, str) or not PLAIN.match(value):
        raise ValueError(f"{what} is not plain text Windows Installer shows as written")
    return value


def _unique_keys(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate extension manifest key")
    return result


def _exact_object(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        raise ValueError(f"{label} requires exactly {keys}")
    return value


def _validate_package(extension: dict) -> None:
    if any(key.startswith("package@") and key != "package@1" for key in extension):
        raise ValueError("unsupported package declaration version")
    declaration = _exact_object(extension.get("package@1"), "id title identity artifact rollback integration", "package@1")
    identity = _exact_object(declaration["identity"], "platform connector_sha256", "package identity")
    artifact = _exact_object(declaration["artifact"], "id sha256", "package artifact")
    integration = _exact_object(declaration["integration"], "connector registration", "package integration")
    package_id = declaration["id"]
    if (not isinstance(package_id, str) or not APP_ID.fullmatch(package_id)
            or package_id != extension.get("id") or artifact["id"] != package_id or integration["registration"] != package_id):
        raise ValueError("package, extension, release artifact and registration IDs must agree")
    if identity != {"platform": "windows/amd64", "connector_sha256": "release-extension.connector_sha256"}:
        raise ValueError("package identity requires the Windows x64 release-extension connector digest reference")
    if artifact["sha256"] != "release-extension.sha256":
        raise ValueError("package artifact requires the release-extension artifact digest reference")
    if declaration["rollback"] != "keep-previous-digest-until-verified":
        raise ValueError("package rollback must keep the previous digest until verification")
    connector = plain_name(integration["connector"], "package connector")
    programs = extension.get("programs")
    if not PROGRAM.fullmatch(connector) or programs != [connector]:
        raise ValueError("package connector must be the extension's declared connector program")
    plain_text(declaration["title"], "package title")
    plain_name(extension.get("folder"), "extension folder")
    host = extension.get("host")
    if not isinstance(host, dict):
        raise ValueError("package extension host must be an object")
    plain_name(host.get("subfolder"), "host subfolder")


def _validate_retained_archive(extension: dict) -> None:
    if any(key.startswith("retained-archive@") and key != "retained-archive@1" for key in extension):
        raise ValueError("unsupported retained archive declaration version")
    archive = extension.get("retained-archive@1")
    fields = "component data_layout model_paths" if isinstance(archive, dict) and (
        "data_layout" in archive or "model_paths" in archive) else "component"
    if isinstance(archive, dict) and "launch_layout" in archive:
        fields = "component data_layout model_paths launch_layout"
    archive = _exact_object(archive, fields, "retained-archive@1")
    if "package@1" not in extension:
        raise ValueError("retained archive requires its extension's package@1")
    component = archive["component"]
    if not isinstance(component, str) or not APP_ID.fullmatch(component) or component == extension["id"]:
        raise ValueError("retained archive component must be a distinct plain ID")
    if "data_layout" in archive:
        data = _exact_object(archive["data_layout"], "root user input temp", "retained archive data layout")
        _host_relative_path(data["root"], "retained archive data root")
        for key in ("user", "input", "temp"):
            plain_name(data[key], "retained archive " + key)
        model = _exact_object(archive["model_paths"], "file group categories", "retained archive model paths")
        filename = plain_name(model["file"], "retained archive model file")
        if not filename.endswith(".json"):
            raise ValueError("retained archive model file must be JSON")
        plain_name(model["group"], "retained archive model group")
        categories = model["categories"]
        if (not isinstance(categories, list) or len(categories) != 3
                or any(not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name) for name in categories)
                or len(set(categories)) != 3):
            raise ValueError("retained archive model paths require three distinct category keys")
    if "launch_layout" in archive:
        launch = _exact_object(archive["launch_layout"], "native_root portable_root image_recipe image_policy",
                               "retained archive launch layout")
        for key in ("native_root", "portable_root"):
            _host_relative_path(launch[key], "retained archive " + key)
        _host_relative_path(launch["image_recipe"], "retained archive image recipe", ".json")
        if not isinstance(launch["image_policy"], str) or not APP_ID.fullmatch(launch["image_policy"]):
            raise ValueError("retained archive image policy must be a plain ID")


def _host_relative_path(value: object, label: str, suffix: str = "") -> str:
    if (not isinstance(value, str) or len(value) > 200
            or not re.search(re.escape(suffix) + r"\Z", value, re.IGNORECASE | re.ASCII)):
        raise ValueError(f"{label} is not a plain relative host path")
    parts = value.split("/")
    if len(parts) > 4:
        raise ValueError(f"{label} holds too many path components")
    for part in parts:
        plain_name(part, label)
    return value


def _host_path_list(value: object, label: str, suffix: str, *, one_segment: bool = False) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 4:
        raise ValueError(f"{label} requires 1 to 4 ordered paths")
    paths = [_host_relative_path(path, label, suffix) for path in value]
    if len({path.lower() for path in paths}) != len(paths) or one_segment and any("/" in path for path in paths):
        raise ValueError(f"{label} repeats a path or names another folder")


def _validate_setup_host(extension: dict) -> None:
    if any(key.startswith("setup-host@") and key != "setup-host@1" for key in extension):
        raise ValueError("unsupported Setup host declaration version")
    host = extension.get("setup-host@1")
    fields = "desktop_program preferred_signed_program signed_scan_first_folder signed_scan_name local_installs settings install_base portable_launchers"
    if isinstance(host, dict) and ("settings_keys" in host or "integration_marker" in host):
        fields += " settings_keys integration_marker"
    if isinstance(host, dict) and "process_folders" in host:
        fields += " process_folders"
    host = _exact_object(host, fields, "setup-host@1")
    for name in ("desktop_program", "preferred_signed_program"):
        path = _host_relative_path(host[name], name, ".exe")
        if len(path.split("/")) != 3 or not path.startswith("Programs/"):
            raise ValueError(f"{name} requires a dedicated folder in Programs")
    plain_name(host["signed_scan_first_folder"], "signed scan folder")
    if not isinstance(host["signed_scan_name"], str) or not re.fullmatch(r"[a-z0-9-]{1,24}", host["signed_scan_name"]):
        raise ValueError("signed scan name must be a lowercase label")
    _host_relative_path(host["local_installs"], "local installs")
    _host_path_list(host["settings"], "host settings", ".json")
    plain_name(host["install_base"], "host install base")
    _host_path_list(host["portable_launchers"], "portable launchers", ".bat", one_segment=True)
    if "settings_keys" in host:
        keys = host["settings_keys"]
        if (not isinstance(keys, list) or not 1 <= len(keys) <= 4
                or any(not isinstance(key, str) or not KEY.fullmatch(key) for key in keys)
                or len(set(keys)) != len(keys)):
            raise ValueError("host settings keys require 1 to 4 distinct keys")
        plain_name(host["integration_marker"], "integration marker")
    if "process_folders" in host:
        _host_path_list(host["process_folders"], "host process folders", "", one_segment=True)


def parse_extension(raw: str) -> dict:
    """Parse the extension, checking any versioned package or retained archive declaration."""
    extension = json.loads(raw)
    if not isinstance(extension, dict):
        raise ValueError("extension manifest must be an object")
    package = any(key.startswith("package@") for key in extension)
    retained = any(key.startswith("retained-archive@") for key in extension)
    setup_host = any(key.startswith("setup-host@") for key in extension)
    if package or retained or setup_host:
        extension = json.loads(raw, object_pairs_hook=_unique_keys)
    if package:
        _validate_package(extension)
    if retained:
        _validate_retained_archive(extension)
    if setup_host:
        _validate_setup_host(extension)
    return extension


def read_extension(path: Path) -> dict:
    """The extension description, checked for shape, with its payload folder
    made absolute."""
    extension = parse_extension(path.read_text(encoding="utf-8"))
    if not FIELDS <= set(extension) <= FIELDS | OPTIONAL_FIELDS:
        raise ValueError("the extension file has exactly " + ", ".join(sorted(FIELDS)) + " and optionally " +
                         ", ".join(sorted(OPTIONAL_FIELDS)))
    if "discovery@1" in extension and not isinstance(extension["discovery@1"], dict):
        raise ValueError("discovery@1 must be an object")
    host = extension["host"]
    if not isinstance(host, dict) or set(host) != HOST_FIELDS:
        raise ValueError("host has exactly " + ", ".join(sorted(HOST_FIELDS)))
    if not isinstance(extension["id"], str) or not APP_ID.match(extension["id"]):
        raise ValueError("id is not an application id")
    plain_text(extension["title"], "title")
    plain_name(extension["folder"], "folder")
    if not isinstance(extension["generated"], list):
        raise ValueError("generated is not a list of file names")
    for name in extension["generated"]:
        plain_name(name, "a generated file")
    plain_text(host["name"], "host name")
    config = PureWindowsPath(host["config"]) if isinstance(host["config"], str) else None
    if config is None or config.is_absolute() or config.drive or not config.parts or \
            any(not MEMBER_SEGMENT.match(part) or DEVICE_NAME.match(part) for part in config.parts):
        raise ValueError("host config is not a plain relative path")
    if not isinstance(host["key"], str) or not KEY.match(host["key"]):
        raise ValueError("host key is not a plain JSON key")
    plain_name(host["subfolder"], "host subfolder")
    if not isinstance(host["download"], str) or not DOWNLOAD.match(host["download"]):
        raise ValueError("host download is not a plain https address")
    folders = extension.setdefault("generated_folders", [])
    if not isinstance(folders, list):
        raise ValueError("generated_folders is not a list of folder names")
    for name in folders:
        plain_name(name, "a generated folder")
    setup = extension.setdefault("python_setup", None)
    if setup is not None:
        if not isinstance(setup, dict) or set(setup) != SETUP_FIELDS:
            raise ValueError("python_setup has exactly " + ", ".join(sorted(SETUP_FIELDS)))
        venv = PureWindowsPath(setup["venv"]) if isinstance(setup["venv"], str) else None
        if venv is None or venv.is_absolute() or venv.drive or not venv.parts or \
                any(not MEMBER_SEGMENT.match(part) or DEVICE_NAME.match(part) for part in venv.parts):
            raise ValueError("python_setup venv is not a plain relative path")
        plain_name(setup["script"], "python_setup script")
    register=extension.setdefault('register_application',False)
    if type(register) is not bool or (register and (setup is None or 'application-manifest.json' not in extension['generated'])):
        raise ValueError('register_application requires checked Python setup and its generated application-manifest.json')
    prepared=extension.setdefault('prepared_files',{})
    if not isinstance(prepared,dict):raise ValueError('prepared_files is not a pinned payload map')
    for name,pin in prepared.items():
        plain_name(name,'a prepared file')
        if pin is not None and (type(pin) is not dict or set(pin)!={'bytes','sha256'} or type(pin['bytes']) is not int or pin['bytes']<0 or not isinstance(pin['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',pin['sha256'])):
            raise ValueError('prepared file lacks its exact size and hash')
    programs = extension.setdefault("programs", [])
    if not isinstance(programs, list) or len(set(programs)) != len(programs):
        raise ValueError("programs is not a list of distinct program names")
    for name in programs:
        if not isinstance(name, str) or not PROGRAM.match(name):
            raise ValueError(f"the program {name!r} is not a plain .exe name")
        plain_name(name, "a program")
    include = extension.setdefault("include", [])
    if not isinstance(include, list):
        raise ValueError("include is not a list of folders")
    for entry in include:
        if not isinstance(entry, dict) or set(entry) != INCLUDE_FIELDS:
            raise ValueError("an include has exactly " + ", ".join(sorted(INCLUDE_FIELDS)))
        for field in sorted(INCLUDE_FIELDS):
            _include_path(entry[field], field)
    payload = path.parent / plain_name(extension["payload"], "payload")
    try:
        extension["payload"] = ordinary_path(payload, kind="directory")
    except FileNotFoundError as error:
        raise ValueError(f"the payload folder {payload} does not exist") from error
    return extension


def _include_path(value, field):
    name = PurePosixPath(value) if isinstance(value, str) else None
    if (name is None or name.is_absolute() or "\\" in value or not name.parts
            or any(not MEMBER_SEGMENT.match(part) or DEVICE_NAME.match(part) for part in name.parts)):
        raise ValueError(f"include {field} is not a plain relative folder")
    return name


def _folder_files(root: Path, what: str) -> list[PurePosixPath]:
    """The files under root, as name chains, in a fixed order. Each is
    reached by walking root's own entries, so none is outside it."""
    files = []

    def walk(folder: Path, parts: tuple[str, ...]) -> None:
        with os.scandir(folder) as entries:
            for entry in sorted(entries, key=lambda e: e.name):
                relative = PurePosixPath(*parts, entry.name)
                if entry.name in SKIPPED_DIRECTORIES or entry.name.startswith("."):
                    continue
                if entry.is_symlink() or entry.is_junction():
                    raise ValueError(f"{relative} is a link; the {what} holds plain folders and files only")
                plain_name(entry.name, f"{what} path {relative}")
                if NATIVE_LIBRARY.match(entry.name):
                    raise ValueError(f"{relative} is a native library; an extension carries none")
                if entry.is_dir():
                    walk(Path(entry.path), parts + (entry.name,))
                elif entry.is_file() and not entry.name.endswith((".pyc", ".pyo")) and \
                        not entry.name.startswith("test_") and not entry.name.endswith(".test.mjs"):
                    files.append(relative)

    walk(ordinary_path(root, kind="directory"), ())
    return files


def payload_files(root: Path) -> list[PurePosixPath]:
    """The files the package installs from the payload folder, as name
    chains under root, in a fixed order."""
    files = _folder_files(root, "payload")
    if PurePosixPath("__init__.py") not in files:
        raise ValueError("the payload has no __init__.py at its top")
    return files


def include_files(include: list[dict], payload: list[PurePosixPath], root: Path = ROOT) -> dict:
    """{payload name chain: source file} for each included repository folder.
    The folder is reached from root one plain folder at a time, never through
    a link, so it lies inside the repository; no included file may take a
    payload file's place."""
    try:
        root = ordinary_path(root, kind="directory")
    except (OSError, ValueError) as error:
        raise ValueError('include root must be an existing plain directory') from error
    found = {}
    names = {name.as_posix().casefold() for name in payload}
    for entry in include:
        source_name = _include_path(entry["from"], "from")
        target = _include_path(entry["to"], "to")
        try:
            folder = ordinary_path(root / Path(*source_name.parts), kind="directory")
        except (OSError, ValueError) as error:
            raise ValueError(f"include {entry['from']} is not a plain folder in the repository") from error
        for relative in _folder_files(folder, "included folder"):
            placed = target / relative
            if placed.as_posix().casefold() in names:
                raise ValueError(f"{placed} is placed twice")
            names.add(placed.as_posix().casefold())
            found[placed] = folder / Path(*relative.parts)
    return found


def program_files(declared: list[str], supplied: list[Path], payload: list[PurePosixPath], included: dict,
                  without: bool = False) -> dict:
    """{payload name: built file} for the declared programs. Each is supplied
    once as a plain file named as declared, taking no other file's place."""
    found = {}
    taken = {member.as_posix().casefold() for member in (*payload, *included)}
    for path in supplied:
        path = Path(path)
        if path.name not in declared or path.name in found:
            raise ValueError(f"the program {path.name} is not declared once in the extension's programs")
        try:
            admitted = ordinary_path(path, kind="file")
        except (OSError, ValueError) as error:
            raise ValueError(f"the program {path} is not a plain file") from error
        placement = path.name.casefold()
        if placement in taken:
            raise ValueError(f"{path.name} is placed twice")
        taken.add(placement)
        found[path.name] = admitted
    missing = [name for name in declared if name not in found]
    if missing and not without:
        raise ValueError("the extension's programs are not supplied: " + ", ".join(missing) + " (--program FILE)")
    return {PurePosixPath(name): path for name, path in found.items()}


def file_pin(path):
    path = Path(path)
    data = path.read_bytes()
    return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def check_prepared_payload(extension, inventory):
    """Receive source-declared prepared members before any MSI staging/effect."""
    for name,pin in extension.get('prepared_files',{}).items():
        if pin is None or inventory.get(name)!=pin:
            raise ValueError('required prepared payload is missing or differs: '+name)


def payload_fragment(root: Path, files: list[Path], generated: list[str], generated_folders=(), sources=None) -> str:
    """payload.wxs: the ExtensionFiles component group under ExtensionFolder.
    Each folder's first file component also removes, on uninstall, the
    folder's Python bytecode folder and, at the top, the generated files and
    every file in each generated folder, then the folder."""
    ET.register_namespace("", WXS)
    wix = ET.Element(f"{{{WXS}}}Wix")
    fragment = ET.SubElement(wix, f"{{{WXS}}}Fragment")
    folders = {PureWindowsPath(): "ExtensionFolder"}
    parents = {PureWindowsPath(): ET.SubElement(fragment, f"{{{WXS}}}DirectoryRef", {"Id": "ExtensionFolder"})}
    caches = {}

    def folder(relative: PureWindowsPath) -> str:
        if relative not in folders:
            folder(relative.parent)
            folders[relative] = f"ExtDir{len(folders)}"
            parents[relative] = ET.SubElement(parents[relative.parent], f"{{{WXS}}}Directory",
                                              {"Id": folders[relative], "Name": relative.name})
        return folders[relative]

    generated_ids = {}
    for name in generated_folders:
        if any(relative.parts[0] == name for relative in files if len(relative.parts) > 1):
            raise ValueError(f"the generated folder {name} holds payload files")
        generated_ids[name] = f"ExtGeneratedDir{len(generated_ids)}"
        ET.SubElement(parents[PureWindowsPath()], f"{{{WXS}}}Directory", {"Id": generated_ids[name], "Name": name})
    for relative in files:
        parent = PureWindowsPath(*relative.parts[:-1])
        folder(parent)
        if relative.suffix == ".py" and parent not in caches:
            caches[parent] = f"ExtCache{len(caches)}"
            ET.SubElement(parents[parent], f"{{{WXS}}}Directory", {"Id": caches[parent], "Name": "__pycache__"})
    group = ET.SubElement(fragment, f"{{{WXS}}}ComponentGroup", {"Id": "ExtensionFiles"})
    cleaned = set()
    for index, relative in enumerate(files):
        parent = PureWindowsPath(*relative.parts[:-1])
        component = ET.SubElement(group, f"{{{WXS}}}Component", {"Id": f"ExtFile{index}", "Directory": folders[parent]})
        source = (sources or {}).get(relative, root / relative)
        ET.SubElement(component, f"{{{WXS}}}File", {"Id": f"ExtFile{index}", "Source": str(source),
                                                    "KeyPath": "yes"})
        if parent in cleaned:
            continue
        cleaned.add(parent)
        if parent in caches:
            ET.SubElement(component, f"{{{WXS}}}RemoveFile", {"Id": f"ExtCacheFiles{index}", "Directory": caches[parent],
                                                              "Name": "*", "On": "uninstall"})
            ET.SubElement(component, f"{{{WXS}}}RemoveFolder", {"Id": f"ExtCache{index}", "Directory": caches[parent],
                                                                "On": "uninstall"})
        if not parent.parts:
            for number, name in enumerate(generated):
                ET.SubElement(component, f"{{{WXS}}}RemoveFile", {"Id": f"ExtGenerated{number}", "Name": name,
                                                                  "On": "uninstall"})
            for number, directory in enumerate(generated_ids.values()):
                ET.SubElement(component, f"{{{WXS}}}RemoveFile", {"Id": f"ExtGeneratedFiles{number}",
                                                                  "Directory": directory, "Name": "*",
                                                                  "On": "uninstall"})
                ET.SubElement(component, f"{{{WXS}}}RemoveFolder", {"Id": f"ExtGeneratedFolder{number}",
                                                                    "Directory": directory, "On": "uninstall"})
        ET.SubElement(component, f"{{{WXS}}}RemoveFolder", {"Id": f"ExtFolder{index}", "On": "uninstall"})
    ET.indent(wix)
    return ET.tostring(wix, encoding="unicode") + "\n"


def native_identity_source():
    """Select the identity owner's exact private or projected source layout."""
    owner=HERE.resolve(strict=True)
    projected=owner/'native_windows.h'
    if owner.name=='apps' and owner.parent.name=='installer':
        checkout=owner.parent.parent
        if not (checkout/'CLAUDE.md').is_file() or not (checkout/'scripts/split.manifest').is_file():
            raise ValueError('selected private shared owner lacks its source layout')
        if projected.exists() or projected.is_symlink() or projected.is_junction():
            raise ValueError('shadow native_windows.h in private shared owner')
        selected=checkout/'openabstractions-flat/abstraction-identity/fileid/native_windows.h'
    elif owner.name=='apps' and owner.parent.name=='windows':
        # A missing public header never triggers a private-source lookup.
        selected=projected
    else:
        raise ValueError('selected shared owner has no admitted native identity source mode')
    if not selected.is_file() or selected.is_symlink() or selected.is_junction() or any(p.is_symlink() or p.is_junction() for p in selected.parents):
        raise ValueError('missing plain selected native_windows.h')
    return selected


def native_action_sources():
    """Measure the shared action's direct source/header dependencies."""
    result={}
    for name in ('hostfolder.c','hostfolder_io.h','native_windows.h'):
        source=native_identity_source() if name=='native_windows.h' else HERE/name
        if source.is_symlink() or source.is_junction() or not source.is_file():
            raise ValueError('native action requires plain owned '+name)
        result[name]=file_pin(source)
    return result


def build_action(out: Path, cl: str) -> Path:
    """Stage the shared action source and header into out; return the DLL."""
    sources=native_action_sources()
    source = out / "hostfolder.c"
    for name,pin in sources.items():
        staged=out/name
        if staged.is_symlink() or staged.is_junction() or (staged.exists() and (not staged.is_file() or staged.stat().st_nlink!=1)):
            raise ValueError('linked or non-file staged native action input: '+name)
        shutil.copyfile(native_identity_source() if name=='native_windows.h' else HERE/name,out/name)
        if file_pin(out/name)!=pin:raise ValueError('staged native action input differs: '+name)
    if subprocess.run([cl, *COMPILE, "/I"+str(out), source.name, *LINK], cwd=out).returncode:
        raise ValueError("cl failed to build hostfolder.dll; run from a Visual Studio x64 developer environment")
    if native_action_sources()!=sources or any(file_pin(out/name)!=pin for name,pin in sources.items()):
        raise ValueError('native action source/header changed during compilation')
    return out / "hostfolder.dll"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_extension.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--extension", type=Path)
    parser.add_argument("--publisher")
    parser.add_argument("--version")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--action-dll", type=Path)
    parser.add_argument("--action-sha256", help="Exact final native action integrity pin; signature authority remains with release signing")
    parser.add_argument("--action-bytes", type=int)
    parser.add_argument("--include-root", type=Path, help="Verified source workspace containing the descriptor's public module directories")
    parser.add_argument("--input-receipt", type=Path, help="Received producer/SDK source provenance; release owner validates its authority")
    parser.add_argument("--wix", default="wix")
    parser.add_argument("--cl", default="cl")
    parser.add_argument("--test-host-config", type=Path)
    parser.add_argument("--test-without-openabstractions", action="store_true")
    parser.add_argument("--program", type=Path, action="append", default=[],
                        help="a built program the extension declares; placed at the top of its folder")
    parser.add_argument("--test-without-programs", action="store_true")
    args = parser.parse_args(argv)
    required = ("extension", "publisher", "version", "out")
    if all(getattr(args, name) is None for name in required):
        parser.print_help()
        return 0
    missing = [name for name in required if getattr(args, name) is None]
    if missing:
        parser.error("missing " + ", ".join("--" + name for name in missing))
    if not MSI_VERSION.match(args.version):
        parser.error("--version is not X.Y.Z")
    out = args.out.resolve()
    try:
        extension = read_extension(args.extension.resolve())
        if (args.action_sha256 is not None or args.action_bytes is not None) and args.action_dll is None:
            raise ValueError('native action integrity pins require --action-dll')
        plain_text(args.publisher, "--publisher")
        host = extension["host"]
        config = "[AppDataFolder]" + str(PureWindowsPath(host["config"]))
        if args.test_host_config is not None:
            config = plain_text(str(args.test_host_config.resolve()), "--test-host-config")
        files = payload_files(extension["payload"])
        included = include_files(extension["include"], files, args.include_root if args.include_root is not None else ROOT)
        included.update(program_files(extension["programs"], args.program, files, included, args.test_without_programs))
        files = files + sorted(included)
        inventory = {relative.as_posix(): file_pin(included.get(relative, extension['payload']/relative)) for relative in files}
        check_prepared_payload(extension, inventory)
        descriptor_pin = file_pin(args.extension)
        received = None
        if args.input_receipt is not None:
            received = dict(file_pin(args.input_receipt), declared=json.loads(args.input_receipt.read_text(encoding='utf-8')),
                            authority='Received provenance only; validated by the release producer before invocation')
            if args.action_dll is None or args.action_sha256 is None or args.action_bytes is None:
                raise ValueError('received release inputs require an explicit final action DLL and size/hash pins')
        setup = extension["python_setup"]
        if setup is not None and PurePosixPath(setup["script"]) not in files:
            raise ValueError(f"the python_setup script {setup['script']} is not a payload file at its top")
        out.mkdir(parents=True, exist_ok=True)
        (out / "payload.wxs").write_text(payload_fragment(extension["payload"], files, extension["generated"],
                                                          extension["generated_folders"], included),
                                         encoding="utf-8", newline="\n")
        action_sources=native_action_sources()
        action = args.action_dll.resolve() if args.action_dll else build_action(out, args.cl)
        if not action.is_file():
            raise ValueError(f"{action} is not a file")
        if args.action_dll is not None and (args.action_dll.is_symlink() or args.action_dll.is_junction()):
            raise ValueError('native action input must not be linked')
        if extension['register_application'] and (args.test_without_openabstractions or args.action_dll is None or args.action_sha256 is None or args.action_bytes is None):
            raise ValueError('application registration requires OpenAbstractions and an explicitly pinned validating native action')
        action_pin = file_pin(action)
        if (args.action_sha256 is None) != (args.action_bytes is None):
            raise ValueError('native action size and hash must be supplied together')
        if args.action_sha256 is not None and action_pin != {'sha256':args.action_sha256,'bytes':args.action_bytes}:
            raise ValueError('native action differs from its exact integrity pin')
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("FAIL ", error)
        return 1
    title = extension["title"]
    folder = extension["folder"]
    missing_host = (f"{title} needs {host['name']}, which was not found on this account; install it from "
                    f"{host['download']}, start it once, then run this installer again.")
    taken = (f"{host['subfolder']} already holds a {folder} folder this installer did not place; "
             f"remove it, then run this installer again.")
    msi = out / f"{extension['id']}-{args.version}.msi"
    command = [args.wix, "build", "-arch", "x64",
               "-d", f"ExtensionId={extension['id']}", "-d", f"Title={title}", "-d", f"Publisher={args.publisher}",
               "-d", f"Version={args.version}", "-d", f"UpgradeCode={upgrade_code(extension['id'])}",
               "-d", f"Folder={folder}", "-d", f"HostConfig={config}", "-d", f"HostKey={host['key']}",
               "-d", f"HostSubfolder={host['subfolder']}", "-d", f"MissingHost={missing_host}",
               "-d", f"TakenFolder={taken}", "-d", f"HostFolderDll={action}",
               "-d", f"RequireOpenAbstractions={'no' if args.test_without_openabstractions else 'yes'}",
               "-d", f"PythonSetup={'no' if setup is None else 'yes'}",
               "-d", f"RegisterApplication={'yes' if extension['register_application'] else 'no'}",
               "-d", f"SetupReturn={'check' if extension['register_application'] else 'ignore'}",
               # The venv lies in the host's folder, one above the subfolder HostFolder names.
               "-d", "SetupProgram=" + ("none" if setup is None else
                                        str(PureWindowsPath("..", setup["venv"], "Scripts", "pythonw.exe"))),
               "-d", "SetupScript=" + ("none" if setup is None else setup["script"]),
               "-o", str(msi), str(HERE / "extension.wxs"), str(out / "payload.wxs")]
    print(" ".join(command))
    if subprocess.run(command, cwd=out).returncode:
        return 1
    # Bind exactly the native and source bytes consumed by WiX. A changed
    # input refuses a receipt; signing policy is the release relay's owner.
    if file_pin(action) != action_pin or file_pin(args.extension) != descriptor_pin:
        raise ValueError('extension descriptor or native action changed during packaging')
    if native_action_sources()!=action_sources:raise ValueError('native action source/header changed during packaging')
    if received is not None and file_pin(args.input_receipt) != {key:received[key] for key in ('sha256','bytes')}:
        raise ValueError('received input provenance changed during packaging')
    for relative in files:
        if file_pin(included.get(relative, extension['payload']/relative)) != inventory[relative.as_posix()]:
            raise ValueError('extension source changed during packaging')
    app = {'id':extension['id'],'title':title,'file':str(msi),**file_pin(msi)}
    (out/'bundle-app.json').write_text(json.dumps(app,indent=2),encoding='utf-8')
    receipt = {'schema':1,'id':extension['id'],'version':args.version,'platform':'windows/amd64',
        'status':'Unsigned extension container; source/signature/runtime qualification pending',
        'descriptor':descriptor_pin,'payload':inventory,
        'includes':[{'from':entry['from'],'to':entry['to']} for entry in extension['include']],
        'native_action':dict(action_pin, supplied=args.action_dll is not None),
        'native_action_sources':action_sources,
        # Expectations from the same ordered fragment, measured source bytes.
        # The release receiver independently checks the compiled MSI tables.
        'expected_payload':{'schema':1,'msi':dict(file_pin(msi),name=msi.name),
            # Static declared MSI tree; the native action's live HostFolder
            # resolution remains a separate installed receiving boundary.
            'files':[dict(inventory[relative.as_posix()],id=f'ExtFile{index}',
                          path=f"LocalAppDataFolder/OpenAbstractions-extension-unset/{extension['folder']}/{relative.as_posix()}")
                     for index,relative in enumerate(files)],
            'binaries':[dict(action_pin,id='HostFolderAction')],'icons':[],
            **({'registration':{'schema':1,'application':extension['id'],
                 'setup_command':'"[HostFolder]'+str(PureWindowsPath('..',setup['venv'],'Scripts','pythonw.exe'))+'" -I -B "[ExtensionFolder]'+setup['script']+'"'}}
               if extension['register_application'] else {})},
        'received_input_receipt':received,'msi':dict(file_pin(msi),path=str(msi)),
        'bundle_app_sha256':file_pin(out/'bundle-app.json')['sha256'],
        'test_build':bool(args.test_host_config or args.test_without_openabstractions or args.test_without_programs)}
    (out/'installer-receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    note = ", TEST BUILD" if args.test_host_config or args.test_without_openabstractions or args.test_without_programs else ""
    print(f"ok    {msi.name} {msi.stat().st_size} bytes, {len(files)} files, UNSIGNED{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
