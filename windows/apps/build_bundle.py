#!/usr/bin/env python3
"""Build "OpenAbstractions Setup", the WiX Burn bundle (installer/apps/bundle.wxs).

The distribution file names the core and independent Catalog packages with
their SHA-256 and size pins. Preview and release use the same command, which
projects the core-only Burn chain and owns the Setup theme:

  {"version": "X.Y.Z",
   "core": {"file": "abstraction-x64.msi", "sha256": "...", "bytes": N},
   "apps": [{"id": "comfyui", "title": "ComfyUI with OA",
             "file": "comfyui-X.Y.Z.msi", "sha256": "...", "bytes": N,
             "download_url": "https://..."}]}

A relative file is relative to the chain file. Every package is checked
against its pin before anything is built, and the core must carry its
LemonadeImage feature with lemonaded.exe, which Setup's picture plan
installs; a core built without the lemonadeimage source is refused, and so
is a core declaring a picture engine feature without every file payload.tsv
gives it. Applications are added through the Panel Catalog and retain their
independent installation and removal ownership.

BAFunctions plans no predecessor-bundle restore. Burn appends the related
bundle's uninstall after the chain; each MSI owns rollback before its commit.
The core's afterInstallFinalize upgrade removal keeps the predecessor on a
precommit failure. A later application failure keeps the committed new core,
with the vital application failure reported by Setup.

The theme is the standard bootstrapper's HyperlinkTheme, read from the pinned
WixToolset.Bal.wixext 5.0.2 extension DLL given by --bal-ext. Setup suppresses
Options and preserves the standard Repair/Uninstall and OA Finish controls.

After the build, `wix burn extract` reads the bundle's own manifest, and every
package in it must be the pinned file: the same chain order, the same size and
the SHA-512 of the same bytes. bundle-receipt.json in --out records the
bundle's and each package's SHA-256 and size. The bundle is UNSIGNED.

Usage:
  build_bundle.py --chain FILE --bal-ext DLL --util-ext DLL --upgrade-binary EXE
    --out DIR [--wix wix] --actions-dll DLL --actions-receipt JSON --actions-receipt-sha256 HEX
  build_bundle.py --installed-scope

--installed-scope is the check before a bundle is handed to someone on this
computer: the bundle installs its core per-machine, and Windows Installer
cannot upgrade an OpenAbstractions installed per-user, so it reports one and
exits 1.

Every chain requires the admitted native inputs. Core-only chains use the same
BAFunctions chain-token minter with an empty application map.

Without arguments, prints this text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / 'scripts'))
from build_app import APP_ID, MSI_VERSION, SHA256  # noqa: E402
from wix_packages import PACKAGES, embedded_wixlib  # noqa: E402
from file_boundary import EXTENDED_MARKERS, ordinary_path, plain_path, relative_beneath_existing  # noqa: E402

# WixToolset.Bal.wixext 5.0.2, the extension the owner consented to
# (2026-10-06): the NuGet package and the extension DLL inside it, as
# installer/wix_packages.py pins them.
_BAL = PACKAGES["WixToolset.Bal.wixext"]
BAL_NUPKG = _BAL["file"]
BAL_NUPKG_SHA256 = _BAL["sha256"]
BAL_NUPKG_BYTES = _BAL["bytes"]
BAL_DLL_SHA256 = _BAL["dll_sha256"]
BAL_DLL_BYTES = _BAL["dll_bytes"]
STANDARD_THEME = "wix-ir/HyperlinkTheme.xml"
STANDARD_LOCALIZATION = "wix-ir/HyperlinkTheme.wxl"
WXL = "http://wixtoolset.org/schemas/v4/wxl"
# Setup's own words over the standard HyperlinkTheme strings. Every other
# string stays as the pinned extension writes it.
STRINGS = {
    "InstallLicenseLinkText": 'Read the <a href="#">license terms</a>.',
    "ProgressHeader": "Installing OpenAbstractions",
    "ProgressLabel": "",
    "OverallProgressPackageText": "Preparing…",
    "ConfirmCancelMessage": "Cancel installing OpenAbstractions?",
    "ModifyHeader": "OpenAbstractions is installed",
    "SuccessHeader": "OpenAbstractions is ready",
    "SuccessInstallHeader": "OpenAbstractions is ready",
    "SuccessModifyHeader": "OpenAbstractions is ready",
    "SuccessRepairHeader": "OpenAbstractions is repaired",
    "SuccessRestartText": "Restart your computer to finish.",
    "FailureHeader": "OpenAbstractions wasn't installed",
    "FailureInstallHeader": "OpenAbstractions wasn't installed",
    "FailureRepairHeader": "OpenAbstractions wasn't repaired",
    "FailureHyperlinkLogText": 'Try again. The <a href="#">log file</a> shows what went wrong.',
    "FailureRestartText": "Restart your computer to finish.",
    "FilesInUseLabel": "Close these apps to continue:",
    "FilesInUseCloseRadioButton": "&Close them and reopen them afterwards",
    "FilesInUseDontCloseRadioButton": "&Keep them open and restart later",
}
# The maintenance page keeps Repair. The core package is permanent, so an
# Uninstall button would remove nothing the person sees; Windows Settings
# removes the core.
REMOVE_CAPTION = "To remove it, open Settings > Apps > Installed apps."
INSTALL_HEADING = "Install OpenAbstractions"
INSTALL_TEXT = "The services your apps share, such as models, downloads and permissions."
SUCCESS_CAPTION = "Add apps from the Catalog in OpenAbstractions."
# The success page's own controls (bundle-actions/actions.h): Finish, and
# the ticked box that opens OpenAbstractions when Setup closes.
# The Setup window's title-bar and taskbar icon: OA's icon, a BA payload
# beside the theme (bundle.wxs). Its caption is the bundle's name, which
# already ends in Setup; the standard "[WixBundleName] Setup" read
# "OpenAbstractions Setup Setup" (preview-1031m).
WINDOW_ICON = "openabstractions.ico"
WINDOW_CAPTION = "[WixBundleName]"
FINISH = "Finish"
# The OpenCode preflight's one command line: --quiet when Setup shows no UI.
PREFLIGHT_QUIET = ("WixBundleUILevel < 3", "--quiet")
PREFLIGHT_PASSIVE = ("WixBundleUILevel = 3", "--passive")
FINISH_BUTTON = "OaFinishButton"
OPEN_CHECKBOX = "OaOpenCheckbox"
OPEN_TEXT = "Open OpenAbstractions"
# The box shows after an install (6), change (7) or repair (8), never after an
# update replace, with no restart pending and Setup not elevated (the
# extension sets OaSetupElevated; --finish refuses an elevated token).
OPEN_CONDITION = ("(WixBundleAction = 6 OR WixBundleAction = 7 OR WixBundleAction = 8)"
                  " AND NOT WixStdBARestartRequired AND NOT OaSetupElevated")

WXS = "http://wixtoolset.org/schemas/v4/wxs"
BAL = "http://wixtoolset.org/schemas/v4/wxs/bal"
THM = "http://wixtoolset.org/schemas/v4/thmutil"
BURN = "http://wixtoolset.org/schemas/v4/2008/Burn"
CORE_ID = "OpenAbstractions"
PACKAGE_GROUP = "ShowcaseApplications"
# Text Burn or the theme would read as a variable, a localization string or a
# preprocessor value is refused in an application title.
TITLE = re.compile(r"(?!.*(\[|\]|[#!$]\())[^\x00-\x1f<>&]{1,64}\Z")
# The Options page controls the standard theme gives the install folder, which
# this bundle has none of: every package chooses its own folder.
FOLDER_CONTROLS = {"InstallFolder", "BrowseButton"}
FOLDER_LABEL = "#(loc.OptionsLocationLabel)"
ACTIONS_NAME = "oa_bundle_actions.dll"
ACTIONS_ROOT = HERE / "bundle-actions"
ACTIONS_SOURCES = ("actions.cpp", "actions.h", "wix5/BAFunctions.h", "wix5/IBootstrapperEngine.h",
                   "wix5/BootstrapperApplicationTypes.h", "wix5/BootstrapperEngineTypes.h", "wix5/LICENSE.TXT")


def brand_sources() -> tuple[Path, Path]:
    """OA's mark for Setup: the Panel's icon, for the Setup program and its
    registration, and its 64-pixel image, for the theme's 64x64 logo.

    The private source keeps both under monitor/icon; the published tree
    carries them beside this file. A missing published file never triggers a
    private-source lookup."""
    owner = HERE
    if owner.name == "apps" and owner.parent.name == "installer":
        icons = owner.parent.parent / "monitor" / "icon"
        selected = (icons / "panel.ico", icons / "mark-64.png")
    elif owner.name == "apps" and owner.parent.name == "windows":
        selected = (owner / "openabstractions.ico", owner / "openabstractions-64.png")
    else:
        raise ValueError("the bundle builder sits in no known source layout")
    for path in selected:
        if not path.is_file() or path.is_symlink() or path.is_junction():
            raise ValueError(f"OA's Setup mark is missing: {path.name}")
    return selected


def icon_images(data: bytes) -> list[bytes]:
    """The image bytes of an .ico file, in its directory order."""
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or kind != 1 or count == 0:
        raise ValueError("not an icon file")
    images = []
    for index in range(count):
        size, offset = struct.unpack_from("<II", data, 6 + 16 * index + 8)
        images.append(data[offset:offset + size])
    return images


def program_icon_images(program: Path) -> list[bytes]:
    """The images of a Windows program's first icon group, which Explorer and
    Apps show for it."""
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LoadLibraryExW.restype = wintypes.HMODULE
    kernel.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    kernel.FindResourceW.restype = wintypes.HRSRC
    kernel.FindResourceW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p]
    kernel.LoadResource.restype = wintypes.HGLOBAL
    kernel.LoadResource.argtypes = [wintypes.HMODULE, wintypes.HRSRC]
    kernel.LockResource.restype = ctypes.c_void_p
    kernel.LockResource.argtypes = [wintypes.HGLOBAL]
    kernel.SizeofResource.restype = wintypes.DWORD
    kernel.SizeofResource.argtypes = [wintypes.HMODULE, wintypes.HRSRC]
    kernel.FreeLibrary.argtypes = [wintypes.HMODULE]
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
    kernel.EnumResourceNamesW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, callback, ctypes.c_void_p]
    module = kernel.LoadLibraryExW(str(program), None, 0x00000002 | 0x00000020)  # as a data file and image resource
    if not module:
        raise ValueError(f"{program.name} cannot be read for its icon")
    try:
        def read(kind: int, name: int) -> bytes:
            found = kernel.FindResourceW(module, ctypes.c_void_p(name), ctypes.c_void_p(kind))
            if not found:
                raise ValueError(f"{program.name} lacks resource {kind}/{name}")
            size = kernel.SizeofResource(module, found)
            return ctypes.string_at(kernel.LockResource(kernel.LoadResource(module, found)), size)
        groups = []
        kernel.EnumResourceNamesW(module, ctypes.c_void_p(14), callback(lambda m, k, name, p: groups.append(name) or False), None)
        if not groups:
            raise ValueError(f"{program.name} has no icon")
        if groups[0] > 0xFFFF:
            group = ctypes.wstring_at(groups[0])
            found = kernel.FindResourceW(module, ctypes.c_wchar_p(group), ctypes.c_void_p(14))
            directory = ctypes.string_at(kernel.LockResource(kernel.LoadResource(module, found)), kernel.SizeofResource(module, found))
        else:
            directory = read(14, groups[0])
        count = struct.unpack_from("<HHH", directory, 0)[2]
        return [read(3, struct.unpack_from("<H", directory, 6 + 14 * index + 12)[0]) for index in range(count)]
    finally:
        kernel.FreeLibrary(module)


def brand_problems(bundle: Path, ba: Path) -> list[str]:
    """Setup that would show WiX's stock icon or logo instead of OA's mark
    (owner, 2026-10-31: "setup is missing icon"). Burn registers the bundle
    with DisplayIcon at its cached program, so the program's icon is also the
    registration's."""
    icon, logo = brand_sources()
    problems = []
    if program_icon_images(bundle) != icon_images(icon.read_bytes()):
        problems.append(f"{bundle.name} does not carry OA's icon ({icon.name})")
    shown = ba / "logo.png"
    if not shown.is_file() or shown.read_bytes() != logo.read_bytes():
        problems.append(f"the Setup window's logo is not OA's mark ({logo.name})")
    return problems + window_problems(ba, icon)


def window_problems(ba: Path, icon: Path) -> list[str]:
    """The Setup window's title bar and taskbar entry (owner, 2026-11-01:
    preview-1031m showed WiX's icon there and read "OpenAbstractions Setup
    Setup"). The theme's Window names OA's icon, a payload beside it, and its
    caption reads the bundle's name once."""
    try:
        window = ET.parse(ba / "thm.xml").getroot().find(f"{{{THM}}}Window")
        name = ET.parse(ba / "manifest.xml").getroot().find(f"{{{BURN}}}Registration/{{{BURN}}}Arp").get("DisplayName")
        strings = {node.get("Id"): node.get("Value") for node in ET.parse(ba / "thm.wxl").getroot().iter()
                   if node.tag.rsplit("}", 1)[-1] == "String"}
    except (OSError, ET.ParseError, AttributeError):
        return ["the Setup window's theme, strings or registration cannot be read"]
    problems = []
    shown = ba / (window.get("IconFile") or "") if window is not None and window.get("IconFile") else None
    if shown is None or not shown.is_file() or shown.read_bytes() != icon.read_bytes():
        problems.append(f"the Setup window's title bar does not show OA's icon ({icon.name})")
    caption = re.sub(r"#\(loc\.(\w+)\)", lambda m: strings.get(m.group(1), m.group(0)), window.get("Caption", "") if window is not None else "")
    caption = caption.replace("[WixBundleName]", name or "")
    words = caption.split()
    if caption != name or any(a == b for a, b in zip(words, words[1:])):
        problems.append(f"the Setup window's title reads {caption!r}, not the bundle's name {name!r}")
    return problems


def sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def sha512(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def variable(app_id: str) -> str:
    """The bundle variable an application's checkbox sets."""
    return "InstallApp_" + app_id.replace("-", "_")


def package_id(app_id: str) -> str:
    return "App_" + app_id.replace("-", "_")


CATALOG_ONLY_APP = "opencode"


def app_install_condition(app_id: str) -> str:
    return "0" if app_id == CATALOG_ONLY_APP else variable(app_id) + " = 1"


def preview_catalog_document(folder, version, *, built=False):
    """The local-package owner adds its freshly built OpenCode MSI after admission."""
    path = ordinary_path(Path(folder) / 'adopter_assets.json', kind='file')
    with path.open('rb') as stream:
        raw = stream.read((1 << 20) + 1)
    value = json.loads(raw) if len(raw) <= 1 << 20 else None
    if (not isinstance(value, dict) or value.get('schema') != 2 or value.get('release_tag') != 'v' + version
            or not isinstance(value.get('apps'), list) or not isinstance(value.get('extensions', []), list)):
        raise ValueError('preview Catalog needs its schema-2 package pins for this version')
    extensions = value.get('extensions', [])
    if any(not isinstance(row, dict) or 'id' not in row for row in extensions):
        raise ValueError('preview Catalog extension descriptor differs')
    opencode = [row for row in extensions if row['id'] == CATALOG_ONLY_APP]
    if len(opencode) != int(built) or (built and (opencode[0].get('file') != 'opencode-' + version + '.msi'
                                                 or opencode[0].get('version') != version)):
        raise ValueError('preview Catalog OpenCode descriptor differs from its producer stage')
    return value


def bundle_actions_inputs(app_ids: list[str], *, catalog_maintenance: bool = False) -> dict:
    """Source-only native inputs; selected IDs precede final MSI/container hashes.

    Every potential role ID is from this same chain owner. The manifest receiver
    still requires exactly the actual roles; absent potential roles never execute.
    """
    if (type(catalog_maintenance) is not bool or not isinstance(app_ids, list) or not 0 <= len(app_ids) <= 16
            or any(not isinstance(app, str) or not APP_ID.fullmatch(app) for app in app_ids)
            or len({variable(app) for app in app_ids}) != len(app_ids)):
        raise ValueError("bundle actions require a closed ordered list of unique app IDs")
    rows = [{"id": app, "variable": variable(app), "packages": [prefix + app.replace('-', '_')
             for prefix in ('App_', 'Host_', 'Preflight_', 'Preparation_')]} for app in app_ids]
    core = HERE.parent / 'abstraction.wxs'
    if core.is_symlink() or core.is_junction() or not core.is_file() or core.stat().st_nlink != 1:
        raise ValueError('canonical core feature source is missing or linked')
    features = []
    for feature in ET.parse(core).iter(f'{{{WXS}}}Feature'):
        name, level = feature.get('Id'), feature.get('Level')
        if (not name or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', name)
                or level not in ('0', '1', '1000') or feature.find(f'{{{WXS}}}Level') is not None):
            raise ValueError('unsupported canonical core feature condition or level')
        if level != '1' and any(child.get('Level') == '1' for child in feature.iter(f'{{{WXS}}}Feature') if child is not feature):
            raise ValueError('unsupported conditional core feature hierarchy')
        features.append({'id': name, 'default': level == '1'})
    if len({row['id'] for row in features}) != len(features) or not any(row['id'] == 'McpGateway' for row in features):
        raise ValueError('canonical core feature roster differs')
    header = "// Generated by build_bundle.bundle_actions_inputs; no package hashes.\n"
    header += "static const OA_BUNDLE_APP OA_BUNDLE_APPS[] = {\n"
    if not rows:
        header += '    {NULL, {NULL, NULL, NULL, NULL}, FALSE},\n'
    for row in rows:
        header += '    {L"' + row['variable'] + '", {' + ', '.join('L"' + name + '"' for name in row['packages']) + '}, ' + ('TRUE' if row['id'] == 'opencode' else 'FALSE') + '},\n'
    header += "};\nstatic const SIZE_T OA_BUNDLE_APP_COUNT = " + str(len(rows)) + ";\n"
    header += "static const BOOL OA_BUNDLE_OPENCODE_CATALOG_ONLY = " + (
        "TRUE" if CATALOG_ONLY_APP in app_ids else "FALSE") + ";\n"
    header += "static const BOOL OA_BUNDLE_CATALOG_MAINTENANCE = " + (
        "TRUE" if catalog_maintenance else "FALSE") + ";\n"
    header += 'static const OA_BUNDLE_CORE_FEATURE OA_BUNDLE_CORE_FEATURES[] = {\n'
    for row in features:
        header += '    {L"' + row['id'] + '", ' + ('TRUE' if row['default'] else 'FALSE') + '},\n'
    header += '};\nstatic const SIZE_T OA_BUNDLE_CORE_FEATURE_COUNT = sizeof(OA_BUNDLE_CORE_FEATURES) / sizeof(OA_BUNDLE_CORE_FEATURES[0]);\n'
    sources = {}
    for name in ACTIONS_SOURCES:
        path = ACTIONS_ROOT / name
        if path.is_symlink() or path.is_junction() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("bundle action source is missing or linked: " + name)
        digest, size = sha256_and_size(path)
        sources[name] = {"sha256": digest, "bytes": size}
    digest, size = sha256_and_size(core)
    inputs = {"sources": sources, "map": rows, "catalog_maintenance": catalog_maintenance,
              "core_features": {'sha256': digest, 'bytes': size, 'features': features},
              "map_header_sha256": hashlib.sha256(header.encode()).hexdigest()}
    return {"schema": 1, "inputs": inputs, "header": header, "output": ACTIONS_NAME}


def bundle_actions_compile(app_ids: list[str], out: Path, cl: str = "cl", *, catalog_maintenance: bool = False) -> list[str]:
    """The existing native producer writes inputs.header to out/actions_map.h."""
    bundle_actions_inputs(app_ids, catalog_maintenance=catalog_maintenance)
    return [cl, "/nologo", "/LD", "/O2", "/W4", "/WX", "/DUNICODE", "/D_UNICODE",
            "/I" + str(out), "/I" + str(ACTIONS_ROOT / 'wix5'),
            "/Fo" + str(out / 'actions.obj'), str(ACTIONS_ROOT / 'actions.cpp'),
            "/link", "Shell32.lib", "User32.lib", "Comctl32.lib", "Advapi32.lib", "Msi.lib", "Ole32.lib", "/OUT:" + str(out / ACTIONS_NAME),
            "/IMPLIB:" + str(out / 'oa_bundle_actions.lib')]


def check_bundle_actions(chain: dict, dll: Path, receipt_path: Path, receipt_sha256: str, *,
                         catalog_maintenance: bool = False) -> dict:
    """Compare native/map bytes from independently admitted signed-native intake.

    This is integrity/source consistency; the existing signing owner verifies
    OA signature authority and the actual embedded BA payload.
    """
    if (not isinstance(receipt_sha256, str) or not SHA256.fullmatch(receipt_sha256)
            or receipt_path.is_symlink() or receipt_path.is_junction()
            or not receipt_path.is_file() or receipt_path.stat().st_nlink != 1
            or receipt_path.stat().st_size > 1 << 20):
        raise ValueError("bundle actions require an admitted plain bounded receipt")
    with receipt_path.open('rb') as source:
        raw = source.read((1 << 20) + 1)
    if len(raw) > 1 << 20 or hashlib.sha256(raw).hexdigest() != receipt_sha256:
        raise ValueError("bundle action receipt differs from admitted bytes")
    receipt = json.loads(raw)
    expected = bundle_actions_inputs([app['id'] for app in chain['apps']], catalog_maintenance=catalog_maintenance)
    if (not isinstance(receipt, dict) or set(receipt) != {'schema', 'inputs', 'native'}
            or receipt['schema'] != 1 or receipt['inputs'] != expected['inputs']
            or not isinstance(receipt['native'], dict) or set(receipt['native']) != {'name', 'sha256', 'bytes'}
            or receipt['native']['name'] != ACTIONS_NAME or dll.name != ACTIONS_NAME
            or dll.is_symlink() or dll.is_junction() or not dll.is_file() or dll.stat().st_nlink != 1):
        raise ValueError("bundle actions differ from this source and actual chain app map")
    digest, size = sha256_and_size(dll)
    if receipt['native'] != {'name': ACTIONS_NAME, 'sha256': digest, 'bytes': size} or size <= 0:
        raise ValueError("bundle action DLL differs from admitted final native bytes")
    return dict(receipt['native'], inputs=expected['inputs'], receipt_sha256=receipt_sha256)


def chain_packages(chain: dict):
    """The existing flat chain, including an app's optional official host."""
    for app in chain["apps"]:
        if "preflight" in app.get("host", {}):
            yield "Preflight_" + app["id"].replace("-", "_"), "ExePackage", app["host"]["preflight"], app
    if 'upgrade' in chain:
        yield "BeginCoreUpgrade", "ExePackage", chain['upgrade'], None
    yield CORE_ID, "MsiPackage", chain["core"], None
    for app in chain["apps"]:
        if "host" in app:
            yield "Host_" + app["id"].replace("-", "_"), "ExePackage", app["host"], app
            if "preparation" in app["host"]:
                yield "Preparation_" + app["id"].replace("-", "_"), "ExePackage", app["host"]["preparation"], app
        if "embedded_integration" not in app:
            yield package_id(app["id"]), "MsiPackage", app, app


def embedded_integration(value: dict) -> dict:
    """Check the closed declaration; producer intake separately authenticates it."""
    if (not isinstance(value, dict) or set(value) != {
            'schema', 'distribution', 'source_policy', 'oa_integration', 'backend_manifest'}
            or value['schema'] != 1 or isinstance(value['schema'], bool)
            or value['distribution'] != 'oa-custom-desktop'):
        raise ValueError('embedded integration requires the source-owned custom Desktop profile')
    for role in ('source_policy', 'oa_integration', 'backend_manifest'):
        pin = value[role]
        fields = {'bytes', 'sha256'} | ({'name'} if role != 'source_policy' else set())
        if (not isinstance(pin, dict) or set(pin) != fields
                or not isinstance(pin['bytes'], int) or isinstance(pin['bytes'], bool) or pin['bytes'] <= 0
                or not isinstance(pin['sha256'], str) or not SHA256.fullmatch(pin['sha256'])):
            raise ValueError('embedded integration has no exact ' + role + ' pin')
        if 'name' in pin and (not isinstance(pin['name'], str) or not pin['name']
                or Path(pin['name']).name != pin['name'] or '\\' in pin['name']):
            raise ValueError('embedded integration pin must name one file')
    if value['backend_manifest']['name'] != 'backend-manifest.json':
        raise ValueError('embedded integration requires the original backend manifest')
    return value


def read_chain(path: Path) -> dict:
    """The chain file, checked for shape, with each file made absolute."""
    return validate_chain(json.loads(path.read_text(encoding="utf-8")), path.parent)


def validate_chain(chain: dict, base: Path) -> dict:
    """Validate the existing chain shape, resolving files at its receiving root."""
    chain = json.loads(json.dumps(chain))
    if not isinstance(chain, dict) or set(chain) != {"version", "core", "apps"}:
        raise ValueError("the chain file has exactly version, core and apps")
    if not isinstance(chain["version"], str) or not MSI_VERSION.match(chain["version"]):
        raise ValueError("the chain version is not X.Y.Z")
    packages = [chain["core"]] + (chain["apps"] if isinstance(chain["apps"], list) else [None])
    for index, package in enumerate(packages):
        app = index > 0
        modern = app and isinstance(package, dict) and 'embedded_integration' in package
        fields = ({'id', 'title', 'host', 'embedded_integration'} if modern else
                  {"file", "sha256", "bytes"} | ({"id", "title"} if app else set()))
        if not isinstance(package, dict) or not fields <= set(package) <= fields | ({"download_url", "host"} if app else set()):
            raise ValueError(f"package {index} has exactly {', '.join(sorted(fields))}" + (" and an optional download_url" if app else ""))
        if modern:
            if set(package) != fields or package['id'] != 'comfyui':
                raise ValueError('only the exact custom ComfyUI Desktop row embeds integration')
            embedded_integration(package['embedded_integration'])
        elif not isinstance(package["sha256"], str) or not SHA256.match(package["sha256"]) or \
                not isinstance(package["bytes"], int) or isinstance(package["bytes"], bool) or package["bytes"] <= 0:
            raise ValueError(f"package {index} has no SHA-256 and size pin")
        if not modern and (not isinstance(package["file"], str) or not package["file"]):
            raise ValueError(f"package {index} names no file")
        if not modern:
            package["file"] = str((base / package["file"]).resolve())
        if app:
            if not isinstance(package["id"], str) or not APP_ID.match(package["id"]):
                raise ValueError(f"package {index} has no application ID")
            if not isinstance(package["title"], str) or not TITLE.match(package["title"]):
                raise ValueError(f"application {package['id']} has a title Burn would not show as written")
            url = package.get("download_url")
            if url is not None and (not isinstance(url, str) or not re.fullmatch(r"https://[!-~]{1,2000}", url)):
                raise ValueError(f"application {package['id']} has a download_url that is not https")
            if "host" in package:
                host = package["host"]
                if modern and (not isinstance(host, dict) or 'preparation' not in host or 'preflight' in host):
                    raise ValueError('custom Desktop requires exactly Host and Preparation roles')
                required = {"file", "sha256", "bytes", "arp_id", "arp_version", "arp_win64"}
                if not isinstance(host, dict) or not required <= set(host) <= required | {"download_url", "preflight", "preparation"} or not ({"preflight", "preparation"} & set(host)):
                    raise ValueError("an official NSIS host has exactly its file pin and ARP identity")
                if not isinstance(host["file"], str) or not host["file"] or not isinstance(host["sha256"], str) or not SHA256.fullmatch(host["sha256"]) \
                        or not isinstance(host["bytes"], int) or isinstance(host["bytes"], bool) or host["bytes"] <= 0:
                    raise ValueError("the official host has no exact file pin")
                if not isinstance(host["arp_id"], str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", host["arp_id"]) \
                        or not isinstance(host["arp_version"], str) or not MSI_VERSION.fullmatch(host["arp_version"]) or not isinstance(host["arp_win64"], bool):
                    raise ValueError("the official host has no exact ARP identity/version")
                url = host.get("download_url")
                if url is not None and (not isinstance(url, str) or not re.fullmatch(r"https://[!-~]{1,2000}", url)):
                    raise ValueError("the official host download_url is not https")
                host["file"] = str((base / host["file"]).resolve())
                for role in ('preflight', 'preparation'):
                    if role not in host:
                        continue
                    helper = host[role]
                    if not isinstance(helper, dict) or set(helper) != {'file', 'sha256', 'bytes'} or not isinstance(helper['file'], str) or not helper['file'] \
                            or not isinstance(helper['sha256'], str) or not SHA256.fullmatch(helper['sha256']) \
                            or not isinstance(helper['bytes'], int) or isinstance(helper['bytes'], bool) or helper['bytes'] <= 0:
                        raise ValueError(f'the fixed native {role} has no exact file pin')
                    helper['file'] = str((base / helper['file']).resolve())
    variables = [variable(app["id"]) for app in chain["apps"]]
    if len(set(variables)) != len(variables):
        raise ValueError("two applications share one checkbox variable")
    return chain


def chain_context(chain: dict) -> dict:
    """Retain the validated chain shape beside its flat Burn receipt."""
    value = json.loads(json.dumps(chain))
    names = set()
    for _, _, package, _ in chain_packages(value):
        name = Path(package['file']).name
        if not name or name in names:
            raise ValueError('the flat bundle has duplicate package file names')
        names.add(name)
        package['file'] = name
        package.pop('sha512', None)
    validate_chain(value, Path('.'))
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
    return {'sha256': hashlib.sha256(encoded).hexdigest(), 'chain': value}


def burn_chain(distribution: dict) -> dict:
    """Setup installs the core; application packages belong to the Panel Catalog.

    Preview and release use this same projection. The complete authenticated
    distribution remains available to the existing Catalog/copy-chain owners.
    """
    return dict(distribution, apps=[])


def setup_actions_inputs(*, catalog_maintenance: bool = False) -> dict:
    """Native Setup roles follow the same package projection as assembly."""
    physical = burn_chain({'apps': []})
    return bundle_actions_inputs([app['id'] for app in physical['apps']],
                                 catalog_maintenance=catalog_maintenance)


def setup_command(*, python, chain, bal_ext, util_ext, upgrade_binary, out, actions_dll,
                  actions_receipt, actions_receipt_sha256, wix='wix', catalog_maintenance=False):
    """The preview and release callers invoke this single Setup assembler."""
    command = [str(python), '-B', str(HERE / 'build_bundle.py'), '--chain', str(chain),
               '--bal-ext', str(bal_ext), '--util-ext', str(util_ext),
               '--upgrade-binary', str(upgrade_binary), '--out', str(out), '--wix', str(wix),
               '--actions-dll', str(actions_dll), '--actions-receipt', str(actions_receipt),
               '--actions-receipt-sha256', str(actions_receipt_sha256)]
    if catalog_maintenance:
        command.append('--catalog-maintenance')
    return command


def read_chain_context(context: dict, root: Path) -> dict:
    if not isinstance(context, dict) or set(context) != {'sha256', 'chain'}:
        raise ValueError('the bundle has no bound chain context')
    encoded = json.dumps(context['chain'], sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
    if context['sha256'] != hashlib.sha256(encoded).hexdigest():
        raise ValueError('the bundle chain context digest differs')
    # Validate shape before traversing packages, then require flat relative names.
    chain = validate_chain(context['chain'], root)
    for _, _, package, _ in chain_packages(context['chain']):
        name = package['file']
        if name != Path(name).name or '/' in name or '\\' in name or ':' in name or name in ('.', '..'):
            raise ValueError('bundle chain context files must be flat relative names')
    if chain_context(chain) != context:
        raise ValueError('bundle chain context differs from its validated shape')
    return chain


def check_pins(chain: dict) -> None:
    """Every package is the file its pin names."""
    for _, _, package, _ in chain_packages(chain):
        digest, size = sha256_and_size(Path(package["file"]))
        if (digest, size) != (package["sha256"], package["bytes"]):
            raise ValueError(f"{Path(package['file']).name} is not the pinned package "
                             f"({size} bytes, sha256 {digest})")


PICTURE_FEATURE = "LemonadeImage"
# payload.tsv's picture engine features: Setup's picture plan adds one of them
# to the core and runs its provider from the files that feature installs.
ENGINE_FEATURES = ("lemonadeimage", "pytorchimage")


def engine_feature_files() -> dict[str, list[str]]:
    """Each picture engine feature's WiX id and the file names payload.tsv
    places with it, the provider program first."""
    from feature_invariants import FEATURE_NAMES
    from validate import rows
    files: dict[str, list[str]] = {}
    for feature, path, *_ in rows("payload.tsv"):
        if feature in ENGINE_FEATURES:
            files.setdefault(FEATURE_NAMES[feature], []).append(Path(path).name)
    return files


def core_upgrade_binary(wix: str, core: Path) -> bytes:
    """Read the incoming supervisor from the core's own Binary table."""
    with tempfile.TemporaryDirectory(prefix='oa-bundle-upgrade-') as temporary:
        root = Path(temporary)
        source, files = root/'core.wxs', root/'files'
        result = subprocess.run([wix, 'msi', 'decompile', str(core), '-x', str(files), '-o', str(source)], capture_output=True, text=True)
        if result.returncode:
            raise ValueError('cannot read core upgrade supervisor')
        rows = [row for row in ET.parse(source).iter(f'{{{WXS}}}Binary') if row.get('Id') == 'UpgradeSupervisorCode']
        if len(rows) != 1 or not rows[0].get('SourceFile'):
            raise ValueError('core has no exact UpgradeSupervisorCode')
        carried = Path(rows[0].get('SourceFile'))
        carried = root/carried if not carried.is_absolute() else carried
        plain_path(carried)
        relative_beneath_existing(carried, root)
        return carried.read_bytes()


def check_upgrade_binary(wix: str, core: Path, binary: Path) -> dict:
    """Burn executes the exact Binary-table supervisor carried by this MSI."""
    plain_path(binary)
    digest, size = sha256_and_size(binary)
    if not size:
        raise ValueError('upgrade supervisor is empty')
    carried = core_upgrade_binary(wix, core)
    if (hashlib.sha256(carried).hexdigest(), len(carried)) != (digest, size):
        raise ValueError('Burn upgrade supervisor differs from core Binary table')
    return {'file': str(binary), 'sha256': digest, 'bytes': size}


def check_core_picture_feature(wix: str, core: Path) -> None:
    """The core carries its LemonadeImage feature with lemonaded.exe in it,
    and every picture engine feature it declares carries its whole payload.

    Setup's picture plan installs one of these features (monitor/internal/
    setup feature_windows.go); a core built without the lemonadeimage source
    gates it out silently, and the bundle then offers no pictures. A declared
    PyTorchImage without its input ZIP would offer an engine Setup cannot
    prepare. Read from the core MSI itself by `wix msi decompile`, never from
    the chain's metadata."""
    with tempfile.TemporaryDirectory(prefix="oa-bundle-core-") as temporary:
        out = Path(temporary) / "core.wxs"
        result = subprocess.run([wix, "msi", "decompile", str(core), "-o", str(out)], capture_output=True, text=True)
        if result.returncode:
            raise ValueError(f"the core package could not be read: {(result.stderr or result.stdout).strip()}")
        root = ET.parse(out).getroot()
    components = {}
    for component in root.iter(f"{{{WXS}}}Component"):
        for item in component.iter(f"{{{WXS}}}File"):
            # The File table name exactly as this repository's core authors it.
            name = item.get("Name") or Path(item.get("Source", "")).name
            components.setdefault(component.get("Id"), set()).add(name)
    declared = {}
    for feature in root.iter(f"{{{WXS}}}Feature"):
        declared.setdefault(feature.get("Id"), []).append(feature)
    if len(declared.get(PICTURE_FEATURE, [])) != 1:
        raise ValueError(f"the core has no {PICTURE_FEATURE} feature; build it with the lemonadeimage source")
    for feature_id, names in engine_feature_files().items():
        found = declared.get(feature_id, [])
        if not found:
            continue
        if len(found) != 1:
            raise ValueError(f"the core declares {feature_id} more than once")
        referenced = {ref.get("Id") for ref in found[0].iter(f"{{{WXS}}}ComponentRef")}
        referenced |= {c.get("Id") for c in found[0].iter(f"{{{WXS}}}Component")}
        carried = set().union(*(components.get(identifier, set()) for identifier in referenced))
        for name in names:
            if name not in carried:
                raise ValueError(f"the core's {feature_id} feature carries no {name}")


def apps_fragment(apps: list[dict]) -> str:
    """apps.wxs: the ShowcaseApplications package group, one optional
    host EXE then integration MSI and one checkbox per application, in order."""
    def source_file(value):
        # WiX reads these paths from XML rather than from the guarded argv.
        # Keep the admitted ordinary spelling and reject unsupported namespaces.
        if any(marker in value for marker in EXTENDED_MARKERS) or plain_path(value) != Path(value):
            raise ValueError('WiX SourceFile requires an ordinary path spelling')
        return value

    ET.register_namespace("", WXS)
    ET.register_namespace("bal", BAL)
    wix = ET.Element(f"{{{WXS}}}Wix")
    fragment = ET.SubElement(wix, f"{{{WXS}}}Fragment")
    for app in apps:
        if app["id"] == CATALOG_ONLY_APP:
            continue
        ET.SubElement(fragment, f"{{{WXS}}}Variable", {
            "Name": variable(app["id"]), "Type": "numeric", "Value": "0", f"{{{BAL}}}Overridable": "yes"})
    group = ET.SubElement(fragment, f"{{{WXS}}}PackageGroup", {"Id": PACKAGE_GROUP})
    checks = ET.SubElement(fragment, f"{{{WXS}}}PackageGroup", {"Id": "SelectedApplicationPreflights"})
    for app in apps:
        condition = app_install_condition(app["id"])
        ET.SubElement(group, f"{{{WXS}}}RollbackBoundary", {"Id": "AppBoundary_" + app["id"].replace("-", "_"), "Vital": "yes"})
        if "host" in app:
            host = app["host"]
            if 'preflight' in host:
                preflight = ET.SubElement(checks,f"{{{WXS}}}ExePackage",{
                    'Id':'Preflight_'+app['id'].replace('-','_'),'SourceFile':source_file(host['preflight']['file']),
                    'Vital':'yes','Compressed':'yes','InstallCondition':condition,
                    'PerMachine':'no','Permanent':'yes','DetectCondition':'0'})
                # Without UI the preflight refuses with its exit code alone; a
                # box nobody can answer held a quiet install for 21 minutes.
                ET.SubElement(preflight, f"{{{WXS}}}CommandLine", {'Condition': PREFLIGHT_QUIET[0], 'InstallArgument': PREFLIGHT_QUIET[1]})
                ET.SubElement(preflight, f"{{{WXS}}}CommandLine", {'Condition': PREFLIGHT_PASSIVE[0], 'InstallArgument': PREFLIGHT_PASSIVE[1]})
            attributes = {"Id": "Host_" + app["id"].replace("-", "_"), "SourceFile": source_file(host["file"]), "Vital": "yes",
                          "Compressed": "no", "InstallCondition": condition, "PerMachine": "no",
                          "Permanent": "yes", "InstallArguments": "/S /currentuser"}
            if host.get("download_url"):
                attributes["DownloadUrl"] = host["download_url"]
            executable = ET.SubElement(group, f"{{{WXS}}}ExePackage", attributes)
            ET.SubElement(executable, f"{{{WXS}}}ArpEntry", {"Id": host["arp_id"], "Version": host["arp_version"], "Win64": "yes" if host["arp_win64"] else "no"})
            if 'preparation' in host:
                preparation = ET.SubElement(group, f"{{{WXS}}}ExePackage", {
                    'Id': 'Preparation_' + app['id'].replace('-', '_'), 'SourceFile': source_file(host['preparation']['file']),
                    'Vital': 'yes', 'Compressed': 'yes', 'InstallCondition': condition,
                    'PerMachine': 'no', 'Permanent': 'yes', 'DetectCondition': '0'})
                ET.SubElement(preparation, f"{{{WXS}}}CommandLine", {'Condition': 'WixBundleUILevel = 4', 'InstallArgument': '--guided'})
                ET.SubElement(preparation, f"{{{WXS}}}CommandLine", {'Condition': 'WixBundleUILevel <> 4', 'InstallArgument': '--verify-only'})
                ET.SubElement(preparation, f"{{{WXS}}}ExitCode", {'Value': '0', 'Behavior': 'success'})
                ET.SubElement(preparation, f"{{{WXS}}}ExitCode", {'Behavior': 'error'})
        if 'embedded_integration' in app:
            continue
        attributes = {"Id": package_id(app["id"]), "SourceFile": source_file(app["file"]), "Vital": "yes",
                      "Compressed": "no", "InstallCondition": condition}
        if app["id"] == CATALOG_ONLY_APP:
            attributes["Permanent"] = "yes"
        if app.get("download_url"):
            attributes["DownloadUrl"] = app["download_url"]
        ET.SubElement(group, f"{{{WXS}}}MsiPackage", attributes)
    ET.indent(wix)
    return ET.tostring(wix, encoding="unicode") + "\n"


def standard_theme(dll_path: Path, member: str = STANDARD_THEME) -> str:
    """The standard bootstrapper's HyperlinkTheme (or its strings) from the pinned extension."""
    data = dll_path.read_bytes()
    if (hashlib.sha256(data).hexdigest(), len(data)) != (BAL_DLL_SHA256, BAL_DLL_BYTES):
        raise ValueError(f"{dll_path.name} is not the pinned WixToolset.Bal.wixext 5.0.2 extension")
    return embedded_wixlib(data).read(member).decode("utf-8-sig")


def localization(standard: str) -> str:
    """bundle.wxl: the standard HyperlinkTheme strings with STRINGS in place."""
    ET.register_namespace("", WXL)
    root = ET.fromstring(standard)
    rows = {row.get("Id"): row for row in root.iter(f"{{{WXL}}}String")}
    missing = sorted(set(STRINGS) - set(rows))
    if root.tag != f"{{{WXL}}}WixLocalization" or missing:
        raise ValueError("the standard localization lacks " + ", ".join(missing or ["its WixLocalization root"]))
    for name, value in STRINGS.items():
        rows[name].set("Value", value)
    notices = "".join(m.group(0) + "\n" for m in re.finditer(r"<!--.*?-->", standard[:standard.find("<WixLocalization")], re.S))
    return '<?xml version="1.0" encoding="utf-8"?>\n' + notices + ET.tostring(root, encoding="unicode") + "\n"


def theme(standard: str, apps: list[dict], *, catalog_maintenance: bool = False) -> str:
    """Brand the standard Setup pages; applications are added in the Panel."""
    ET.register_namespace("", THM)
    root = ET.fromstring(standard, parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True)))
    window = root.find(f"{{{THM}}}Window")
    if window is None or window.get("Caption") != "#(loc.Caption)":
        raise ValueError("the standard theme has no Window with the standard caption")
    window.set("Caption", WINDOW_CAPTION)
    window.set("IconFile", WINDOW_ICON)
    options = [page for page in root.iter(f"{{{THM}}}Page") if page.get("Name") == "Options"]
    if len(options) != 1:
        raise ValueError("the standard theme has no single Options page")
    page = options[0]
    folder = [c for c in page if c.get("Name") in FOLDER_CONTROLS or (c.text or "").strip() == FOLDER_LABEL]
    if len(folder) != 3:
        raise ValueError("the standard theme's Options page is not the one this builder edits")
    for control in folder:
        page.remove(control)
    # The Install page names what Setup installs above the license line.
    install = [p for p in root.iter(f"{{{THM}}}Page") if p.get('Name') == 'Install']
    eula = [c for p in install for c in p if c.get('Name') == 'EulaHyperlink']
    if len(install) != 1 or len(eula) != 1:
        raise ValueError('the standard theme has no single Install page with its license link')
    heading = ET.Element(f"{{{THM}}}Label", {"X": "11", "Y": "80", "Width": "-11", "Height": "30",
                                             "FontId": "2", "DisablePrefix": "yes"})
    heading.text = INSTALL_HEADING
    body = ET.Element(f"{{{THM}}}Label", {"X": "11", "Y": "121", "Width": "-11", "Height": "17",
                                          "FontId": "3", "DisablePrefix": "yes"})
    body.text = INSTALL_TEXT
    heading.tail = body.tail = eula[0].tail
    eula[0].set('Y', '151')
    eula[0].set('Height', '34')
    install[0][0:0] = [heading, body]
    # The progress label is empty (STRINGS); the package text takes its place at the margin.
    pages = [p for p in root.iter(f"{{{THM}}}Page") if p.get('Name') == 'Progress']
    progress = [c for p in pages for c in p if c.get('Name') == 'OverallProgressPackageText']
    labels = [c for p in pages for c in p if (c.text or '').strip() == '#(loc.ProgressLabel)']
    if len(pages) != 1 or len(progress) != 1 or len(labels) != 1:
        raise ValueError('the standard progress page has no single label and package text')
    pages[0].remove(labels[0])
    progress[0].set('X', '11')
    maintenance = [p for p in root.iter(f"{{{THM}}}Page") if p.get('Name') == 'Modify']
    if len(maintenance) != 1:
        raise ValueError('the standard theme has no single maintenance page')
    repairs = [c for c in maintenance[0] if c.get('Name') == 'RepairButton']
    removes = [c for c in maintenance[0] if c.get('Name') == 'UninstallButton']
    if len(repairs) != 1 or len(removes) != 1:
        raise ValueError('the standard maintenance page has no single Repair and Uninstall control')
    repairs[0].set('X', removes[0].get('X'))
    at = list(maintenance[0]).index(removes[0])
    maintenance[0].remove(removes[0])
    caption = ET.Element(f"{{{THM}}}Label", {"X": "11", "Y": "121", "Width": "-11", "Height": "17",
                                             "FontId": "3", "DisablePrefix": "yes"})
    caption.text = REMOVE_CAPTION
    caption.tail = repairs[0].tail
    maintenance[0].insert(at, caption)
    # The success page (owner, 2026-10-31): Finish, plus a ticked "Open
    # OpenAbstractions" box after an install, change or repair. Finish closes
    # Setup; with the box ticked the bundle actions extension, which owns both
    # controls, first starts the Panel's Finish mode in the person's own
    # session: the setup question when there is setup to do, otherwise the
    # Panel. The verified Catalog may require the custom Finish when there
    # are no chained app packages. Other core-only bundles keep the standard
    # Finish control and load the extension for its chain-token minter.
    success = [p for p in root.iter(f"{{{THM}}}Page") if p.get("Name") == "Success"]
    if len(success) != 1:
        raise ValueError("the standard theme has no single Success page")
    page = success[0]
    launch = [c for c in page if c.get("Name") == "LaunchButton"]
    close = [c for c in page if c.get("Name") == "SuccessCloseButton"]
    if len(launch) != 1 or len(close) != 1:
        raise ValueError("the standard Success page has no single launch and close button")
    tail = launch[0].tail
    page.remove(launch[0])
    caption = ET.Element(f"{{{THM}}}Label", {"X": "11", "Y": "121", "Width": "-11", "Height": "17",
                                             "FontId": "3", "DisablePrefix": "yes"})
    caption.text = SUCCESS_CAPTION
    caption.tail = tail
    page.insert(list(page).index(close[0]), caption)
    if not apps and not catalog_maintenance:
        text = close[0].find(f"{{{THM}}}Text")
        (text if text is not None else close[0]).text = FINISH
    else:
        at = list(page).index(close[0])
        page.remove(close[0])
        box = ET.Element(f"{{{THM}}}Checkbox", {"Name": OPEN_CHECKBOX, "X": "11", "Y": "147", "Width": "-11", "Height": "17",
                                                "TabStop": "yes", "FontId": "3",
                                                "VisibleCondition": OPEN_CONDITION})
        box.text = OPEN_TEXT
        finish = ET.Element(f"{{{THM}}}Button", {"Name": FINISH_BUTTON, "X": "-11", "Y": "-11", "Width": "75", "Height": "23",
                                                "TabStop": "yes", "FontId": "0"})
        finish.text = FINISH
        box.tail = finish.tail = tail
        page[at:at] = [box, finish]
    # The parser keeps no comment outside the root element; the standard
    # theme's copyright and license notice is carried over as written.
    notices = "".join(m.group(0) + "\n" for m in re.finditer(r"<!--.*?-->", standard[:standard.find("<Theme")], re.S))
    return '<?xml version="1.0" encoding="utf-8"?>\n' + notices + ET.tostring(root, encoding="unicode") + "\n"


def manifest_chain(manifest: str) -> list[dict]:
    """The packages the built bundle's manifest names, in chain order, each
    with its payload's size and SHA-512."""
    root = ET.fromstring(manifest)
    ns = {"b": BURN}
    payloads = {p.get("Id"): p for p in root.findall("b:Payload", ns)}
    chain = []
    for package in root.find("b:Chain", ns):
        if package.tag not in {f"{{{BURN}}}MsiPackage", f"{{{BURN}}}ExePackage"}:
            raise ValueError("unexpected package type in the built flat chain")
        refs = package.findall("b:PayloadRef", ns)
        if not refs:
            raise ValueError(f"package {package.get('Id')} names no payload")
        payload = payloads[refs[0].get("Id")]
        chain.append({"id": package.get("Id"), "type": package.tag.rsplit("}", 1)[-1], "bytes": int(payload.get("FileSize")),
                      "sha512": bytes.fromhex(payload.get("Hash")).hex(), "vital": package.get("Vital"),
                      "condition": package.get("InstallCondition"),
                      "per_machine": package.get("PerMachine"),
                      "cache": package.get("Cache"),
                      "permanent": package.get("Permanent"),
                      "boundary_forward": package.get("RollbackBoundaryForward"),
                      "arguments": package.get("InstallArguments", ""),
                      "repair_arguments": package.get("RepairArguments", ""),
                      "uninstall_arguments": package.get("UninstallArguments", ""),
                      "command_lines": [(p.get('Condition'), p.get('InstallArgument', ''), p.get('RepairArgument', ''), p.get('UninstallArgument', '')) for p in package.findall('b:CommandLine', ns)],
                      "exit_codes": [(p.get('Code'), p.get('Type')) for p in package.findall('b:ExitCode', ns)],
                      "packaging": payload.get('Packaging'),
                      "detection": package.get("DetectionType"),
                      "detect_condition": package.get("DetectCondition"),
                      "arp_id": package.get("ArpId"), "arp_version": package.get("ArpDisplayVersion"),
                      "arp_win64": package.get("ArpWin64", "no"),
                      "allusers": [(p.get("Value"), p.get("Condition"))
                                   for p in package.findall("b:MsiProperty[@Id='ALLUSERS']", ns)],
                      "upgrade_chain": [(p.get("Value"), p.get("Condition"))
                                   for p in package.findall("b:MsiProperty[@Id='OAUPGRADECHAIN']", ns)],
                      "features": [p.get('Id') for p in package.findall('b:MsiFeature', ns)]})
    return chain


def elevation_problems(manifest: str) -> list[str]:
    """Authoring that would let Burn do per-machine work without elevating, or
    let a bundle upgrade remove a per-machine package (upgrade_problems).

    The bundle asks for administrator rights whenever it needs them and never
    fails with access denied (owner, 2026-10-31). Burn elevates for a
    per-machine package it executes. A per-user bundle registers itself
    per-user and skips cross-scope dependency registration, so the remaining
    per-machine work is caching: "keep" caches a per-machine package that is
    already present and planned to do nothing, and "force" caches it whatever
    the plan, both into the per-machine package cache with no elevation
    (preview-1031d). "remove" caches a package only while it executes, inside
    the elevated step. A per-machine bundle elevates for everything."""
    root = ET.fromstring(manifest)
    registration = root.find(f"{{{BURN}}}Registration")
    if registration is not None and registration.get("PerMachine") == "yes":
        return []
    problems = []
    for package in root.find(f"{{{BURN}}}Chain"):
        if package.get("PerMachine") == "yes" and package.get("Cache") != "remove":
            problems.append(f"per-machine package {package.get('Id')} has Cache={package.get('Cache')}: a per-user run could "
                            "cache it into the per-machine package cache without elevating; it must be Cache=remove")
    return problems + upgrade_problems(root)


def upgrade_problems(root: ET.Element) -> list[str]:
    """Authoring that would let a bundle upgrade remove a per-machine package.

    A per-user bundle registers no dependency on a per-machine package (Burn
    logs "Skipping cross-scope dependency registration"). When an upgrade then
    removes the earlier bundle, that bundle's uninstall finds no other
    dependent and uninstalls the package (preview-1031f lost its core). A
    permanent package is never uninstalled by a bundle; it must also stay
    visible (no ARPSYSTEMCOMPONENT) so the person can remove it from Apps."""
    registration = root.find(f"{{{BURN}}}Registration")
    if registration is not None and registration.get("PerMachine") == "yes":
        return []
    problems = []
    for package in root.find(f"{{{BURN}}}Chain"):
        if package.get("PerMachine") != "yes":
            continue
        # This condition-only command has no installed product to remove. Its
        # uninstall command is the existing rollback activation, not removal.
        if (package.tag == f'{{{BURN}}}ExePackage' and package.get('Id') == 'BeginCoreUpgrade'
                and package.get('DetectionType') == 'condition' and package.get('DetectCondition') == 'false'
                and package.get('InstallCondition') == 'OACorePrior = 5 AND WixBundleAction = 6'
                and package.get('InstallArguments') == 'service begin-upgrade --machine --installed --chain [OAUpgradeChain]'
                and package.get('UninstallArguments') == 'service start --machine'
                and package.get('Vital') == 'no' and package.get('Cache') == 'remove'):
            continue
        if package.get("Permanent") != "yes":
            problems.append(f"per-machine package {package.get('Id')} is not Permanent: a per-user bundle holds no dependency "
                            "on it, so an upgrade that removes an earlier bundle would uninstall it")
        if any(item.get("Id") == "ARPSYSTEMCOMPONENT" and item.get("Value") == "1"
               for item in package.findall(f"{{{BURN}}}MsiProperty")):
            problems.append(f"permanent per-machine package {package.get('Id')} is hidden from Apps; it must stay visible "
                            "so the person can remove it")
    return problems


def apps_entry_problems(manifest: str) -> list[str]:
    """Authoring that would give the person a second Apps entry.

    The person sees one entry, the core "OpenAbstractions" (owner,
    2026-10-31). Burn hides a bundle's own entry, writing SystemComponent,
    only when its Arp registration disables both modify and remove; the
    bundle stays registered for related-bundle upgrades and its cache."""
    registration = ET.fromstring(manifest).find(f"{{{BURN}}}Registration")
    arp = registration.find(f"{{{BURN}}}Arp") if registration is not None else None
    if arp is None or arp.get("DisableModify") != "yes" or arp.get("DisableRemove") != "yes":
        return ["the bundle would have its own Apps entry beside the core; its registration must set "
                "DisableModify=yes and DisableRemove=yes"]
    return []


def check_manifest(manifest: str, chain: dict) -> list[dict]:
    """The bundle carries the pinned packages in the chain's order."""
    built = manifest_chain(manifest)
    expected = list(chain_packages(chain))
    boundaries = {item.get("Id"): item for item in ET.fromstring(manifest).findall(f"{{{BURN}}}RollbackBoundary")}
    active_boundary = None
    if [p["id"] for p in built] != [i for i, _, _, _ in expected]:
        raise ValueError(f"the bundle's chain is {[p['id'] for p in built]}, not {[i for i, _, _, _ in expected]}")
    core = next(package for package in built if package['id'] == CORE_ID)
    if core["per_machine"] != "yes" or core["allusers"] != [("1", None)]:
        raise ValueError("the core must be per-machine with unconditional ALLUSERS=1")
    if 'upgrade' in chain and core['upgrade_chain'] != [('[OAUpgradeChain]', None)]:
        raise ValueError('the core MSI must receive the per-run upgrade chain token')
    for problem in elevation_problems(manifest) + apps_entry_problems(manifest):
        raise ValueError(problem)
    features = core['features']
    # Every admitted bundle carries the same native core-feature planner,
    # including a Catalog-only chain with no physical application packages.
    allowed = {row['id'] for row in bundle_actions_inputs([])['inputs']['core_features']['features']}
    if not features or len(features) != len(set(features)) or not {'McpGateway', 'LemonadeImage', 'PyTorchImage'} <= set(features) or not set(features) <= allowed:
        raise ValueError('every bundle requires canonical core feature planning including McpGateway')
    for found, (identifier, kind, package, app) in zip(built, expected):
        active_boundary = found["boundary_forward"] or active_boundary
        if identifier == 'BeginCoreUpgrade':
            if (found['type'] != 'ExePackage' or found['vital'] != 'no' or found['per_machine'] != 'yes'
                    or found['cache'] != 'remove' or found['condition'] != 'OACorePrior = 5 AND WixBundleAction = 6'
                    or found['arguments'] != 'service begin-upgrade --machine --installed --chain [OAUpgradeChain]'
                    or found['uninstall_arguments'] != 'service start --machine' or found['detection'] != 'condition'
                    or found['detect_condition'] != 'false' or found['permanent'] != 'no' or found['packaging'] != 'embedded'
                    or found['bytes'] != package['bytes'] or found['sha512'] != package['sha512']):
                raise ValueError('early upgrade package changed its scope, planning, command or pinned bytes')
            continue
        if found["type"] != kind or found["vital"] != "yes":
            raise ValueError("a selected package must keep its type and report failure")
        if app is not None and (found["per_machine"] != "no" or found["allusers"] or found["condition"] != app_install_condition(app["id"])):
            raise ValueError("application packages must keep their per-user install condition")
        if app is not None and app["id"] == CATALOG_ONLY_APP and found["permanent"] != "yes":
            raise ValueError("Catalog-owned OpenCode packages must be permanent")
        if kind == "ExePackage" and found["permanent"] != "yes":
            raise ValueError("the official Desktop keeps its own removal ownership")
        if app is not None and not identifier.startswith('Preflight_'):
            boundary = "AppBoundary_" + app["id"].replace("-", "_")
            if active_boundary != boundary or boundary not in boundaries or boundaries[boundary].get("Vital") != "yes" or boundaries[boundary].get("Transaction") != "no":
                raise ValueError("a selected application's vital boundary must preserve the completed core")
        preparation = identifier.startswith('Preparation_')
        if preparation and (found['arguments'] or found['repair_arguments'] or found['uninstall_arguments'] or found['packaging'] != 'embedded'
                or found['command_lines'] != [('WixBundleUILevel = 4', '--guided', '', ''), ('WixBundleUILevel <> 4', '--verify-only', '', '')]
                or found['exit_codes'] != [('0', '1'), ('*', '2')]):
            raise ValueError('the fixed preparation must keep its disjoint UI modes, embedded payload and zero-only success')
        if kind == "ExePackage" and 'arp_id' not in package and not preparation and (found['arguments']!='' or found['detection']!='condition'
                or found['detect_condition']!='0' or found['command_lines'] != [(PREFLIGHT_QUIET[0], PREFLIGHT_QUIET[1], '', ''), (PREFLIGHT_PASSIVE[0], PREFLIGHT_PASSIVE[1], '', '')]):
            raise ValueError('the fixed read-only preflight must run before its host without arguments, --quiet only without UI')
        if kind == "ExePackage" and 'arp_id' in package and (found["arguments"] != "/S /currentuser" or found["detection"] != "arp"
                or found["arp_id"] != package["arp_id"] or found["arp_version"] != package["arp_version"]
                or found["arp_win64"] != ("yes" if package["arp_win64"] else "no")):
            raise ValueError("the official host changed its command or ARP binding")
        if found["bytes"] != package["bytes"] or found["sha512"] != package["sha512"]:
            raise ValueError(f"the bundle's {found['id']} is not the pinned package")
    return built


def wix_burn_manifest(wix: str, bundle: Path) -> str:
    """The manifest of a built bundle, through `wix burn extract`."""
    with tempfile.TemporaryDirectory() as temp:
        command = [wix, "burn", "extract", str(bundle), "-oba", temp]
        if subprocess.run(command).returncode:
            raise ValueError("wix burn extract failed")
        return (Path(temp) / "manifest.xml").read_text(encoding="utf-8-sig")


def bundle_readback(wix: str, bundle: Path) -> tuple[str, list[str]]:
    """A built bundle's manifest and brand_problems, through one `wix burn extract`."""
    with tempfile.TemporaryDirectory() as temp:
        if subprocess.run([wix, "burn", "extract", str(bundle), "-oba", temp]).returncode:
            raise ValueError("wix burn extract failed")
        return (Path(temp) / "manifest.xml").read_text(encoding="utf-8-sig"), brand_problems(bundle, Path(temp))


def core_upgrade_code() -> str:
    """The core package's UpgradeCode, from the canonical core source."""
    package = ET.parse(HERE.parent / "abstraction.wxs").getroot().find(f"{{{WXS}}}Package")
    code = package.get("UpgradeCode") if package is not None else None
    if not code or not re.fullmatch(r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", code):
        raise ValueError("the canonical core source names no UpgradeCode")
    return "{" + code.upper() + "}"


def installed_related_products(upgrade_code: str) -> list[dict]:
    """Every product Windows Installer lists for upgrade_code on this account,
    with its install context: AssignmentType 0 per-user, 1 per-machine."""
    import ctypes
    msi = ctypes.WinDLL("msi")
    products = []
    for index in range(256):
        buffer = ctypes.create_unicode_buffer(39)
        status = msi.MsiEnumRelatedProductsW(upgrade_code, 0, index, buffer)
        if status == 259:  # ERROR_NO_MORE_ITEMS
            return products
        if status:
            raise OSError(f"Windows Installer could not list products for {upgrade_code}: error {status}")
        def info(name):
            size = ctypes.c_uint(1024)
            value = ctypes.create_unicode_buffer(size.value)
            return value.value if msi.MsiGetProductInfoW(buffer.value, name, value, ctypes.byref(size)) == 0 else ""
        products.append({"product": buffer.value, "assignment": info("AssignmentType"),
                         "version": info("VersionString"), "location": info("InstallLocation")})
    raise OSError("too many related products")


def installed_scope_conflicts(related: list[dict]) -> list[str]:
    """The bundle installs its core per-machine (ForcePerMachine). Windows
    Installer upgrades a product only within its own install context, so a
    per-user OpenAbstractions stays installed beside the new per-machine core
    (preview-1031c, 2026-10-31). One sentence per such product."""
    return [f"OpenAbstractions {row['version'] or '?'} is installed per-user ({row['product']}"
            + (f", {row['location']}" if row['location'] else "")
            + "); this bundle installs the core per-machine and cannot upgrade it. Uninstall it first."
            for row in related if row.get("assignment") != "1"]


def external_output_inputs(chain: dict, out: Path) -> list:
    """Reserve fresh WiX output names without exposing admitted input aliases."""
    selected = []
    for _, _, package, app in chain_packages(chain):
        if app is None:
            continue
        source = Path(package['file'])
        destination = out / source.name
        ordinary_path(destination, kind='file', allow_missing=True)
        ordinary_path(source, kind="file")
        if source.stat().st_nlink != 1 or os.path.lexists(destination):
            raise ValueError('external package requires a single-link input and fresh output')
        selected.append((source, destination, sha256_and_size(source), source.stat()))
    return selected


def independent_external_outputs(selected: list) -> None:
    """Detach only WiX-created aliases of exact authenticated package inputs."""
    for source, destination, expected, admitted in selected:
        ordinary_path(source, kind="file")
        ordinary_path(destination, kind="file")
        before, output = source.stat(), destination.stat()
        if (before.st_dev, before.st_ino, before.st_mtime_ns) != (admitted.st_dev, admitted.st_ino, admitted.st_mtime_ns):
            raise ValueError('WiX external input changed identity')
        if sha256_and_size(source) != expected or sha256_and_size(destination) != expected:
            raise ValueError('WiX external package differs from its admitted bytes')
        if output.st_nlink == 1:
            if before.st_nlink != 1:
                raise ValueError('WiX external input acquired an unrelated link')
            continue
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if identity(before) != identity(output) or before.st_nlink != 2 or output.st_nlink != 2:
            raise ValueError('WiX external output is not its exact new input alias')
        descriptor, temporary = tempfile.mkstemp(prefix='.external-', dir=destination.parent)
        try:
            with os.fdopen(descriptor, 'wb') as copy, source.open('rb') as original:
                if identity(os.fstat(original.fileno())) != identity(before):
                    raise ValueError('WiX external input changed before copying')
                shutil.copyfileobj(original, copy, length=1 << 20)
                copy.flush()
                os.fsync(copy.fileno())
            if (sha256_and_size(Path(temporary)) != expected or
                    identity(source.stat()) != identity(before) or
                    identity(destination.stat()) != identity(output)):
                raise ValueError('WiX external package changed while copying')
            ordinary_path(destination, kind="file")
            os.replace(temporary, destination)
            if (source.stat().st_nlink != 1 or destination.stat().st_nlink != 1 or
                    sha256_and_size(source) != expected or sha256_and_size(destination) != expected):
                raise ValueError('WiX external package did not retain independent exact bytes')
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_bundle.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--installed-scope", action="store_true",
                        help="before handing a bundle to someone on this computer: report an installed "
                             "OpenAbstractions the per-machine core cannot upgrade, and exit 1 if there is one")
    parser.add_argument("--chain", type=Path)
    parser.add_argument("--bal-ext", type=Path)
    parser.add_argument("--util-ext", type=Path, help="Pinned WiX 5.0.2 Util extension for native core product search")
    parser.add_argument("--upgrade-binary", type=Path, help="Exact UpgradeSupervisorCode binary from the core MSI")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--wix", default="wix")
    parser.add_argument("--actions-dll", type=Path, help="Final OA-signed BAFunctions DLL from admitted native intake")
    parser.add_argument("--actions-receipt", type=Path, help="Existing native producer's source/map/final-DLL facts")
    parser.add_argument("--actions-receipt-sha256", help="Independent admitted native receipt pin")
    parser.add_argument("--catalog-maintenance", action="store_true",
                        help="The verified distribution includes a Catalog desktop integration update")
    args = parser.parse_args(argv)
    if args.installed_scope:
        try:
            conflicts = installed_scope_conflicts(installed_related_products(core_upgrade_code()))
        except (OSError, ValueError, ET.ParseError) as error:
            print("FAIL ", error)
            return 1
        for line in conflicts:
            print("FAIL ", line)
        if not conflicts:
            print("ok    no installed OpenAbstractions in another install context")
        return 1 if conflicts else 0
    if all(value is None for value in (args.chain, args.bal_ext, args.util_ext, args.upgrade_binary, args.out,
                                      args.actions_dll, args.actions_receipt, args.actions_receipt_sha256)):
        parser.print_help()
        return 0
    if args.chain is None or args.bal_ext is None or args.out is None:
        parser.error("--chain, --bal-ext and --out are required")
    out = args.out.resolve()
    try:
        distribution = read_chain(args.chain.resolve())
        check_pins(distribution)
        chain = burn_chain(distribution)
        context = chain_context(chain)
        check_core_picture_feature(args.wix, Path(chain["core"]["file"]))
        action_args = (args.actions_dll, args.actions_receipt, args.actions_receipt_sha256)
        if not all(action_args):
            raise ValueError('every bundle requires the admitted signed bundle actions DLL and receipt')
        actions = check_bundle_actions(chain, *action_args, catalog_maintenance=args.catalog_maintenance)
        if args.util_ext is None or args.upgrade_binary is None:
            raise ValueError('every bundle requires --util-ext and --upgrade-binary')
        util = PACKAGES['WixToolset.Util.wixext']
        if sha256_and_size(args.util_ext) != (util['dll_sha256'], util['dll_bytes']):
            raise ValueError('Util extension differs from pinned WiX 5.0.2')
        chain['upgrade'] = check_upgrade_binary(args.wix, Path(chain['core']['file']), args.upgrade_binary.resolve())
        names = [Path(package['file']).name for _,_,package,_ in chain_packages(chain)]
        if len(names) != len(set(names)):
            raise ValueError('upgrade supervisor collides with a flat bundle package name')
        for _, _, package, _ in chain_packages(chain):
            package["sha512"] = sha512(Path(package["file"]))
        external = external_output_inputs(chain, out)
        out.mkdir(parents=True, exist_ok=True)
        upgrade = Path(chain['upgrade']['file'])
        carried_upgrade = out/upgrade.name
        if upgrade != carried_upgrade:
            shutil.copyfile(upgrade, carried_upgrade)
        if sha256_and_size(carried_upgrade) != (chain['upgrade']['sha256'], chain['upgrade']['bytes']):
            raise ValueError('upgrade supervisor changed while copying into flat bundle')
        chain['upgrade']['file'] = str(carried_upgrade)
        (out / "apps.wxs").write_text(apps_fragment(chain["apps"]), encoding="utf-8", newline="\n")
        icon, logo = brand_sources()
        (out / "bundle.thm").write_text(theme(standard_theme(args.bal_ext), chain["apps"],
                                             catalog_maintenance=args.catalog_maintenance),
                                        encoding="utf-8", newline="\n")
        (out / "bundle.wxl").write_text(localization(standard_theme(args.bal_ext, STANDARD_LOCALIZATION)),
                                        encoding="utf-8", newline="\n")
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, json.JSONDecodeError, ET.ParseError) as error:
        print("FAIL ", error)
        return 1
    bundle = out / f"OpenAbstractions-Setup-{chain['version']}.exe"
    command = [args.wix, "build", "-arch", "x64", "-ext", str(args.bal_ext.resolve()), "-ext", str(args.util_ext.resolve()),
               "-d", f"Version={chain['version']}", "-d", f"CoreMsi={chain['core']['file']}",
               "-d", f"UpgradeBinary={chain['upgrade']['file']}",
               "-d", f"ThemeFile={out / 'bundle.thm'}", "-d", f"LocalizationFile={out / 'bundle.wxl'}",
               "-d", f"BundleIcon={icon}", "-d", f"BundleLogo={logo}",
               "-d", "SuppressOptionsUI=yes",
               "-d", "CoreFeatureSelection=yes",
               *(["-d", f"BundleActions={args.actions_dll.resolve()}"] if actions else []),
               "-o", str(bundle), str(HERE / "bundle.wxs"), str(out / "apps.wxs")]
    print(" ".join(command))
    if subprocess.run(command, cwd=out).returncode:
        return 1
    try:
        independent_external_outputs(external)
        manifest, brand = bundle_readback(args.wix, bundle)
        built = check_manifest(manifest, chain)
        for problem in brand:
            raise ValueError(problem)
        if actions and check_bundle_actions(chain, *action_args, catalog_maintenance=args.catalog_maintenance) != actions:
            raise ValueError('bundle actions changed during bundle build')
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        print("FAIL ", error)
        return 1
    digest, size = sha256_and_size(bundle)
    receipt = {"bundle": {"name": bundle.name, "sha256": digest, "bytes": size, "signed": False},
               "chain_context": context,
               "extension": {"name": BAL_NUPKG, "sha256": BAL_NUPKG_SHA256, "bytes": BAL_NUPKG_BYTES},
               "chain": [{"id": found["id"], "name": Path(package["file"]).name, "sha256": package["sha256"],
                          "bytes": package["bytes"], "vital": found["vital"] == "yes",
                          "per_machine": found["per_machine"] == "yes"}
                         for found, (_, _, package, _) in zip(built, chain_packages(chain))]}
    if actions:
        receipt['bootstrapper_native'] = actions
    (out / "bundle-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    for entry in receipt["chain"]:
        print(f"ok    {entry['id']} {entry['name']} {entry['bytes']} bytes sha256 {entry['sha256']}")
    print(f"ok    {bundle.name} {size} bytes sha256 {digest}, {len(built)} packages, UNSIGNED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
