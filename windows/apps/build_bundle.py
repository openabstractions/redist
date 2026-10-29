#!/usr/bin/env python3
"""Build "OpenAbstractions Setup", the WiX Burn bundle (installer/apps/bundle.wxs).

The bundle chains the core OpenAbstractions MSI with optional showcase
applications. An application can carry its official NSIS host EXE before
the integration MSI that installer/apps/build_app.py builds (VISION 2026-10-06).
The chain file names every package with its SHA-256 and size pin:

  {"version": "X.Y.Z",
   "core": {"file": "abstraction-x64.msi", "sha256": "...", "bytes": N},
   "apps": [{"id": "comfyui", "title": "ComfyUI with OA",
             "file": "comfyui-X.Y.Z.msi", "sha256": "...", "bytes": N,
             "download_url": "https://..."}]}

A relative file is relative to the chain file. Every package is checked
against its pin before anything is built. The chain is the core first, then
the applications in the chain file's order. Each application's checkbox selects
its vital packages and rollback boundary. A failure preserves the completed
core and remains visible. Packages stay outside the bundle's container and
use download_url when absent beside the bundle. An official host keeps its
separate uninstall ownership.

The theme is the standard bootstrapper's HyperlinkTheme, read from the
WixToolset.Bal.wixext 5.0.2 extension DLL given by --bal-ext, with the Options
page's folder controls replaced by one checkbox per application. That DLL must
be the pinned one (BAL_DLL_SHA256).
The maintenance page reuses these choices through its existing Repair action.
The source-bound BAFunctions DLL preserves unchecked installed applications
and plans selected absent application packages during install/modify/repair.

After the build, `wix burn extract` reads the bundle's own manifest, and every
package in it must be the pinned file: the same chain order, the same size and
the SHA-512 of the same bytes. bundle-receipt.json in --out records the
bundle's and each package's SHA-256 and size. The bundle is UNSIGNED.

Usage:
  build_bundle.py --chain FILE --bal-ext DLL --out DIR [--wix wix]
    [--actions-dll DLL --actions-receipt JSON --actions-receipt-sha256 HEX]

Application chains require all three admitted native inputs. Core-only chains
use the standard bootstrapper without an extension.

Without arguments, prints this text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
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
from file_boundary import EXTENDED_MARKERS, plain_path  # noqa: E402

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


def bundle_actions_inputs(app_ids: list[str]) -> dict:
    """Source-only native inputs; selected IDs precede final MSI/container hashes.

    Every potential role ID is from this same chain owner. The manifest receiver
    still requires exactly the actual roles; absent potential roles never execute.
    """
    if (not isinstance(app_ids, list) or not 0 < len(app_ids) <= 16
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
    for row in rows:
        header += '    {L"' + row['variable'] + '", {' + ', '.join('L"' + name + '"' for name in row['packages']) + '}, ' + ('TRUE' if row['id'] == 'opencode' else 'FALSE') + '},\n'
    header += "};\nstatic const SIZE_T OA_BUNDLE_APP_COUNT = sizeof(OA_BUNDLE_APPS) / sizeof(OA_BUNDLE_APPS[0]);\n"
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
    inputs = {"sources": sources, "map": rows, "core_features": {'sha256': digest, 'bytes': size, 'features': features},
              "map_header_sha256": hashlib.sha256(header.encode()).hexdigest()}
    return {"schema": 1, "inputs": inputs, "header": header, "output": ACTIONS_NAME}


def bundle_actions_compile(app_ids: list[str], out: Path, cl: str = "cl") -> list[str]:
    """The existing native producer writes inputs.header to out/actions_map.h."""
    bundle_actions_inputs(app_ids)
    return [cl, "/nologo", "/LD", "/O2", "/W4", "/WX", "/DUNICODE", "/D_UNICODE",
            "/I" + str(out), "/I" + str(ACTIONS_ROOT / 'wix5'),
            "/Fo" + str(out / 'actions.obj'), str(ACTIONS_ROOT / 'actions.cpp'),
            "/link", "Shell32.lib", "Msi.lib", "/OUT:" + str(out / ACTIONS_NAME),
            "/IMPLIB:" + str(out / 'oa_bundle_actions.lib')]


def check_bundle_actions(chain: dict, dll: Path, receipt_path: Path, receipt_sha256: str) -> dict:
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
    expected = bundle_actions_inputs([app['id'] for app in chain['apps']])
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
    yield CORE_ID, "MsiPackage", chain["core"], None
    for app in chain["apps"]:
        if "host" in app:
            if "preflight" in app["host"]:
                yield "Preflight_" + app["id"].replace("-", "_"), "ExePackage", app["host"]["preflight"], app
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
        ET.SubElement(fragment, f"{{{WXS}}}Variable", {
            "Name": variable(app["id"]), "Type": "numeric", "Value": "0", f"{{{BAL}}}Overridable": "yes"})
    group = ET.SubElement(fragment, f"{{{WXS}}}PackageGroup", {"Id": PACKAGE_GROUP})
    for app in apps:
        ET.SubElement(group, f"{{{WXS}}}RollbackBoundary", {"Id": "AppBoundary_" + app["id"].replace("-", "_"), "Vital": "yes"})
        if "host" in app:
            host = app["host"]
            if 'preflight' in host:
                ET.SubElement(group,f"{{{WXS}}}ExePackage",{
                    'Id':'Preflight_'+app['id'].replace('-','_'),'SourceFile':source_file(host['preflight']['file']),
                    'Vital':'yes','Compressed':'yes','InstallCondition':variable(app['id'])+' = 1',
                    'PerMachine':'no','Permanent':'yes','DetectCondition':'0'})
            attributes = {"Id": "Host_" + app["id"].replace("-", "_"), "SourceFile": source_file(host["file"]), "Vital": "yes",
                          "Compressed": "no", "InstallCondition": variable(app["id"]) + " = 1", "PerMachine": "no",
                          "Permanent": "yes", "InstallArguments": "/S /currentuser"}
            if host.get("download_url"):
                attributes["DownloadUrl"] = host["download_url"]
            executable = ET.SubElement(group, f"{{{WXS}}}ExePackage", attributes)
            ET.SubElement(executable, f"{{{WXS}}}ArpEntry", {"Id": host["arp_id"], "Version": host["arp_version"], "Win64": "yes" if host["arp_win64"] else "no"})
            if 'preparation' in host:
                preparation = ET.SubElement(group, f"{{{WXS}}}ExePackage", {
                    'Id': 'Preparation_' + app['id'].replace('-', '_'), 'SourceFile': source_file(host['preparation']['file']),
                    'Vital': 'yes', 'Compressed': 'yes', 'InstallCondition': variable(app['id']) + ' = 1',
                    'PerMachine': 'no', 'Permanent': 'yes', 'DetectCondition': '0'})
                ET.SubElement(preparation, f"{{{WXS}}}CommandLine", {'Condition': 'WixBundleUILevel = 4', 'InstallArgument': '--guided'})
                ET.SubElement(preparation, f"{{{WXS}}}CommandLine", {'Condition': 'WixBundleUILevel <> 4', 'InstallArgument': '--verify-only'})
                ET.SubElement(preparation, f"{{{WXS}}}ExitCode", {'Value': '0', 'Behavior': 'success'})
                ET.SubElement(preparation, f"{{{WXS}}}ExitCode", {'Behavior': 'error'})
        if 'embedded_integration' in app:
            continue
        attributes = {"Id": package_id(app["id"]), "SourceFile": source_file(app["file"]), "Vital": "yes",
                      "Compressed": "no", "InstallCondition": variable(app["id"]) + " = 1"}
        if app.get("download_url"):
            attributes["DownloadUrl"] = app["download_url"]
        ET.SubElement(group, f"{{{WXS}}}MsiPackage", attributes)
    ET.indent(wix)
    return ET.tostring(wix, encoding="unicode") + "\n"


def standard_theme(dll_path: Path) -> str:
    """The standard bootstrapper's HyperlinkTheme from the pinned extension."""
    data = dll_path.read_bytes()
    if (hashlib.sha256(data).hexdigest(), len(data)) != (BAL_DLL_SHA256, BAL_DLL_BYTES):
        raise ValueError(f"{dll_path.name} is not the pinned WixToolset.Bal.wixext 5.0.2 extension")
    return embedded_wixlib(data).read(STANDARD_THEME).decode("utf-8-sig")


def theme(standard: str, apps: list[dict]) -> str:
    """Use the existing Options and Repair planning controls for add/repair.

    The BAFunctions payload preserves unselected packages and admits selected
    missing packages during Repair. It owns planning; the theme only selects.
    """
    ET.register_namespace("", THM)
    root = ET.fromstring(standard, parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True)))
    options = [page for page in root.iter(f"{{{THM}}}Page") if page.get("Name") == "Options"]
    if len(options) != 1:
        raise ValueError("the standard theme has no single Options page")
    page = options[0]
    folder = [c for c in page if c.get("Name") in FOLDER_CONTROLS or (c.text or "").strip() == FOLDER_LABEL]
    if len(folder) != 3:
        raise ValueError("the standard theme's Options page is not the one this builder edits")
    at = list(page).index(folder[0])
    tail = folder[0].tail
    for control in folder:
        page.remove(control)
    controls = []
    if apps:
        label = ET.Element(f"{{{THM}}}Label", {"X": "11", "Y": "121", "Width": "-11", "Height": "17",
                                               "FontId": "3", "DisablePrefix": "yes"})
        label.text = "Choose apps to install or repair. Unchecked installed apps are kept."
        controls.append(label)
    for index, app in enumerate(apps):
        box = ET.Element(f"{{{THM}}}Checkbox", {"Name": variable(app["id"]), "X": "11", "Y": str(143 + 22 * index),
                                                "Width": "-11", "Height": "17", "TabStop": "yes", "FontId": "3"})
        box.text = app["title"]
        controls.append(box)
    for control in controls:
        control.tail = tail
    page[at:at] = controls
    if apps:
        maintenance = [p for p in root.iter(f"{{{THM}}}Page") if p.get('Name') == 'Modify']
        if len(maintenance) != 1:
            raise ValueError('the standard theme has no single maintenance page')
        repairs = [c for c in maintenance[0] if c.get('Name') == 'RepairButton']
        if len(repairs) != 1:
            raise ValueError('the standard maintenance page has no single Repair planning control')
        repairs[0].text = 'Apply app choices'
        choose = ET.SubElement(maintenance[0], f"{{{THM}}}Button", {
            'Name':'ChooseAppOptionsButton','X':'11','Y':'121','Width':'170','Height':'23',
            'TabStop':'yes','FontId':'0'})
        ET.SubElement(choose, f"{{{THM}}}Text").text = 'Choose applications'
        ET.SubElement(choose, f"{{{THM}}}ChangePageAction", {'Page':'Options'})
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
                      "features": [p.get('Id') for p in package.findall('b:MsiFeature', ns)]})
    return chain


def check_manifest(manifest: str, chain: dict) -> list[dict]:
    """The bundle carries the pinned packages in the chain's order."""
    built = manifest_chain(manifest)
    expected = list(chain_packages(chain))
    boundaries = {item.get("Id"): item for item in ET.fromstring(manifest).findall(f"{{{BURN}}}RollbackBoundary")}
    active_boundary = None
    if [p["id"] for p in built] != [i for i, _, _, _ in expected]:
        raise ValueError(f"the bundle's chain is {[p['id'] for p in built]}, not {[i for i, _, _, _ in expected]}")
    if built[0]["per_machine"] != "yes" or built[0]["allusers"] != [("1", None)]:
        raise ValueError("the core must be per-machine with unconditional ALLUSERS=1")
    features = built[0]['features']
    if any(app['id'] == 'opencode' for app in chain['apps']):
        allowed = {row['id'] for row in bundle_actions_inputs(['opencode'])['inputs']['core_features']['features']}
        if not features or len(features) != len(set(features)) or 'McpGateway' not in features or not set(features) <= allowed:
            raise ValueError('selected OpenCode requires canonical core feature planning including McpGateway')
    elif features:
        raise ValueError('unrelated/core-only bundle must preserve ordinary core feature selection')
    for found, (identifier, kind, package, app) in zip(built, expected):
        active_boundary = found["boundary_forward"] or active_boundary
        if found["type"] != kind or found["vital"] != "yes":
            raise ValueError("a selected package must keep its type and report failure")
        if app is not None and (found["per_machine"] != "no" or found["allusers"] or found["condition"] != variable(app["id"]) + " = 1"):
            raise ValueError("application packages must be per-user under their one checkbox")
        if kind == "ExePackage" and found["permanent"] != "yes":
            raise ValueError("the official Desktop keeps its own removal ownership")
        if app is not None:
            boundary = "AppBoundary_" + app["id"].replace("-", "_")
            if active_boundary != boundary or boundary not in boundaries or boundaries[boundary].get("Vital") != "yes" or boundaries[boundary].get("Transaction") != "no":
                raise ValueError("a selected application's vital boundary must preserve the completed core")
        preparation = identifier.startswith('Preparation_')
        if preparation and (found['arguments'] or found['repair_arguments'] or found['uninstall_arguments'] or found['packaging'] != 'embedded'
                or found['command_lines'] != [('WixBundleUILevel = 4', '--guided', '', ''), ('WixBundleUILevel <> 4', '--verify-only', '', '')]
                or found['exit_codes'] != [('0', '1'), ('*', '2')]):
            raise ValueError('the fixed preparation must keep its disjoint UI modes, embedded payload and zero-only success')
        if kind == "ExePackage" and 'arp_id' not in package and (found['arguments']!='' or found['detection']!='condition' or found['detect_condition']!='0'):
            raise ValueError('the fixed read-only preflight must run before its host without arguments')
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_bundle.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chain", type=Path)
    parser.add_argument("--bal-ext", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--wix", default="wix")
    parser.add_argument("--actions-dll", type=Path, help="Final OA-signed BAFunctions DLL from admitted native intake")
    parser.add_argument("--actions-receipt", type=Path, help="Existing native producer's source/map/final-DLL facts")
    parser.add_argument("--actions-receipt-sha256", help="Independent admitted native receipt pin")
    args = parser.parse_args(argv)
    if all(value is None for value in (args.chain, args.bal_ext, args.out,
                                      args.actions_dll, args.actions_receipt, args.actions_receipt_sha256)):
        parser.print_help()
        return 0
    if args.chain is None or args.bal_ext is None or args.out is None:
        parser.error("--chain, --bal-ext and --out are required")
    out = args.out.resolve()
    try:
        chain = read_chain(args.chain.resolve())
        check_pins(chain)
        context = chain_context(chain)
        action_args = (args.actions_dll, args.actions_receipt, args.actions_receipt_sha256)
        if chain['apps']:
            if not all(action_args):
                raise ValueError('optional apps require the admitted signed bundle actions DLL and receipt')
            actions = check_bundle_actions(chain, *action_args)
        elif any(action_args):
            raise ValueError('a core-only bundle has no optional-app native action payload')
        else:
            actions = None
        for _, _, package, _ in chain_packages(chain):
            package["sha512"] = sha512(Path(package["file"]))
        out.mkdir(parents=True, exist_ok=True)
        (out / "apps.wxs").write_text(apps_fragment(chain["apps"]), encoding="utf-8", newline="\n")
        (out / "bundle.thm").write_text(theme(standard_theme(args.bal_ext), chain["apps"]),
                                        encoding="utf-8", newline="\n")
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, json.JSONDecodeError, ET.ParseError) as error:
        print("FAIL ", error)
        return 1
    bundle = out / f"OpenAbstractions-Setup-{chain['version']}.exe"
    command = [args.wix, "build", "-arch", "x64", "-ext", str(args.bal_ext.resolve()),
               "-d", f"Version={chain['version']}", "-d", f"CoreMsi={chain['core']['file']}",
               "-d", f"ThemeFile={out / 'bundle.thm'}",
               "-d", f"SuppressOptionsUI={'no' if chain['apps'] else 'yes'}",
               "-d", f"CoreFeatureSelection={'yes' if any(app['id'] == 'opencode' for app in chain['apps']) else 'no'}",
               *(["-d", f"BundleActions={args.actions_dll.resolve()}"] if actions else []),
               "-o", str(bundle), str(HERE / "bundle.wxs"), str(out / "apps.wxs")]
    print(" ".join(command))
    if subprocess.run(command, cwd=out).returncode:
        return 1
    try:
        built = check_manifest(wix_burn_manifest(args.wix, bundle), chain)
        if actions and check_bundle_actions(chain, *action_args) != actions:
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
