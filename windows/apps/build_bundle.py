#!/usr/bin/env python3
"""Build "OpenAbstractions Setup", the WiX Burn bundle (installer/apps/bundle.wxs).

The bundle chains the core OpenAbstractions MSI with the optional showcase
application MSIs that installer/apps/build_app.py builds (VISION 2026-10-06).
The chain file names every package with its SHA-256 and size pin:

  {"version": "X.Y.Z",
   "core": {"file": "abstraction-x64.msi", "sha256": "...", "bytes": N},
   "apps": [{"id": "comfyui", "title": "ComfyUI with OA",
             "file": "comfyui-X.Y.Z.msi", "sha256": "...", "bytes": N,
             "download_url": "https://..."}]}

A relative file is relative to the chain file. Every package is checked
against its pin before anything is built. The chain is the core first, then
the applications in the chain file's order; each application is optional, not
vital, outside the bundle's container (downloaded from download_url when it is
not beside the bundle) and installed only when its checkbox is ticked.

The theme is the standard bootstrapper's HyperlinkTheme, read from the
WixToolset.Bal.wixext 5.0.2 extension DLL given by --bal-ext, with the Options
page's folder controls replaced by one checkbox per application. That DLL must
be the pinned one (BAL_DLL_SHA256).

After the build, `wix burn extract` reads the bundle's own manifest, and every
package in it must be the pinned file: the same chain order, the same size and
the SHA-512 of the same bytes. bundle-receipt.json in --out records the
bundle's and each package's SHA-256 and size. The bundle is UNSIGNED.

Usage:
  build_bundle.py --chain FILE --bal-ext DLL --out DIR [--wix wix]

Without arguments, prints this text.
"""

from __future__ import annotations

import argparse
import hashlib
import io
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
from build_app import APP_ID, MSI_VERSION, SHA256  # noqa: E402
from wix_packages import PACKAGES  # noqa: E402

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


def read_chain(path: Path) -> dict:
    """The chain file, checked for shape, with each file made absolute."""
    chain = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(chain, dict) or set(chain) != {"version", "core", "apps"}:
        raise ValueError("the chain file has exactly version, core and apps")
    if not isinstance(chain["version"], str) or not MSI_VERSION.match(chain["version"]):
        raise ValueError("the chain version is not X.Y.Z")
    packages = [chain["core"]] + (chain["apps"] if isinstance(chain["apps"], list) else [None])
    for index, package in enumerate(packages):
        app = index > 0
        fields = {"file", "sha256", "bytes"} | ({"id", "title"} if app else set())
        if not isinstance(package, dict) or not fields <= set(package) <= fields | ({"download_url"} if app else set()):
            raise ValueError(f"package {index} has exactly {', '.join(sorted(fields))}" + (" and an optional download_url" if app else ""))
        if not isinstance(package["sha256"], str) or not SHA256.match(package["sha256"]) or \
                not isinstance(package["bytes"], int) or isinstance(package["bytes"], bool) or package["bytes"] <= 0:
            raise ValueError(f"package {index} has no SHA-256 and size pin")
        if not isinstance(package["file"], str) or not package["file"]:
            raise ValueError(f"package {index} names no file")
        package["file"] = str((path.parent / package["file"]).resolve())
        if app:
            if not isinstance(package["id"], str) or not APP_ID.match(package["id"]):
                raise ValueError(f"package {index} has no application ID")
            if not isinstance(package["title"], str) or not TITLE.match(package["title"]):
                raise ValueError(f"application {package['id']} has a title Burn would not show as written")
            url = package.get("download_url")
            if url is not None and (not isinstance(url, str) or not re.fullmatch(r"https://[!-~]{1,2000}", url)):
                raise ValueError(f"application {package['id']} has a download_url that is not https")
    variables = [variable(app["id"]) for app in chain["apps"]]
    if len(set(variables)) != len(variables):
        raise ValueError("two applications share one checkbox variable")
    return chain


def check_pins(chain: dict) -> None:
    """Every package is the file its pin names."""
    for package in [chain["core"], *chain["apps"]]:
        digest, size = sha256_and_size(Path(package["file"]))
        if (digest, size) != (package["sha256"], package["bytes"]):
            raise ValueError(f"{Path(package['file']).name} is not the pinned package "
                             f"({size} bytes, sha256 {digest})")


def apps_fragment(apps: list[dict]) -> str:
    """apps.wxs: the ShowcaseApplications package group, one optional
    MsiPackage and one checkbox variable per application, in order."""
    ET.register_namespace("", WXS)
    ET.register_namespace("bal", BAL)
    wix = ET.Element(f"{{{WXS}}}Wix")
    fragment = ET.SubElement(wix, f"{{{WXS}}}Fragment")
    for app in apps:
        ET.SubElement(fragment, f"{{{WXS}}}Variable", {
            "Name": variable(app["id"]), "Type": "numeric", "Value": "0", f"{{{BAL}}}Overridable": "yes"})
    group = ET.SubElement(fragment, f"{{{WXS}}}PackageGroup", {"Id": PACKAGE_GROUP})
    for app in apps:
        attributes = {"Id": package_id(app["id"]), "SourceFile": app["file"], "Vital": "no",
                      "Compressed": "no", "InstallCondition": variable(app["id"]) + " = 1"}
        if app.get("download_url"):
            attributes["DownloadUrl"] = app["download_url"]
        ET.SubElement(group, f"{{{WXS}}}MsiPackage", attributes)
    ET.indent(wix)
    return ET.tostring(wix, encoding="unicode") + "\n"


def embedded_wixlib(dll: bytes) -> zipfile.ZipFile:
    """The bootstrapper wixlib the extension DLL carries as a resource: a ZIP
    whose end record is the last one in the DLL."""
    end = dll.rfind(b"PK\x05\x06")
    if end < 0:
        raise ValueError("the extension DLL carries no wixlib")
    comment = int.from_bytes(dll[end + 20:end + 22], "little")
    return zipfile.ZipFile(io.BytesIO(dll[:end + 22 + comment]))


def standard_theme(dll_path: Path) -> str:
    """The standard bootstrapper's HyperlinkTheme from the pinned extension."""
    data = dll_path.read_bytes()
    if (hashlib.sha256(data).hexdigest(), len(data)) != (BAL_DLL_SHA256, BAL_DLL_BYTES):
        raise ValueError(f"{dll_path.name} is not the pinned WixToolset.Bal.wixext 5.0.2 extension")
    return embedded_wixlib(data).read(STANDARD_THEME).decode("utf-8-sig")


def theme(standard: str, apps: list[dict]) -> str:
    """The standard theme with the Options page's folder controls replaced by
    one checkbox per application; every other page is left as it is."""
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
        label.text = "Also install these applications:"
        controls.append(label)
    for index, app in enumerate(apps):
        box = ET.Element(f"{{{THM}}}Checkbox", {"Name": variable(app["id"]), "X": "11", "Y": str(143 + 22 * index),
                                                "Width": "-11", "Height": "17", "TabStop": "yes", "FontId": "3"})
        box.text = app["title"]
        controls.append(box)
    for control in controls:
        control.tail = tail
    page[at:at] = controls
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
        refs = package.findall("b:PayloadRef", ns)
        if not refs:
            raise ValueError(f"package {package.get('Id')} names no payload")
        payload = payloads[refs[0].get("Id")]
        chain.append({"id": package.get("Id"), "bytes": int(payload.get("FileSize")),
                      "sha512": bytes.fromhex(payload.get("Hash")).hex(), "vital": package.get("Vital"),
                      "condition": package.get("InstallCondition"),
                      "per_machine": package.get("PerMachine"),
                      "allusers": [(p.get("Value"), p.get("Condition"))
                                   for p in package.findall("b:MsiProperty[@Id='ALLUSERS']", ns)]})
    return chain


def check_manifest(manifest: str, chain: dict) -> list[dict]:
    """The bundle carries the pinned packages in the chain's order."""
    built = manifest_chain(manifest)
    expected = [(CORE_ID, chain["core"])] + [(package_id(app["id"]), app) for app in chain["apps"]]
    if [p["id"] for p in built] != [i for i, _ in expected]:
        raise ValueError(f"the bundle's chain is {[p['id'] for p in built]}, not {[i for i, _ in expected]}")
    if built[0]["per_machine"] != "yes" or built[0]["allusers"] != [("1", None)]:
        raise ValueError("the core must be per-machine with unconditional ALLUSERS=1")
    for found, (_, package) in zip(built, expected):
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
    args = parser.parse_args(argv)
    if args.chain is None and args.bal_ext is None and args.out is None:
        parser.print_help()
        return 0
    if args.chain is None or args.bal_ext is None or args.out is None:
        parser.error("--chain, --bal-ext and --out are required")
    out = args.out.resolve()
    try:
        chain = read_chain(args.chain.resolve())
        check_pins(chain)
        for package in [chain["core"], *chain["apps"]]:
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
               "-o", str(bundle), str(HERE / "bundle.wxs"), str(out / "apps.wxs")]
    print(" ".join(command))
    if subprocess.run(command, cwd=out).returncode:
        return 1
    try:
        built = check_manifest(wix_burn_manifest(args.wix, bundle), chain)
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        print("FAIL ", error)
        return 1
    digest, size = sha256_and_size(bundle)
    receipt = {"bundle": {"name": bundle.name, "sha256": digest, "bytes": size, "signed": False},
               "extension": {"name": BAL_NUPKG, "sha256": BAL_NUPKG_SHA256, "bytes": BAL_NUPKG_BYTES},
               "chain": [{"id": found["id"], "name": Path(package["file"]).name, "sha256": package["sha256"],
                          "bytes": package["bytes"], "vital": found["vital"] == "yes",
                          "per_machine": found["per_machine"] == "yes"}
                         for found, package in zip(built, [chain["core"], *chain["apps"]])]}
    (out / "bundle-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    for entry in receipt["chain"]:
        print(f"ok    {entry['id']} {entry['name']} {entry['bytes']} bytes sha256 {entry['sha256']}")
    print(f"ok    {bundle.name} {size} bytes sha256 {digest}, {len(built)} packages, UNSIGNED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
