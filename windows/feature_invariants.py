"""Feature vocabulary and declaration-placement invariants shared by the
Windows and POSIX packagers and their checks.

installer/payload.tsv and installer/posix/payload.tsv both draw their
"feature" column from this one vocabulary: the WiX feature ids of
abstraction.wxs, lower case, because a WiX Id carries no separator. POSIX
ships no examples, no Panel and no separate developer opt-out, so its
payload.tsv uses a subset — service, localstores, modelhost and mcpgateway —
of the names below.
"""
import json

# TSV "feature" column value -> WiX <Feature Id="...">.
FEATURE_NAMES = {
    "service": "Service",
    "tools": "Tools",
    "localstores": "LocalStores",
    "modelhost": "ModelHost",
    "lemonadeimage": "LemonadeImage",
    "thenoiseimage": "TheNoiseImage",
    "pytorchimage": "PyTorchImage",
    "mcpgateway": "McpGateway",
    "developer": "Developer",
    "path": "Path",
}


def check_installed_declarations(paths, placed, authored, root, declarations):
    """Every declaration file a feature installs, and the program it names.

    A declaration file the installation places names its program the way the
    Panel is named today: a file name, resolved beside the installed runtime.
    An absolute path cannot be written here — the install location (the
    Windows install folder, or the POSIX home directory) is chosen when the
    package is installed — so the program is a sibling, and the feature that
    declares it is the feature that installs it. A declaration left behind by
    a removed program is a registry entry for something that is not there.

    root is the directory authored paths resolve against (installer/ on
    Windows, installer/posix/ on POSIX). declarations is the path prefix
    under which a payload row is a declaration file.
    """
    bad = []
    for path in sorted(p for p in paths if p.startswith(declarations)):
        source = authored.get(path)
        if source is None:
            bad.append(f"payload.tsv: {path} is a declaration file and not an authored row; "
                       f"the installation's declarations are written here and shipped as they stand")
            continue
        try:
            file = json.loads((root / source).read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            bad.append(f"{source}: unreadable declaration: {err}")
            continue
        declaration = file.get("declaration", {})
        name = declaration.get("name", "")
        if file.get("version") != 2 or file.get("declared_by") != "installation":
            bad.append(f"{source}: the installation ships version 2 declarations declared_by "
                       f"installation; this one is version {file.get('version')!r} declared_by "
                       f"{file.get('declared_by')!r}")
        if path.rsplit("/", 1)[-1] != f"{name}.json":
            bad.append(f"{source}: declares {name!r} and lands at {path}. The runtime reads a "
                       f"declaration file whose name is its declaration's name and reports any other")
        program = declaration.get("program", "")
        if declaration.get("role") == "host" or not program:
            continue
        if "/" in program or "\\" in program or program in (".", ".."):
            bad.append(f"{source}: names the program {program!r}. The install location is chosen "
                       f"when the package is installed, so a bundled provider names a file beside "
                       f"the runtime, the way the Panel is named")
            continue
        beside = path.rsplit("/", 2)[0] + "/" + program
        if placed.get(beside) != placed.get(path):
            bad.append(f"{source}: declares {program}, which {placed.get(path)} does not install at "
                       f"{beside}. The feature that declares a provider installs it, so removing the "
                       f"feature takes the declaration and the program together")
    return bad


def check_login_source(wxs, host_source=None):
    """Check package login lifetime and, when supplied, its private Go source.

    The published Windows packager receives WiX source only. The private
    source lifecycle receiver also supplies the service template owner.
    """
    import xml.etree.ElementTree as ET
    ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
    root = ET.fromstring(wxs)
    for old in ("LogonStart", "PanelTrayLogonStart"):
        if root.find(".//w:ComponentGroup[@Id='" + old + "']", ns) is not None or root.find(".//w:ComponentGroupRef[@Id='" + old + "']", ns) is not None:
            raise ValueError("unconditional login component survives: " + old)
    action = root.find(".//w:CustomAction[@Id='RemoveUserLogin']", ns)
    expected = dict(Id="RemoveUserLogin", BinaryRef="UpgradeSupervisorCode",
                    ExeCommand='service remove-login --user "[ToolsFolder]."',
                    Execute="commit", Impersonate="yes", Return="ignore")
    if action is None or action.attrib != expected:
        raise ValueError("login cleanup must use original-account Binary-table commit")
    row = root.find(".//w:InstallExecuteSequence/w:Custom[@Action='RemoveUserLogin']", ns)
    if row is None or row.attrib != dict(Action="RemoveUserLogin", Before="RemoveFiles",
            Condition='REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE AND NOT (AdminUser AND NOT ALLUSERS)'):
        raise ValueError("login cleanup must run only on final removal in supported account context")
    if host_source is not None and ("windows.SERVICE_AUTO_START" in host_source or host_source.count("windows.SERVICE_DEMAND_START") != 2):
        raise ValueError("fresh and repaired service templates must use demand start")
    result = {"legacy_login_components": 0, "cleanup": "commit"}
    if host_source is not None:
        result["service_start"] = "demand"
    return result
