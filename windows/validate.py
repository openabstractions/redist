import argparse
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEATURES = {"service": "Service", "tools": "Tools", "developer": "Developer"}
FILELESS = {"Path"}
KINDS = {"gobuild", "copy", "authored"}
SUBSYSTEMS = {"console", "windows"}
WIDTH = 7

MACHINE, USER = "ALLUSERS", "NOT ALLUSERS"
SCOPES = {"for everyone": True, "just for me": False}
# What starts the supervisor, in each scope. Both arms exist or one scope
# installs the programs and nothing that ever runs them.
ARMS = {True: "SupervisorServiceMarker", False: "LogonStartShortcut"}
SUPERVISOR_ACTIONS = ("RegisterSupervisor", "RollbackSupervisor", "UnregisterSupervisor", "StopPreviousSupervisor",
                      "BeginMachineUpgradeExclusion", "EndMachineUpgradeExclusion", "RestartPreviousSupervisor")
UPGRADE_CONDITIONS = {"machine": "ALLUSERS AND WIX_UPGRADE_DETECTED AND NOT REMOVE",
                      "user": "NOT ALLUSERS AND WIX_UPGRADE_DETECTED AND NOT REMOVE"}
# The early script, in order. For each scope: hold the upgrade exclusion,
# register its release on commit, register the rollback restart, then stop the
# predecessor. InstallExecute flushes all eight before any file is replaced,
# and rollback runs them in reverse: release and restart after the files are
# restored. (action, scope, ExeCommand, Execute, Impersonate, Return)
UPGRADE_CHAIN = (
    ("BeginMachineUpgradeExclusion", "machine",
     'service begin-upgrade --machine "[APPLICATIONFOLDER]." --related "[WIX_UPGRADE_DETECTED]"', "deferred", "no", "check"),
    ("EndMachineUpgradeExclusion", "machine", "service end-upgrade --machine", "commit", "no", "check"),
    ("RestartPreviousSupervisor", "machine", "service start --machine", "rollback", "no", "ignore"),
    ("StopPreviousSupervisor", "machine", "service stop", "deferred", "no", "check"),
    ("BeginUserUpgradeExclusion", "user",
     'service begin-upgrade --user "[APPLICATIONFOLDER]." --related "[WIX_UPGRADE_DETECTED]"', "deferred", "yes", "check"),
    ("EndUserUpgradeExclusion", "user", "service end-upgrade --user", "commit", "yes", "check"),
    ("RestartPreviousUserSupervisor", "user", 'service start --related "[WIX_UPGRADE_DETECTED]"', "rollback", "yes", "ignore"),
    ("StopPreviousUserSupervisor", "user",
     'service stop --user "[APPLICATIONFOLDER]." --related "[WIX_UPGRADE_DETECTED]"', "deferred", "yes", "check"),
)
# Nothing else stops this package's processes, so removal stops its own. It
# follows the upgrade chain in the early script, and InstallExecute flushes it
# with them, before RemoveFiles.
# (action, ExeCommand, Execute, Impersonate, Return, After, Condition)
REMOVAL_STOPS = (
    ("StopUserSupervisorOnRemoval", 'service stop --user "[APPLICATIONFOLDER]."',
     "deferred", "yes", "check", "StopPreviousUserSupervisor",
     'NOT ALLUSERS AND REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE'),
    ("StopSupervisorOnRemoval", "service stop",
     "deferred", "no", "check", "StopUserSupervisorOnRemoval",
     'ALLUSERS AND REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE'),
)
# After the new version is committed, and only then, the predecessor is
# removed. (action, Execute, Return, After, Condition)
LATE_REMOVAL = (
    ("RollbackSupervisor", "rollback", "ignore", "InstallFiles",
     'ALLUSERS AND NOT (REMOVE="ALL") AND NOT WIX_UPGRADE_DETECTED'),
    ("RegisterSupervisor", "deferred", "check", "RollbackSupervisor",
     'ALLUSERS AND NOT (REMOVE="ALL") AND NOT WIX_UPGRADE_DETECTED'),
    ("RegisterSupervisorAfterRemoval", "immediate", "check", "RemoveExistingProducts",
     "ALLUSERS AND WIX_UPGRADE_DETECTED AND NOT REMOVE"),
    ("StartUserRuntime", "immediate", "check", "RegisterSupervisorAfterRemoval",
     'NOT ALLUSERS AND NOT (REMOVE="ALL") AND NOT UPGRADINGPRODUCTCODE'),
)
UPGRADE_MESSAGES = {
    "StopPreviousSupervisor": "abstraction.wxs: incoming checked stop must execute before the new files replace the "
                              "predecessor's, and the old product must be removed only after InstallFinalize",
    "StopPreviousUserSupervisor": "abstraction.wxs: incoming checked per-user stop must run impersonated from the embedded "
                                  "jobd Binary against [APPLICATIONFOLDER] and the related products' recorded folders "
                                  "before the new files replace the predecessor's",
    "RestartPreviousUserSupervisor": "abstraction.wxs: a failed per-user upgrade must restart the stopped predecessor from "
                                     "a rollback action scheduled before StopPreviousUserSupervisor",
}


def rows(name):
    out = []
    for line in (HERE / name).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith(">"):
            continue
        out.append([f.strip() for f in line.split("\t") if f.strip()])
    return out[1:]


def untag(el):
    return el.tag.split("}")[-1]


UNREGISTER_CONDITION = 'ALLUSERS AND REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE'


def check_supervisor_removal(root):
    actions = {el.get("Id"): el for el in root.iter() if untag(el) == "CustomAction"}
    action = actions.get("UnregisterSupervisor")
    if action is None or action.get("Return") != "check":
        return ["abstraction.wxs: supervisor removal must propagate shutdown failure before payload removal"]
    sequence = next((el for el in root.iter()
                     if untag(el) == "Custom" and el.get("Action") == "UnregisterSupervisor"), None)
    if sequence is None or sequence.get("Before") != "RemoveFiles":
        return ["abstraction.wxs: checked supervisor removal must precede RemoveFiles"]
    # A successor removes this product after it has registered the shared
    # service name for itself. Deleting the service there is what a shipped
    # 0.1.5 does to us; this package does it to nobody.
    if sequence.get("Condition") != UNREGISTER_CONDITION:
        return ["abstraction.wxs: supervisor removal must run for a real uninstall only, under exactly "
                f"{UNREGISTER_CONDITION!r}, so a successor's registration survives this product's removal"]
    return []


def check_upgrade_shutdown(root):
    def find(tag, key=None, value=None):
        return next((el for el in root.iter() if untag(el) == tag
                     and (key is None or el.get(key) == value)), None)

    bad = []
    major = find("MajorUpgrade")
    binary = find("Binary", "Id", "UpgradeSupervisorCode")
    if (major is None or major.get("Schedule") != "afterInstallFinalize"
            or binary is None or binary.get("SourceFile") != "payload/tools/jobd.exe"):
        bad.append(UPGRADE_MESSAGES["StopPreviousSupervisor"])
    previous = "InstallInitialize"
    for action, scope, command, execute, impersonate, returns in UPGRADE_CHAIN:
        element = find("CustomAction", "Id", action)
        row = find("Custom", "Action", action)
        expected = {"BinaryRef": "UpgradeSupervisorCode", "ExeCommand": command,
                    "Execute": execute, "Impersonate": impersonate, "Return": returns}
        ok = (element is not None and element.get("FileRef") is None
              and all(element.get(k) == v for k, v in expected.items())
              and row is not None and row.get("After") == previous and row.get("Before") is None
              and row.get("Condition") == UPGRADE_CONDITIONS[scope])
        if not ok:
            token = "the installing user's token" if impersonate == "yes" else "an administrator token"
            bad.append(UPGRADE_MESSAGES.get(action, (
                f"abstraction.wxs: {action} must be a {execute} action with {token} and return={returns}, "
                f"running `{command}` from the embedded incoming jobd after {previous} for {scope} upgrades")))
        previous = action
    for action, command, execute, impersonate, returns, after, condition in REMOVAL_STOPS:
        element = find("CustomAction", "Id", action)
        row = find("Custom", "Action", action)
        if (element is None or element.get("BinaryRef") != "UpgradeSupervisorCode"
                or element.get("ExeCommand") != command or element.get("Execute") != execute
                or element.get("Impersonate") != impersonate or element.get("Return") != returns
                or row is None or row.get("After") != after or row.get("Before") is not None
                or row.get("Condition") != condition):
            token = "the installing user's token" if impersonate == "yes" else "an administrator token"
            bad.append(f"abstraction.wxs: {action} must be a {execute} action with {token} "
                       f"and return={returns}, running `{command}` from the embedded jobd after {after} under "
                       f"exactly {condition!r}: the Restart Manager is disabled, so nothing else ends the "
                       "supervisor before the removal script runs")
        else:
            previous = action
    flush = find("InstallExecute")
    if flush is None or flush.get("After") != previous:
        bad.append("abstraction.wxs: the early InstallExecute must flush every incoming stop, and the "
                   "removal stop, before RemoveFiles and InstallFiles")
    manager = find("Property", "Id", "MSIRESTARTMANAGERCONTROL")
    if manager is None or manager.get("Value") != "Disable":
        bad.append("abstraction.wxs: MSIRESTARTMANAGERCONTROL must be an authored Property set to Disable. "
                   "The Restart Manager shuts the supervisor down at InstallValidate, before the action "
                   "that records what to restart, and its session opens before the first sequenced action, "
                   "so a SetProperty arrives too late")
    for action, execute, returns, after, condition in LATE_REMOVAL:
        element = find("CustomAction", "Id", action)
        row = find("Custom", "Action", action)
        if (element is None or element.get("Execute") != execute or element.get("Return") != returns
                or row is None or row.get("After") != after or row.get("Before") is not None
                or row.get("Condition") != condition):
            bad.append(f"abstraction.wxs: {action} must be an {execute} action with return={returns}, "
                       f"scheduled after {after} under exactly {condition!r}, so the predecessor's own "
                       "uninstall cannot delete the shared supervisor service this version registered")
    return bad


# Per-user activation's reviewed condition. The elevated refusal is exactly this
# condition with AdminUser, so it fires wherever activation would refuse the token.
START_USER_RUNTIME_CONDITION = 'NOT ALLUSERS AND NOT (REMOVE="ALL") AND NOT UPGRADINGPRODUCTCODE'


def check_elevated_scope(root):
    def find(tag, key, value):
        return next((el for el in root.iter() if untag(el) == tag and el.get(key) == value), None)

    def scheduled(action):
        return [(untag(sequence), el) for sequence in root.iter()
                if untag(sequence) in ("InstallExecuteSequence", "InstallUISequence")
                for el in sequence if untag(el) == "Custom" and el.get("Action") == action]

    bad = []
    detection = find("Property", "Id", "MSIUSEREALADMINDETECTION")
    if detection is None or detection.get("Value") != "1":
        bad.append("abstraction.wxs: AdminUser must report the installing token (MSIUSEREALADMINDETECTION=1); "
                   "otherwise a policy-elevated standard user is refused")
    start = find("CustomAction", "Id", "StartUserRuntime")
    start_rows = scheduled("StartUserRuntime")
    if (start is None or "--require-unelevated" not in (start.get("ExeCommand") or "").split()
            or len(start_rows) != 1 or start_rows[0][1].get("Condition") != START_USER_RUNTIME_CONDITION):
        bad.append("abstraction.wxs: per-user activation must keep --require-unelevated under its reviewed condition")
    refusal = find("CustomAction", "Id", "RefuseElevatedPerUserInstall")
    if refusal is None or set(refusal.attrib) != {"Id", "Error"} or "ALLUSERS=1" not in refusal.get("Error", ""):
        bad.append("abstraction.wxs: RefuseElevatedPerUserInstall must be an error action naming ALLUSERS=1")
    rows = scheduled("RefuseElevatedPerUserInstall")
    expected = "AdminUser AND " + START_USER_RUNTIME_CONDITION
    if (len(rows) != 1 or rows[0][0] != "InstallExecuteSequence" or rows[0][1].get("Before") != "CostInitialize"
            or rows[0][1].get("After") is not None or rows[0][1].get("Condition") != expected):
        bad.append("abstraction.wxs: an elevated per-user install must be refused in InstallExecuteSequence "
                   f"before CostInitialize under exactly {expected!r}")
    return bad


def gated_sources(text):
    stack, gated = [], {}
    for line in text.splitlines():
        for d in re.finditer(r"<\?(if|endif)\b(.*?)\?>", line):
            if d.group(1) == "endif":
                if stack:
                    stack.pop()
                continue
            v = re.search(r"\$\(var\.(\w+)\)", d.group(2))
            stack.append(v.group(1) if v else "?")
        m = re.search(r'Source="payload/([^"]+)"', line)
        if m and stack:
            gated[m.group(1)] = stack[-1]
    return gated


def scoped(root):
    where, conditions = {}, {}
    for group in (el for el in root.iter() if untag(el) == "ComponentGroup"):
        for c in (x for x in group.iter() if untag(x) == "Component"):
            cid = c.get("Id") or next(
                (f.get("Id") for f in c if untag(f) == "File"), "?")
            where[cid] = group.get("Id")
            conditions[cid] = c.get("Condition")
    return where, conditions


def installs(condition, machine):
    if condition is None:
        return True
    return machine if condition == MACHINE else not machine


def wxs_features(root):
    groups, features = {}, {}
    for el in root.iter():
        tag = untag(el)
        if tag == "ComponentGroup":
            groups[el.get("Id")] = [
                f.get("Source", "")[len("payload/"):]
                for f in el.iter()
                if untag(f) == "File"
            ]
        elif tag == "Feature":
            features[el.get("Id")] = [
                r.get("Id") for r in el.iter() if untag(r) == "ComponentGroupRef"
            ]
    return groups, features


def folders(root):
    parent = {}
    for el in root.iter():
        for child in el:
            if untag(child) in ("Directory", "StandardDirectory"):
                parent[child.get("Id")] = (el.get("Id"), child.get("Name"))
    return parent


def under_root(parent, directory):
    names, seen = [], set()
    while directory in parent and directory != "APPLICATIONFOLDER":
        if directory in seen:
            return None
        seen.add(directory)
        directory, name = parent[directory]
        names.append(name)
    return "/".join(reversed(names)) if directory == "APPLICATIONFOLDER" else None


def installed_at(root, parent):
    where = {}
    for group in (el for el in root.iter() if untag(el) == "ComponentGroup"):
        for component in (c for c in group.iter() if untag(c) == "Component"):
            directory = component.get("Directory") or group.get("Directory")
            for f in (x for x in component.iter() if untag(x) == "File"):
                source = f.get("Source", "")[len("payload/"):]
                name = f.get("Name") or source.rsplit("/", 1)[-1]
                where[source] = (directory, under_root(parent, directory), name)
    return where


def built(msi, wix, root, gated):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "decompiled.wxs"
        r = subprocess.run([wix, "msi", "decompile", str(msi), "-o", str(out)],
                           capture_output=True, text=True)
        if r.returncode:
            return [f"{msi.name}: wix msi decompile failed: {r.stderr.strip() or r.stdout.strip()}"]
        inside = {el.get("Id") for el in ET.parse(out).getroot().iter() if untag(el) == "File"}
    want = {el.get("Id"): el.get("Source", "")[len("payload/"):]
            for el in root.iter() if untag(el) == "File"}
    bad = [f"{msi.name}: carries file {fid}, which abstraction.wxs does not install"
           for fid in sorted(inside - set(want))]
    for fid, path in want.items():
        if fid in inside:
            continue
        if path in gated:
            print(f"note  {msi.name} leaves out {path}, which this build was not given")
        else:
            bad.append(f"{msi.name}: {path} is in abstraction.wxs and not in the package")
    if not bad:
        print(f"ok    {msi.name} carries {len(inside)} of the {len(want)} files abstraction.wxs installs")
    return bad


def main():
    ap = argparse.ArgumentParser(description="Check installer/ against itself, and a built MSI against it.")
    ap.add_argument("msi", nargs="*", type=Path, help="a built package to check as well")
    ap.add_argument("--wix", default="wix", help="the wix executable, for reading an MSI")
    a = ap.parse_args()

    bad = []
    wxs = HERE / "abstraction.wxs"
    text = wxs.read_text(encoding="utf-8")
    root = ET.fromstring(text)
    groups, features = wxs_features(root)
    gated = gated_sources(text)

    sources = {r[0]: r for r in rows("sources.tsv")}
    unpinned = []
    for sid, repo, ref in sources.values():
        if ref == "-":
            if repo != "-":
                unpinned.append(f"{sid} {repo}")
            continue
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            bad.append(f"sources.tsv: {sid} pinned to {ref!r}, which is not a 40-hex commit")

    short = [r for r in rows("payload.tsv") if len(r) != WIDTH]
    for r in short:
        bad.append(f"payload.tsv: {r[1] if len(r) > 1 else r} has {len(r)} fields, want {WIDTH}")
    if short:
        for line in bad:
            print("FAIL ", line)
        return 1

    payload = {}
    for feature, path, kind, source, frm, sign, subsystem in rows("payload.tsv"):
        if kind == "gobuild" and subsystem not in SUBSYSTEMS:
            bad.append(f"payload.tsv: {path} subsystem={subsystem} — a gobuild row is "
                       f"{' or '.join(sorted(SUBSYSTEMS))}")
        if kind != "gobuild" and subsystem != "-":
            bad.append(f"payload.tsv: {path} subsystem={subsystem} — {kind} is not a link "
                       f"and has no subsystem")
        if feature not in FEATURES:
            bad.append(f"payload.tsv: {path} claims feature {feature!r}")
        if kind not in KINDS:
            bad.append(f"payload.tsv: {path} claims kind {kind!r}")
        if source not in sources:
            bad.append(f"payload.tsv: {path} names source {source!r}, absent from sources.tsv")
        if (sign == "yes") != path.endswith(".exe"):
            bad.append(f"payload.tsv: {path} sign={sign} — only a PE file can be an Authenticode target")
        if path in payload:
            bad.append(f"payload.tsv: {path} listed twice")
        if source == "UNRESOLVED" and path not in gated:
            bad.append(f"payload.tsv: {path} has no publishable source and is not gated in abstraction.wxs")
        payload[path] = (feature, sign)

    placed = {}
    for fid, refs in features.items():
        for ref in refs:
            if ref not in groups:
                bad.append(f"abstraction.wxs: feature {fid} references absent component group {ref}")
                continue
            for path in groups[ref]:
                if path in placed:
                    bad.append(f"abstraction.wxs: {path} installed by two features")
                placed[path] = fid

    for gid in groups:
        if not any(gid in refs for refs in features.values()):
            bad.append(f"abstraction.wxs: component group {gid} is referenced by no feature")

    expected = set(FEATURES.values()) | FILELESS
    if set(features) != expected:
        bad.append(f"abstraction.wxs: features are {sorted(features)}, want {sorted(expected)}")

    where, conditions = scoped(root)
    for cid, condition in conditions.items():
        if condition not in (None, MACHINE, USER):
            bad.append(f"abstraction.wxs: component {cid} is conditioned on {condition!r}. This "
                       f"package has two scopes, so a condition here is absent, {MACHINE!r} or "
                       f"{USER!r}, and every rule below reads them")

    member = {fid: [c for c, g in where.items() if g in refs]
              for fid, refs in features.items()}
    for fid, members in member.items():
        for name, machine in SCOPES.items():
            if not any(installs(conditions[c], machine) for c in members):
                bad.append(f"abstraction.wxs: feature {fid} installs nothing {name}. A feature a "
                           f"person reads and ticks installs something, or it is not offered")

    for machine, arm in ARMS.items():
        want = MACHINE if machine else USER
        if arm not in member.get("Service", []):
            bad.append(f"abstraction.wxs: the Service feature has no {arm}, so one scope installs "
                       f"the supervisor and nothing that ever starts it")
        elif conditions[arm] != want:
            bad.append(f"abstraction.wxs: {arm} is conditioned on {conditions[arm]!r}, want "
                       f"{want!r}. Each scope gets its own arm and never the other's, or an "
                       f"install quietly does less than it said")

    sequenced = {el.get("Action"): el.get("Condition", "")
                 for el in root.iter() if untag(el) == "Custom"}
    bad.extend(check_supervisor_removal(root))
    bad.extend(check_upgrade_shutdown(root))
    bad.extend(check_elevated_scope(root))
    for action in SUPERVISOR_ACTIONS:
        if action not in sequenced:
            bad.append(f"abstraction.wxs: {action} is sequenced nowhere")
        elif not sequenced[action].startswith(MACHINE + " "):
            bad.append(f"abstraction.wxs: {action} runs when {sequenced[action]!r}. It reaches the "
                       f"service manager, so it runs under {MACHINE} and nothing else: anywhere "
                       f"else it is a per-user install failing 1603")

    absent = re.search(r'<\?define Absent = "([^"]*)" \?>', text)
    if not absent:
        bad.append("abstraction.wxs: nothing defines Absent, so a build that dropped files "
                   "produces a package that does not say it is incomplete")
    else:
        named = {m for m in re.findall(r"\$\(var\.No(\w+)\)", absent.group(1))}
        for var in sorted(set(gated.values()) - named):
            bad.append(f"abstraction.wxs: payload files are gated on {var} and no sentence about "
                       f"{var} reaches ARPCOMMENTS. A build may carry less than its own text "
                       f"says; it may not do so silently")
        for var in sorted(named - set(gated.values())):
            bad.append(f"abstraction.wxs: ARPCOMMENTS carries No{var} and no payload file is "
                       f"gated on {var}")
        for var in sorted(named & set(gated.values())):
            if not re.search(rf'<\?define No{var} = "[^"]+" \?>', text):
                bad.append(f"abstraction.wxs: No{var} is never given a sentence, so a build "
                           f"without {var} leaves it out and says nothing")

    for path, (feature, _) in payload.items():
        if path not in placed:
            bad.append(f"{path} is in payload.tsv and in no component")
        elif placed[path] != FEATURES[feature]:
            bad.append(f"{path} is feature {feature} in payload.tsv and {placed[path]} in abstraction.wxs")
    for path in placed:
        if path not in payload:
            bad.append(f"{path} is installed by abstraction.wxs and is in no payload.tsv row")

    parent = folders(root)
    where = installed_at(root, parent)
    for path, (directory, folder, name) in where.items():
        if folder is None:
            bad.append(f"abstraction.wxs: {path} is installed into {directory}, which is not "
                       f"under APPLICATIONFOLDER")
            continue
        lands = f"{folder}/{name}" if folder else name
        if lands != path:
            bad.append(f"abstraction.wxs: {path} lands at {lands}, and payload.tsv's path "
                       f"column is where it lands")

    on_path = set()
    for env in (el for el in root.iter() if untag(el) == "Environment"):
        if env.get("Name") != "PATH":
            continue
        m = re.fullmatch(r"\[(\w+)\]", env.get("Value", ""))
        if not m:
            bad.append(f"abstraction.wxs: PATH entry {env.get('Id')} is {env.get('Value')!r}, "
                       f"and a PATH entry is one resolved Directory so that moving the "
                       f"executables moves it")
            continue
        folder = under_root(parent, m.group(1))
        if folder is None:
            bad.append(f"abstraction.wxs: PATH entry {env.get('Id')} names {m.group(1)}, "
                       f"which is not a directory under APPLICATIONFOLDER")
        else:
            on_path.add(folder)
    for path, (_, folder, _) in where.items():
        if path.endswith(".exe") and folder not in on_path:
            bad.append(f"{path} is an executable in {folder or 'the install root'!s} and no "
                       f"PATH entry names that folder: a program a person types is on PATH")
    for folder in on_path:
        if not any(f == folder for _, f, _ in where.values()):
            bad.append(f"abstraction.wxs: PATH carries {folder or 'the install root'!s}, "
                       f"which no installed file lands in")

    targets = sorted(p for p, (_, sign) in payload.items() if sign == "yes")
    conf = ET.fromstring((HERE / "signpath.artifact-configuration.xml").read_text(encoding="utf-8"))
    for msi in (el for el in conf.iter() if untag(el) == "msi-file"):
        named = sorted(pe.get("path") for pe in msi.iter() if untag(pe) == "pe-file")
        if named != targets:
            bad.append(
                f"signpath.artifact-configuration.xml: {msi.get('path')} signs {named}, "
                f"payload.tsv says {targets}"
            )
        if not any(untag(child) == "authenticode-sign" for child in msi):
            bad.append(f"signpath.artifact-configuration.xml: {msi.get('path')} is not itself signed")

    for line in bad:
        print("FAIL ", line)
    if bad:
        return 1
    print(f"ok    abstraction.wxs parses, {len(payload)} files across {len(features)} features")
    print(f"ok    every file has a source in sources.tsv and one feature that installs it")
    print(f"ok    every feature installs something in both scopes, each scope starts the "
          f"supervisor its own way, and whatever a build can drop, ARPCOMMENTS names")
    for s in unpinned:
        print(f"note  {s} carries no commit yet: a --src build pins nothing and a --bin "
              f"build has nothing to take")
    print("signing targets, inside each MSI:")
    for t in targets:
        print(f"      {t}{'   (gated: absent unless the build is given its source)' if t in gated else ''}")
    print("      abstraction-x64.msi")
    print("      abstraction-arm64.msi")

    for path in a.msi:
        bad += built(path, a.wix, root, gated)
    for line in bad:
        print("FAIL ", line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
