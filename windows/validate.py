import argparse
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEATURES = {"service": "Service", "tools": "Tools", "developer": "Developer"}
KINDS = {"gobuild", "copy", "authored"}


def rows(name):
    out = []
    for line in (HERE / name).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith(">"):
            continue
        out.append([f.strip() for f in line.split("\t") if f.strip()])
    return out[1:]


def untag(el):
    return el.tag.split("}")[-1]


def gated_sources(text):
    depth, gated = 0, set()
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("<?if"):
            depth += 1
        elif s.startswith("<?endif"):
            depth -= 1
        m = re.search(r'Source="payload/([^"]+)"', line)
        if m and depth > 0:
            gated.add(m.group(1))
    return gated


def wxs_features(root):
    groups, features, seen = {}, {}, []
    for el in root.iter():
        tag = untag(el)
        if tag == "ComponentGroup":
            groups[el.get("Id")] = [
                f.get("Source", "")[len("payload/"):]
                for f in el.iter()
                if untag(f) == "File"
            ]
            seen.append(el.get("Id"))
        elif tag == "Feature":
            features[el.get("Id")] = [
                r.get("Id") for r in el.iter() if untag(r) == "ComponentGroupRef"
            ]
    return groups, features


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
    for sid, _, ref in sources.values():
        if ref != "-" and not re.fullmatch(r"[0-9a-f]{40}", ref):
            bad.append(f"sources.tsv: {sid} pinned to {ref!r}, which is not a 40-hex commit")

    payload = {}
    for feature, path, kind, source, frm, sign in rows("payload.tsv"):
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

    if set(features) != set(FEATURES.values()):
        bad.append(f"abstraction.wxs: features are {sorted(features)}, want {sorted(FEATURES.values())}")

    for path, (feature, _) in payload.items():
        if path not in placed:
            bad.append(f"{path} is in payload.tsv and in no component")
        elif placed[path] != FEATURES[feature]:
            bad.append(f"{path} is feature {feature} in payload.tsv and {placed[path]} in abstraction.wxs")
    for path in placed:
        if path not in payload:
            bad.append(f"{path} is installed by abstraction.wxs and is in no payload.tsv row")

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
    print("signing targets, inside each MSI:")
    for t in targets:
        print(f"      {t}{'   (no publishable source yet)' if t in gated else ''}")
    print("      abstraction-x64.msi")
    print("      abstraction-arm64.msi")

    for path in a.msi:
        bad += built(path, a.wix, root, gated)
    for line in bad:
        print("FAIL ", line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
