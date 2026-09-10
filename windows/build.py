import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from validate import rows

HERE = Path(__file__).resolve().parent
GOARCH = {"x64": "amd64", "arm64": "arm64"}
GATE = {"Abstraction Panel.exe": "Panel",
        "Abstraction Panel.exe.manifest": "Panel",
        "dev/include/abstraction/download/over_curl.hpp": "Cpp"}


def stage(src, out, arch):
    dropped = []
    for _, path, kind, source, frm, _ in rows("payload.tsv"):
        if source not in src:
            dropped.append(path)
            continue
        dst = out / "payload" / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        if kind == "gobuild":
            subprocess.run(
                ["go", "build", "-ldflags", "-s -w -buildid=", "-o", str(dst), "."],
                cwd=src[source] / frm, check=True,
                env={**os.environ, "CGO_ENABLED": "0", "GOOS": "windows",
                     "GOARCH": GOARCH[arch], "GOFLAGS": "-trimpath"})
        else:
            shutil.copyfile(src[source] / frm, dst)
    return dropped


def main():
    ap = argparse.ArgumentParser(description="Build one unsigned MSI from payload.tsv.")
    ap.add_argument("--arch", choices=GOARCH, default="x64")
    ap.add_argument("--version", default="0.0.0")
    ap.add_argument("--wix", default="wix")
    ap.add_argument("--ext", default="WixToolset.UI.wixext")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--license", type=Path, default=HERE.parent / "LICENSE")
    ap.add_argument("--src", action="append", default=[], metavar="ID=DIR",
                    help="where the sources.tsv source ID is checked out; "
                         "a source not given here is left out of the package")
    a = ap.parse_args()

    src = {"installer": HERE}
    for pair in a.src:
        sid, _, d = pair.partition("=")
        src[sid] = Path(d).resolve()

    a.out.mkdir(parents=True, exist_ok=True)
    dropped = stage(src, a.out, a.arch)
    for path in dropped:
        if path not in GATE:
            print(f"FAIL  {path} has no --src for its source and no gate to leave it out")
            return 1

    subprocess.run([sys.executable, str(HERE / "mklicense.py"),
                    str(a.license), str(a.out / "license.rtf")], check=True)
    if subprocess.run([sys.executable, str(HERE / "validate.py")]).returncode:
        return 1

    msi = a.out / f"abstraction-{a.arch}.msi"
    off = {GATE[p] for p in dropped}
    defs = {"Version": a.version}
    for v in dict.fromkeys(GATE.values()):
        defs[v] = "no" if v in off else "yes"
    cmd = [a.wix, "build", "-arch", a.arch, "-bindpath", str(a.out),
           *[x for k, v in defs.items() for x in ("-d", f"{k}={v}")],
           "-ext", a.ext, "-o", str(msi), str(HERE / "abstraction.wxs")]
    print(" ".join(cmd))
    if subprocess.run(cmd, cwd=a.out).returncode:
        return 1

    for path in dropped:
        print(f"note  {path} left out, so {GATE[path]}=no")
    print(f"ok    {msi.name} {msi.stat().st_size} bytes, UNSIGNED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
