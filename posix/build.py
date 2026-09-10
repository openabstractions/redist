import argparse
import gzip
import io
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCHES = {"amd64", "arm64"}
KINDS = {"gobuild", "copy", "authored", "generated", "license"}


def rows(name):
    out = []
    for line in (HERE / name).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith(">"):
            continue
        out.append([f.strip() for f in line.split("\t") if f.strip()])
    return out[1:]


def sources():
    return {r[0]: (r[1], r[2], r[3]) for r in rows("sources.tsv")}


# This file is two directories below the root in the tree it is written in and
# one below it in the repository it publishes into, so the depth is discovered
# rather than counted.
def nearest_license():
    for d in HERE.parents:
        if (d / "LICENSE").is_file():
            return d / "LICENSE"
    return HERE / "LICENSE"


def payload(platform):
    out = []
    for plat, path, kind, source, frm, mode in rows("payload.tsv"):
        if plat not in ("both", platform):
            continue
        if kind not in KINDS:
            sys.exit(f"FAIL  {path} has kind {kind}, which is not one of {sorted(KINDS)}")
        out.append((path, kind, source, frm, int(mode, 8)))
    return out


def pinned(src, want):
    for sid, d in src.items():
        if sid not in want or not (d / ".git").exists():
            continue
        got = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        repo, tag, commit = want[sid]
        if got != commit:
            sys.exit(f"FAIL  {sid} is checked out at {got}, sources.tsv pins {commit}")
        print(f"ok    {sid} {repo} {tag} {commit}")


def gobuild(pkgdir, dst, goos, goarch):
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["go", "build", "-ldflags", "-s -w -buildid=", "-o", str(dst), "."],
                   cwd=pkgdir, check=True,
                   env={**os.environ, "CGO_ENABLED": "0", "GOOS": goos,
                        "GOARCH": goarch, "GOFLAGS": "-trimpath"})


def stage(items, src, root, goos, goarch, programs=True, prebuilt=None, license=None):
    files = []
    for path, kind, source, frm, mode in items:
        dst = root / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        if kind == "gobuild":
            if not programs:
                pass
            elif prebuilt is not None:
                shutil.copyfile(prebuilt / Path(path).name, dst)
            else:
                gobuild(src[source] / frm, dst, goos, goarch)
        elif kind == "generated":
            dst.write_bytes(b"")
        elif kind == "license":
            dst.write_bytes(license.read_bytes().replace(b"\r\n", b"\n"))
        else:
            # Every non-program file here is text, and a build on Windows would
            # otherwise put CRLF into a shell script that a shell then refuses.
            base = HERE if source == "posix" else src[source]
            dst.write_bytes((base / frm).read_bytes().replace(b"\r\n", b"\n"))
        files.append((path, mode))
    return files


def needs(*tools):
    absent = [t for t in tools if shutil.which(t) is None]
    if absent:
        sys.exit(f"FAIL  {', '.join(absent)} not on PATH. A macOS package is built on macOS; "
                 f"this platform is {sys.platform}. UNPROVEN, not skipped.")


def lipo(thin, root, items):
    for path, kind, _, _, _ in items:
        if kind != "gobuild":
            continue
        dst = root / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["lipo", "-create", "-output", str(dst),
                        *[str(t / path) for t in thin]], check=True)


def tarball(root, files, out, top):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        seen = set()
        for path, mode in sorted(files):
            parts = Path(path).parts
            for i in range(1, len(parts)):
                d = "/".join(parts[:i])
                if d in seen:
                    continue
                seen.add(d)
                info = tarfile.TarInfo(f"{top}/payload/{d}")
                info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, 0
                tar.addfile(info)
            data = (root / path).read_bytes()
            info = tarfile.TarInfo(f"{top}/payload/{path}")
            info.size, info.mode, info.mtime = len(data), mode, 0
            tar.addfile(info, io.BytesIO(data))
        script = (HERE / "linux" / "install.sh").read_bytes().replace(b"\r\n", b"\n")
        info = tarfile.TarInfo(f"{top}/install.sh")
        info.size, info.mode, info.mtime = len(script), 0o755, 0
        tar.addfile(info, io.BytesIO(script))
    with open(out, "wb") as f:
        with gzip.GzipFile(fileobj=f, mode="wb", mtime=0) as gz:
            gz.write(buf.getvalue())
    return out


def pkg(root, files, out, version, work):
    scripts = work / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HERE / "macos" / "postinstall", scripts / "postinstall")
    (scripts / "postinstall").chmod(0o755)

    manifest = root / ".local/share/abstraction/FILES"
    manifest.write_text("".join(f"{p}\n" for p, _ in sorted(files)), encoding="utf-8", newline="\n")

    for path, mode in files:
        (root / path).chmod(mode)

    component = work / "component.pkg"
    subprocess.run(["pkgbuild", "--root", str(root), "--scripts", str(scripts),
                    "--identifier", "com.openabstractions.abstraction",
                    "--version", version, "--install-location", "/",
                    "--ownership", "recommended", str(component)], check=True)

    res = work / "resources"
    res.mkdir(parents=True, exist_ok=True)
    for name in ("welcome.txt", "conclusion.txt"):
        shutil.copyfile(HERE / "macos" / name, res / name)
    shutil.copyfile(root / ".local/share/abstraction/LICENSE", res / "LICENSE")

    dist = work / "distribution.xml"
    dist.write_text((HERE / "macos" / "distribution.xml").read_text(encoding="utf-8")
                    .replace("@VERSION@", version), encoding="utf-8", newline="\n")

    subprocess.run(["productbuild", "--distribution", str(dist),
                    "--package-path", str(work), "--resources", str(res), str(out)],
                   check=True)
    return out


def main():
    ap = argparse.ArgumentParser(description="Build one unsigned Linux tarball or macOS pkg.")
    ap.add_argument("--platform", choices=("linux", "macos"), required=True)
    ap.add_argument("--arch", choices=sorted(ARCHES),
                    help="linux only; macOS builds one universal package")
    ap.add_argument("--version", default="0.0.0")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--src", action="append", default=[], metavar="ID=DIR",
                    help="where the sources.tsv source ID is checked out; "
                         "a source not given here has its rows left out, and "
                         "each one is named")
    ap.add_argument("--bin", type=Path, metavar="DIR",
                    help="take the programs from DIR instead of building them, "
                         "for a package assembled out of published module "
                         "versions rather than out of checkouts; on macOS they "
                         "must already be universal, because lipo is what joins "
                         "two thin builds and this route does not run it")
    ap.add_argument("--license", type=Path, default=nearest_license(),
                    help="the LICENSE the package installs")
    a = ap.parse_args()

    want = sources()
    src = {}
    for pair in a.src:
        sid, _, d = pair.partition("=")
        if sid not in want:
            sys.exit(f"FAIL  --src {sid} is not a source in sources.tsv")
        src[sid] = Path(d).resolve()

    if not a.license.is_file():
        sys.exit(f"FAIL  --license {a.license} is not a file, and the package installs one")

    items = payload(a.platform)
    have = lambda kind, source: (source == "posix" or kind == "license"
                                 or (kind == "gobuild" and a.bin is not None)
                                 or source in src)
    unbuildable = [p for p, k, s, _, _ in items if k == "gobuild" and not have(k, s)]
    if unbuildable:
        sys.exit(f"FAIL  no --src and no --bin for {', '.join(unbuildable)}; "
                 f"a package that installs no program is not this package")
    for path, kind, source, _, _ in items:
        if not have(kind, source):
            print(f"note  {path} left out: no --src {source}")
    items = [it for it in items if have(it[1], it[2])]
    pinned(src, want)

    a.out.mkdir(parents=True, exist_ok=True)
    work = a.out / a.platform
    if work.exists():
        shutil.rmtree(work)
    root = work / "root"

    if a.platform == "linux":
        if a.arch not in ARCHES:
            sys.exit("FAIL  --arch amd64 or arm64 is required for linux")
        files = stage(items, src, root, "linux", a.arch, prebuilt=a.bin, license=a.license)
        top = f"abstraction-{a.version}-linux-{a.arch}"
        out = tarball(root, files, a.out / f"{top}.tar.gz", top)
    else:
        needs("pkgbuild", "productbuild")
        if a.bin:
            files = stage(items, src, root, "darwin", "arm64",
                          prebuilt=a.bin, license=a.license)
        else:
            needs("lipo")
            thin = []
            for arch in sorted(ARCHES):
                d = work / f"thin-{arch}"
                stage(items, src, d, "darwin", arch, license=a.license)
                thin.append(d)
            files = stage(items, src, root, "darwin", "arm64",
                          programs=False, license=a.license)
            lipo(thin, root, items)
        out = pkg(root, files, a.out / f"abstraction-{a.version}-macos-universal.pkg",
                  a.version, work)

    print(f"ok    {out.name} {out.stat().st_size} bytes, UNSIGNED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
