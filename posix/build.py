import argparse
import gzip
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCHES = {"amd64", "arm64"}
KINDS = {"gobuild", "swiftbuild", "copy", "authored", "generated", "license"}
# Apple's own name for each GOARCH value payload.tsv's macOS rows build for.
SWIFT_ARCH = {"amd64": "x86_64", "arm64": "arm64"}
# The selectable parts of the package, the same vocabulary as the Windows
# package's WiX feature ids, lower case (installer/feature_invariants.py):
# service is what the package is for and is always installed; the rest are
# the optional providers of VISION 2026-09-22, each one on or off on its
# own. The value is the Linux default: a provider that only reads is
# installed unless the person says otherwise.
FEATURES = {"service": True, "localstores": True, "modelhost": False, "mcpgateway": False}
OPTIONAL = [f for f in FEATURES if f != "service"]
BASE = "service"
# One component package per feature on macOS, because a distribution choice
# selects a package and cannot select part of one. The base identifier is the
# receipt every earlier version wrote and keeps.
IDENTIFIER = {"service": "com.openabstractions.abstraction",
              "localstores": "com.openabstractions.abstraction.localstores",
              "modelhost": "com.openabstractions.abstraction.modelhost",
              "mcpgateway": "com.openabstractions.abstraction.mcpgateway"}
TITLE = {"localstores": "Local model stores",
         "modelhost": "Model host",
         "mcpgateway": "MCP gateway"}
CHOICE_TEXT = {
    "localstores": "Reads every model store on this machine and reports what each one holds to "
                    "applications that ask the runtime. It writes in no store, which is why it is "
                    "ticked to begin with.",
    "modelhost": "modelhostd, the provider that loads one model file this machine already holds "
                  "with a llama-server this machine already has, and serves it through the "
                  "runtime under a lease. Installing it starts nothing until openabstractions "
                  "models host names the model and the engine path.",
    "mcpgateway": "openabstractions-mcp, a local stdio MCP server an assistant starts by its "
                   "absolute path. It holds nothing by being installed.",
}
FEATURES_FILE = ".local/share/abstraction/FEATURES"


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
    for plat, feature, path, kind, source, frm, mode in rows("payload.tsv"):
        if plat not in ("both", platform):
            continue
        if kind not in KINDS:
            sys.exit(f"FAIL  {path} has kind {kind}, which is not one of {sorted(KINDS)}")
        if feature not in FEATURES:
            sys.exit(f"FAIL  {path} claims feature {feature}, which is not one of {sorted(FEATURES)}")
        out.append((path, kind, source, frm, int(mode, 8)))
    return out


def feature_of(platform):
    """Which selectable part of the package installs each file."""
    return {path: feature
            for plat, feature, path, *_ in rows("payload.tsv")
            if plat in ("both", platform)}


def pinned(src, want):
    for sid, d in src.items():
        if sid not in want or not (d / ".git").exists():
            continue
        repo, tag, commit = want[sid]
        got = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        if commit == "-":
            print(f"note  {sid} {repo} has never been published; this build takes {got} "
                  f"from the directory it was handed and checks it against nothing")
            continue
        if got != commit:
            sys.exit(f"FAIL  {sid} is checked out at {got}, sources.tsv pins {commit}")
        print(f"ok    {sid} {repo} {tag} {commit}")


def gobuild(pkgdir, dst, goos, goarch):
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["go", "build", "-ldflags", "-s -w -buildid=", "-o", str(dst), "."],
                   cwd=pkgdir, check=True,
                   env={**os.environ, "CGO_ENABLED": "0", "GOOS": goos,
                        "GOARCH": goarch, "GOFLAGS": "-trimpath"})


def swiftbuild(srcfile, dst, goarch):
    dst.parent.mkdir(parents=True, exist_ok=True)
    arch = SWIFT_ARCH[goarch]
    subprocess.run(["swiftc", "-O", "-target", f"{arch}-apple-macos12.0",
                    str(srcfile), "-o", str(dst)], check=True)


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
        elif kind == "swiftbuild":
            if not programs:
                pass
            elif prebuilt is not None:
                shutil.copyfile(prebuilt / Path(path).name, dst)
            else:
                swiftbuild(src[source] / frm, dst, goarch)
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
        if kind not in ("gobuild", "swiftbuild"):
            continue
        dst = root / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["lipo", "-create", "-output", str(dst),
                        *[str(t / path) for t in thin]], check=True)


def write_features(root, files, owner):
    """The Linux tarball's record of which feature puts each file there.

    install.sh reads it to install the features the person chose. It is a
    payload file like any other, so it is in the ledger and removed with the
    rest; a file it does not name belongs to the runtime, which install.sh
    always installs.
    """
    lines = ["default %s %s\n" % (f, "on" if FEATURES[f] else "off") for f in FEATURES]
    lines += ["file %s %s\n" % (owner[path], path) for path, _ in sorted(files)]
    with io.open(root / FEATURES_FILE, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(lines))


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


def split_root(root, paths, out):
    """A payload tree holding exactly paths, with their modes, for one package."""
    for path in paths:
        dst = out / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / path, dst)
    return out


def choices(version, carried):
    """The choices-outline and pkg-refs for the features this package carries.

    Each optional feature is its own component package, because a distribution
    choice selects a package and cannot select part of one. The optional ones
    are installed before the base package, whose postinstall writes the one
    removal ledger out of the files that are actually there.
    """
    outline, elements, refs = [], [], []
    for feature in carried:
        identifier = IDENTIFIER[feature]
        ref = '\t<pkg-ref id="%s" version="%s" onConclusion="none">%s</pkg-ref>' % (
            identifier, version, component_name(feature))
        if feature == BASE:
            outline.append('\t\t\t<line choice="%s"/>' % identifier)
            elements.append('\t<choice id="%s" visible="false">\n\t\t<pkg-ref id="%s"/>\n\t</choice>'
                            % (identifier, identifier))
        else:
            outline.insert(0, '\t\t\t<line choice="%s"/>' % identifier)
            elements.append(
                '\t<choice id="%s" title="%s" description="%s" start_selected="%s">\n'
                '\t\t<pkg-ref id="%s"/>\n\t</choice>'
                % (identifier, TITLE[feature], CHOICE_TEXT[feature],
                   "true" if FEATURES[feature] else "false", identifier))
        refs.append(ref)
    return "\n".join(outline), "\n".join(elements + refs)


def component_name(feature):
    return "component.pkg" if feature == BASE else "component-%s.pkg" % feature


PANEL_APP = Path(".local/bin/Abstraction Panel.app")


def sign_panel_app(root, identity, keychain=None):
    """Sign the assembled nested programs, then seal the outer app bundle."""
    if not identity or identity == "-":
        raise ValueError("whole-app signing requires a Developer ID Application identity")
    app = root / PANEL_APP
    nested = [app / "Contents/MacOS/panel", app / "Contents/MacOS/Abstraction Panel"]
    if not (app / "Contents/Info.plist").is_file() or any(not path.is_file() for path in nested):
        raise ValueError("the complete Panel.app must be assembled before signing")
    options = ["--keychain", str(keychain)] if keychain else []
    for target in [*nested, app]:
        subprocess.run(["codesign", "--force", "--timestamp", "--options", "runtime",
                        *options, "--sign", identity, str(target)], check=True)
        subprocess.run(["codesign", "--verify", "--strict", "--verbose=2", str(target)], check=True)
        details = subprocess.run(["codesign", "-dv", "--verbose=4", str(target)],
                                 capture_output=True, text=True, check=True).stderr
        if ("Timestamp=" not in details or not re.search(r"CodeDirectory .*\(.*runtime", details) or
                "Authority=Developer ID Application:" not in details):
            raise RuntimeError(str(target) + " lacks Developer ID, a secure timestamp, or hardened runtime")
    subprocess.run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)], check=True)
    signature = app / "Contents/_CodeSignature/CodeResources"
    if not signature.is_file():
        raise RuntimeError("Panel.app signing produced no CodeResources seal")
    return signature.relative_to(root).as_posix()


def pkg(root, files, out, version, work, owner):
    scripts = work / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    for name in ("preinstall", "postinstall", "lifecycle.sh"):
        # Both package hooks need LF regardless of the source checkout platform.
        raw = (HERE / "macos" / name).read_bytes().replace(b"\r\n", b"\n")
        (scripts / name).write_bytes(raw)
        (scripts / name).chmod(0o755)

    manifest = root / ".local/share/abstraction/FILES"
    # io.open and not Path.write_text: newline= landed on write_text in 3.10, and
    # macOS ships /usr/bin/python3 at 3.9, where this raised TypeError after every
    # expensive step. LF is forced because the bom and the payload are compared.
    # Every file the package can install is named here, including the optional
    # features' — postinstall records the ones that are actually on disk, which
    # is what a person's choice decided.
    with io.open(manifest, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(f"{p}\n" for p, _ in sorted(files)))

    for path, mode in files:
        (root / path).chmod(mode)

    carried = [f for f in FEATURES if any(owner[p] == f for p, _ in files)]
    for feature in carried:
        paths = [p for p, _ in sorted(files) if owner[p] == feature]
        # Every package is built from a tree holding its own files alone, so a
        # feature the person did not choose leaves no file behind.
        tree = split_root(root, paths, work / ("root-%s" % feature))
        command = ["pkgbuild", "--root", str(tree)]
        if feature == BASE:
            command += ["--scripts", str(scripts)]
        subprocess.run(command + ["--identifier", IDENTIFIER[feature],
                                  "--version", version, "--install-location", "/",
                                  "--ownership", "recommended",
                                  str(work / component_name(feature))], check=True)

    res = work / "resources"
    res.mkdir(parents=True, exist_ok=True)
    for name in ("welcome.txt", "conclusion.txt"):
        shutil.copyfile(HERE / "macos" / name, res / name)
    shutil.copyfile(root / ".local/share/abstraction/LICENSE", res / "LICENSE")

    outline, elements = choices(version, carried)
    dist = work / "distribution.xml"
    with io.open(dist, "w", encoding="utf-8", newline="\n") as fh:
        fh.write((HERE / "macos" / "distribution.xml").read_text(encoding="utf-8")
                 .replace("@VERSION@", version)
                 .replace("\t\t\t@OUTLINE@", outline)
                 .replace("\t@CHOICES@", elements))

    subprocess.run(["productbuild", "--distribution", str(dist),
                    "--package-path", str(work), "--resources", str(res), str(out)],
                   check=True)
    return out


def main():
    ap = argparse.ArgumentParser(description="Build a Linux tarball or macOS pkg; whole-app signing is opt-in.")
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
    ap.add_argument("--sign-app-identity", help="macOS Developer ID Application identity for the complete Panel.app")
    ap.add_argument("--signing-keychain", type=Path, help="keychain containing --sign-app-identity")
    a = ap.parse_args()

    if a.sign_app_identity and a.platform != "macos":
        sys.exit("FAIL  --sign-app-identity is only valid for the macOS package")
    if a.signing_keychain and not a.sign_app_identity:
        sys.exit("FAIL  --signing-keychain requires --sign-app-identity")

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
    owner = feature_of(a.platform)

    def have(kind, path, source):
        if source == "posix" or kind == "license":
            return True
        if kind in ("gobuild", "swiftbuild") and a.bin is not None:
            return (a.bin / Path(path).name).is_file()
        return source in src

    # A runtime program this build cannot obtain stops it: a package that
    # installs no runtime is not this package. An optional provider's program
    # it cannot obtain takes that feature out of the package instead, and the
    # note says which, the way the Windows build gates a feature away. The
    # Panel's Swift launcher is BASE too: it is bundled whenever it builds,
    # the way the Windows package's Tools feature bundles it, not a choice.
    unbuildable = [p for p, k, s, _, _ in items
                   if k in ("gobuild", "swiftbuild") and owner[p] == BASE and not have(k, p, s)]
    if unbuildable:
        sys.exit(f"FAIL  no --src and no --bin for {', '.join(unbuildable)}; "
                 f"a package that installs no program is not this package")
    off = {owner[p]: s for p, k, s, _, _ in items
           if k in ("gobuild", "swiftbuild") and not have(k, p, s)}
    for feature, source in sorted(off.items()):
        print(f"note  the {feature} feature is not in this package: no --src {source} and no "
              f"{source} program in --bin, so there is nothing to offer")
    for path, kind, source, _, _ in items:
        if owner[path] not in off and not have(kind, path, source):
            print(f"note  {path} left out: no --src {source}")
    items = [it for it in items
             if owner[it[0]] not in off and have(it[1], it[0], it[2])]
    carried = [f for f in FEATURES if any(owner[p] == f for p, *_ in items)]
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
        write_features(root, files, owner)
        top = f"abstraction-{a.version}-linux-{a.arch}"
        out = tarball(root, files, a.out / f"{top}.tar.gz", top)
    else:
        needs("pkgbuild", "productbuild", "swiftc")
        if a.sign_app_identity:
            needs("codesign")
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
        if a.sign_app_identity:
            for path, mode in files:
                (root / path).chmod(mode)
            signature = sign_panel_app(root, a.sign_app_identity, a.signing_keychain)
            files.append((signature, 0o644))
            owner[signature] = BASE
        out = pkg(root, files, a.out / f"abstraction-{a.version}-macos-universal.pkg",
                  a.version, work, owner)

    state = "Panel.app SIGNED; package UNSIGNED" if a.sign_app_identity else "UNSIGNED"
    print(f"ok    {out.name} {out.stat().st_size} bytes, {state}")
    listed = ", ".join("%s (%s)" % (f, "on" if FEATURES[f] else "off") for f in carried)
    print(f"ok    features in it: {listed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
