import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from validate import rows
from modelhost_engine import (BUNDLE_NAME as MODELHOST_ENGINE_NAME,
                              RECEIPT_NAME as MODELHOST_RECEIPT_NAME,
                              pin as modelhost_pin, verify_bundle)
from pytorch_engine import (BUNDLE_NAME as PYTORCH_INPUT_NAME,
                            MANIFEST_NAME as PYTORCH_MANIFEST_NAME,
                            load_manifest as pytorch_manifest, verify_bundle as verify_pytorch_bundle)

HERE = Path(__file__).resolve().parent
GOARCH = {"x64": "amd64", "arm64": "arm64"}
GATE = {"tools/Abstraction Panel.exe": "Panel",
        "dev/include/abstraction/download/over_curl.hpp": "Cpp",
        "tools/inventoryd.exe": "LocalStores",
        "tools/modelhostd.exe": "ModelHost",
        "tools/engines/llama-b10825-oa-win-vulkan-x64.zip": "ModelHostEngine",
        "tools/engines/llama-b10825-oa-win-vulkan-x64.receipt.json": "ModelHostEngine",
        "tools/engines/llama.cpp-MIT.txt": "ModelHostEngine",
        "tools/engines/BoringSSL-LICENSE.txt": "ModelHostEngine",
        "tools/lemonaded.exe": "LemonadeImage",
        "tools/thenoise-provider.exe": "TheNoiseImage",
        "tools/pytorchd.exe": "PyTorchImage",
        "engines/pytorch/" + PYTORCH_INPUT_NAME: "PyTorchImage",
        "engines/pytorch/" + PYTORCH_MANIFEST_NAME: "PyTorchImage",
        "tools/declarations/lemonade-image.json": "LemonadeImage",
        "tools/openabstractions-mcp.exe": "McpGateway",
        "tools/abstraction_ipc.dll": "IpcLibrary",
        "tools/openabstractions-system.exe": "SystemHelper"}
MODELHOST_ENGINE_PAYLOAD = frozenset({"tools/engines/" + MODELHOST_ENGINE_NAME,
                                      "tools/engines/" + MODELHOST_RECEIPT_NAME,
                                      "tools/engines/llama.cpp-MIT.txt",
                                      "tools/engines/BoringSSL-LICENSE.txt"})
BORINGSSL_NOTICE_SHA256 = "827c8d8fc207c2392794eef9e00fe246f9f61fdcc132556c275be3dd8c3cd97f"
PYTORCH_PAYLOAD = frozenset({"tools/pytorchd.exe", "engines/pytorch/" + PYTORCH_INPUT_NAME,
                             "engines/pytorch/" + PYTORCH_MANIFEST_NAME})


def prebuilt(binaries, kind, path):
    if binaries is None or kind != "gobuild":
        return None
    p = binaries / Path(path).name
    return p if p.is_file() else None


def ldflags(subsystem):
    return "-s -w -buildid=" + (" -H=windowsgui" if subsystem == "windows" else "")


def windows_go_environment(base):
    # Private checkout and projected redist carry the same source-owned helper.
    paths = (HERE.parent / "scripts/windows_go_sdk.py", HERE.parent / "tools/windows_go_sdk.py")
    helper = next((path for path in paths if path.is_file()), None)
    if helper is None:
        raise ValueError("Windows build needs the carried verified Go SDK helper")
    spec = importlib.util.spec_from_file_location("oa_installer_windows_go_sdk", helper)
    sdk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sdk)
    linked = base.get("OA_WINDOWS_GO_SDK_RECEIPT")
    receipt = (sdk.validate_sdk_receipt(json.loads(Path(linked).read_bytes())) if linked
               else sdk.prepare_sdk(HERE.parent / ".forks/windows-go-sdk"))
    return sdk.sdk_environment(receipt, base), sdk, receipt


def stage(src, out, arch, binaries=None):
    go_env = None
    sdk = receipt = None
    pytorch_program = prebuilt(binaries, "gobuild", "tools/pytorchd.exe") is not None or "pytorchimage" in src
    pytorch_root = src.get("pytorchengine")
    pytorch_bundle = pytorch_root / PYTORCH_INPUT_NAME if pytorch_root else None
    pytorch_inputs = pytorch_root / PYTORCH_MANIFEST_NAME if pytorch_root else None
    has_pytorch_inputs = (pytorch_bundle is not None and pytorch_bundle.is_file()
                          and pytorch_inputs.is_file())
    if arch == "x64":
        if pytorch_program != has_pytorch_inputs:
            raise ValueError("x64 PyTorch requires pytorchd, the prepared input ZIP and its owner manifest together")
        if has_pytorch_inputs:
            identity = verify_pytorch_bundle(pytorch_bundle, pytorch_manifest(pytorch_inputs))
            print(f"ok    PyTorch input bundle {identity['name']} {identity['size_bytes']} bytes sha256:{identity['sha256']}")
    host_program = prebuilt(binaries, "gobuild", "tools/modelhostd.exe") is not None or "modelhost" in src
    engine_root = src.get("modelhostengine")
    engine_bundle = engine_root / MODELHOST_ENGINE_NAME if engine_root else None
    engine_receipt = engine_root / MODELHOST_RECEIPT_NAME if engine_root else None
    engine_pin = engine_root / "pin.json" if engine_root else None
    has_engine = (engine_bundle is not None and engine_bundle.is_file()
                  and engine_receipt.is_file() and engine_pin.is_file())
    if arch == "x64":
        if host_program != has_engine:
            raise ValueError("x64 ModelHost requires modelhostd and the exact reviewed reduced b10825 bundle together")
        if has_engine:
            verify_bundle(engine_bundle, engine_receipt, modelhost_pin(engine_pin))
            notice = HERE / "engines/BoringSSL-LICENSE.txt"
            notice_bytes = notice.read_bytes()
            notice_hash = hashlib.sha256(notice_bytes).hexdigest()
            if notice_hash != BORINGSSL_NOTICE_SHA256:
                raise ValueError("source checkout ModelHost BoringSSL notice differs from reviewed text: "
                                 f"sha256={notice_hash} bytes={len(notice_bytes)} "
                                 f"crlf={notice_bytes.count(bytes([13, 10]))} lf={notice_bytes.count(bytes([10]))}")
    dropped = []
    for feature, path, kind, source, frm, _, subsystem in rows("payload.tsv"):
        if path in PYTORCH_PAYLOAD and (arch != "x64" or not pytorch_program):
            dropped.append(path)
            continue
        if path in MODELHOST_ENGINE_PAYLOAD and (arch != "x64" or not host_program):
            dropped.append(path)
            continue
        if feature in {"lemonadeimage", "thenoiseimage"} and arch != "x64":
            dropped.append(path)
            continue
        ready = prebuilt(binaries, kind, path)
        if ready is None and source not in src:
            dropped.append(path)
            continue
        dst = out / "payload" / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        if ready is not None:
            shutil.copyfile(ready, dst)
        elif kind == "gobuild":
            if go_env is None:
                go_env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "windows",
                          "GOARCH": GOARCH[arch], "GOFLAGS": "-trimpath"}
                if os.name == "nt":
                    go_env, sdk, receipt = windows_go_environment(go_env)
            subprocess.run(
                [str(Path(go_env["GOROOT"]) / "bin/go.exe") if sdk else "go", "build", "-ldflags", ldflags(subsystem), "-o", str(dst), "."],
                cwd=src[source] / frm, check=True,
                env=go_env)
        else:
            shutil.copyfile(src[source] / frm, dst)
    if sdk is not None:
        sdk.validate_sdk_receipt(receipt)
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
    ap.add_argument("--bin", type=Path, metavar="DIR",
                    help="take the programs from DIR instead of building them, "
                         "for a package assembled out of published module "
                         "versions rather than out of checkouts")
    a = ap.parse_args()

    # wix runs with cwd=out, so a relative --out would be applied twice and the
    # package would land under itself.
    a.out = a.out.resolve()

    src = {"installer": HERE}
    for pair in a.src:
        sid, _, d = pair.partition("=")
        src[sid] = Path(d).resolve()

    if subprocess.run([sys.executable, str(HERE / "validate.py")]).returncode:
        return 1

    a.out.mkdir(parents=True, exist_ok=True)
    try:
        dropped = stage(src, a.out, a.arch, a.bin)
    except ValueError as error:
        print("FAIL ", error)
        return 1
    for path in dropped:
        if path not in GATE:
            print(f"FAIL  {path} has no --src for its source, no --bin holding it, "
                  f"and no gate to leave it out")
            return 1

    subprocess.run([sys.executable, str(HERE / "mklicense.py"),
                    str(a.license), str(a.out / "license.rtf")], check=True)

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
