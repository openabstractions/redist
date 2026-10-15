"""Prepare public-source Windows SDK smokes for the disposable MSI account.

The candidate's checked npm/Python artifacts supply the native JavaScript and
Python clients. The Windows program provenance record pins source for the
other SDKs and the config protocol used by every read-only probe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
MODULES = {
    "abstraction-identity": "github.com/openabstractions/abstraction-identity",
    "abstraction-facade": "github.com/openabstractions/abstraction-facade/go",
    "abstraction-config": "github.com/openabstractions/abstraction-config/go",
}
SERVICE_MODULE = "github.com/openabstractions/abstractions/serve"
SERVICE_PROGRAMS = {"openabstractions.exe", "openabstractionsw.exe"}
GO_CORE = "github.com/openabstractions/abstraction-facade/go-core"


def checked(*args: object, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, check=True, timeout=600)


def service_version(tools: Path) -> str:
    programs = {}
    for line in tools.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if fields[0] not in SERVICE_PROGRAMS:
            continue
        if len(fields) != 5 or fields[0] in programs:
            raise RuntimeError("invalid installed service module in tools.tsv")
        programs[fields[0]] = fields[1]
    if set(programs) != SERVICE_PROGRAMS or len(set(programs.values())) != 1:
        raise RuntimeError("installed service programs have no single module pin in tools.tsv")
    module, separator, version = next(iter(programs.values())).partition("@")
    if module != SERVICE_MODULE or not separator or not version:
        raise RuntimeError("installed service programs do not pin the serve module")
    return version


def provenance_rows(record: Path, tools: Path) -> dict[str, dict[str, str]]:
    evidence = json.loads(record.read_text(encoding="utf-8"))
    if evidence.get("schema") != 1:
        raise RuntimeError("unrecognized module provenance record")
    version = service_version(tools)
    graphs = [item for item in evidence["modules"]
              if item.get("input", {}).get("path") == SERVICE_MODULE]
    if len(graphs) != 1 or graphs[0]["input"].get("version") != version:
        raise RuntimeError("candidate provenance lacks the exact installed service graph")
    graph = graphs[0]
    rows: dict[str, dict[str, str]] = {}
    for selected in graph["selected"]:
        path = selected["path"]
        if not path.startswith("github.com/openabstractions/"):
            continue
        if path in rows:
            raise RuntimeError("duplicate module in installed service graph: " + path)
        rows[path] = selected
    service = rows.get(SERVICE_MODULE)
    if (not service or service.get("version") != version
            or service.get("expected_commit") != graph["input"].get("expected_commit")):
        raise RuntimeError("installed service graph contradicts its input pin")
    required = set(MODULES.values()) | {GO_CORE}
    if not required.issubset(rows):
        raise RuntimeError("candidate service graph lacks identity, facade, config or facade core SDK pin")
    for path in required:
        row = rows[path]
        if (not row.get("expected_commit") or not row.get("tag")
                or row.get("origin_hash") != row["expected_commit"]
                or not row.get("repository")):
            raise RuntimeError("SDK source has no verified published tag and commit")
    return rows


def pins(rows: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {name: rows[module] for name, module in MODULES.items()}


def checkout_sources(root: Path, selected: dict[str, dict[str, str]]) -> None:
    root.mkdir()
    for name, row in selected.items():
        source = root / name
        checked("git", "clone", "--quiet", "--no-checkout", row["repository"], source)
        checked("git", "-C", source, "checkout", "--quiet", row["expected_commit"])
        actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if actual != row["expected_commit"]:
            raise RuntimeError(f"{name} checkout differs from candidate module provenance")


def copy_probe(name: str, out: Path) -> None:
    shutil.copy2(HERE / name, out / name)


def prepare_python(out: Path, sources: Path, wheel_dir: Path) -> None:
    wheel = list(wheel_dir.glob("abstraction_ipc-*-win_amd64.whl"))
    if len(wheel) != 1:
        raise RuntimeError("one candidate Windows x64 abstraction-ipc wheel required")
    target = out / "python"
    checked("python", "-m", "pip", "install", "--disable-pip-version-check", "--no-deps",
            "--no-index", "--target", target, wheel[0])
    for name in ("abstraction-facade", "abstraction-config"):
        package = sources / name / "py" / "abstraction"
        if not package.is_dir():
            raise RuntimeError("pinned Python source missing: " + str(package))
        shutil.copytree(package, target / "abstraction", dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    copy_probe("python_probe.py", out)
    checked("python", "-m", "py_compile", out / "python_probe.py")


def prepare_javascript(out: Path, sources: Path, npm_dir: Path, temporary: Path) -> None:
    archive = list(npm_dir.glob("*.tgz"))
    names = ("@openabstractions/ipc", "@openabstractions/ipc-win32-x64", "@openabstractions/facade")
    by_name = {}
    for package in archive:
        with tarfile.open(package, "r:gz") as content:
            metadata = json.load(content.extractfile("package/package.json"))
        if metadata["name"] in by_name:
            raise RuntimeError("duplicate candidate npm package: " + metadata["name"])
        by_name[metadata["name"]] = package
    chosen = []
    for name in names:
        if name not in by_name:
            raise RuntimeError("candidate npm artifact missing: " + name)
        chosen.append(by_name[name])
    packed = temporary / "npm-pack"
    packed.mkdir()
    npm_env = dict(os.environ, NPM_CONFIG_CACHE=str(temporary / "npm-cache"))
    node = shutil.which("node.exe")
    if not node:
        raise RuntimeError("setup-node did not provide node.exe")
    npm_cli = Path(node).parent / "node_modules" / "npm" / "bin" / "npm-cli.js"
    if not npm_cli.is_file():
        raise RuntimeError("setup-node did not provide its matching npm CLI")
    checked(node, npm_cli, "pack", "--offline", "--ignore-scripts", "--pack-destination", packed,
            sources / "abstraction-config" / "javascript", env=npm_env)
    config = list(packed.glob("openabstractions-config-*.tgz"))
    if len(config) != 1:
        raise RuntimeError("pinned config source produced no npm package")
    checked(node, npm_cli, "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund",
            "--no-package-lock", "--prefix", out, *chosen, config[0], env=npm_env)
    copy_probe("javascript_probe.mjs", out)
    checked("node", "--check", out / "javascript_probe.mjs")


def check_go_selection(raw: str, rows: dict[str, dict[str, str]]) -> None:
    resolved = dict(line.rsplit("@", 1) for line in raw.splitlines() if "@" in line)
    for path in set(MODULES.values()) | {GO_CORE}:
        if resolved.get(path) != rows[path]["version"]:
            raise RuntimeError(f"composed Go SDK selects {path}@{resolved.get(path)}, "
                               f"expected verified service graph {rows[path]['version']}")


def prepare_go(out: Path, selected: dict[str, dict[str, str]], rows: dict[str, dict[str, str]], temporary: Path) -> None:
    source = temporary / "go"
    source.mkdir()
    shutil.copy2(HERE / "go_probe.go", source / "main.go")
    facade = selected["abstraction-facade"]["version"]
    core_row = rows.get(GO_CORE)
    if not core_row:
        raise RuntimeError("candidate provenance lacks facade/go-core")
    core = core_row["version"]
    (source / "go.mod").write_text(
        "module openabstractions.invalid/sdk-smoke\n\ngo 1.26.0\n\nrequire (\n"
        f" github.com/openabstractions/abstraction-facade/go {facade}\n"
        f" github.com/openabstractions/abstraction-facade/go-core {core}\n)\n", encoding="utf-8")
    env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="-trimpath -p=2")
    checked("go", "mod", "tidy", cwd=source, env=env)
    graph = subprocess.check_output(["go", "list", "-m", "-f", "{{.Path}}@{{.Version}}", "all"],
                                    cwd=source, env=env, text=True, timeout=600)
    check_go_selection(graph, rows)
    checked("go", "build", "-o", out / "go_probe.exe", ".", cwd=source, env=env)


def msvc_cmake() -> tuple[Path, str]:
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    if not vswhere.is_file():
        raise RuntimeError("Visual Studio compiler inventory is unavailable")
    base = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                                    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property",
                                    "installationPath"], text=True).strip()
    if not base:
        raise RuntimeError("Visual Studio C++ build tools are unavailable")
    version = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                                       "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property",
                                       "installationVersion"], text=True).strip()
    path = Path(base)
    major = version.partition(".")[0]
    generator = {"17": "Visual Studio 17 2022", "18": "Visual Studio 18 2026"}.get(major)
    cmake = path / "Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
    if not generator or not cmake.is_file():
        raise RuntimeError("Visual Studio has no supported bundled CMake")
    return cmake, generator


def prepare_cpp(out: Path, sources: Path, temporary: Path) -> Path:
    cmake, generator = msvc_cmake()
    prefix = temporary / "cpp-prefix"
    for name, extra in (
        ("abstraction-identity", ["-DBUILD_SHARED_LIBS=OFF"]),
        ("abstraction-config", []),
        ("abstraction-facade", ["-DABSTRACTION_FACADE_BUILD_AGGREGATE=OFF",
                                "-DABSTRACTION_FACADE_BUILD_RESOLUTION=ON"]),
    ):
        build = temporary / ("build-" + name)
        checked(cmake, "-S", sources / name / "cpp", "-B", build, "-G", generator, "-A", "x64",
                "-DCMAKE_INSTALL_PREFIX=" + str(prefix), "-DCMAKE_PREFIX_PATH=" + str(prefix),
                "-DCMAKE_BUILD_TYPE=Release", *extra)
        if name == "abstraction-identity":
            checked(cmake, "--build", build, "--config", "Release", "--target", "abstraction_ipc")
        checked(cmake, "--install", build, "--config", "Release")
    build = temporary / "build-sdk-cpp"
    checked(cmake, "-S", HERE, "-B", build, "-G", generator, "-A", "x64", "-DCMAKE_PREFIX_PATH=" + str(prefix),
            "-DCMAKE_BUILD_TYPE=Release")
    checked(cmake, "--build", build, "--config", "Release")
    matches = list(build.rglob("cpp_probe.exe"))
    if len(matches) != 1:
        raise RuntimeError("C++ SDK smoke did not produce exactly one executable")
    shutil.copy2(matches[0], out / "cpp_probe.exe")
    return prefix


def prepare_rust(out: Path, sources: Path, temporary: Path, prefix: Path) -> None:
    crate = temporary / "installer" / "sdk_smokes"
    crate.mkdir(parents=True)
    for name in ("Cargo.toml", "rust_probe.rs"):
        shutil.copy2(HERE / name, crate / name)
    env = dict(os.environ, OA_IPC_PREFIX=str(prefix), CARGO_TARGET_DIR=str(temporary / "cargo-target"))
    checked("cargo", "build", "--offline", "--release", "--manifest-path", crate / "Cargo.toml", env=env)
    image = temporary / "cargo-target" / "release" / "rust_probe.exe"
    if not image.is_file():
        raise RuntimeError("Rust SDK smoke executable absent")
    shutil.copy2(image, out / "rust_probe.exe")


def hash_files(out: Path, selected: dict[str, dict[str, str]]) -> None:
    entries = {}
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            entries[path.relative_to(out).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (out / "manifest.json").write_text(json.dumps({"schema": 1, "sources": {
        name: {"module": MODULES[name], "version": row["version"], "commit": row["expected_commit"]}
        for name, row in selected.items()}, "files": entries}, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--npm", required=True, type=Path)
    parser.add_argument("--pypi", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--tools", type=Path, default=Path("tools.tsv"))
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        raise RuntimeError("SDK smoke output already exists: " + str(out))
    rows = provenance_rows(args.provenance, args.tools)
    selected = pins(rows)
    out.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix=".sdk-smokes-build-", dir=out.parent) as scratch:
        temporary = Path(scratch)
        sources = temporary / "sources"
        checkout_sources(sources, selected)
        prepare_python(out, sources, args.pypi)
        prepare_javascript(out, sources, args.npm, temporary)
        prepare_go(out, selected, rows, temporary)
        # C++ and Rust preparation uses these same three pinned source trees.
        prefix = prepare_cpp(out, sources, temporary)
        prepare_rust(out, sources, temporary, prefix)
    copy_probe("run.ps1", out)
    hash_files(out, selected)


if __name__ == "__main__":
    main()
