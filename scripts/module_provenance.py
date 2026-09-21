#!/usr/bin/env python3
"""Verify and record the published Go modules selected by tools.tsv."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

ORG = "github.com/openabstractions/"
VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
IMMUTABLE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
Runner = Callable[..., subprocess.CompletedProcess[str]]


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False, **kwargs)


def checked(runner: Runner, command: list[str], **kwargs) -> str:
    result = runner(command, **kwargs)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{' '.join(command)} failed ({result.returncode}): {detail}")
    return result.stdout


def json_values(raw: str):
    decoder = json.JSONDecoder()
    while raw.strip():
        value, end = decoder.raw_decode(raw.lstrip())
        yield value
        raw = raw.lstrip()[end:]


def read_modules(path: Path) -> list[tuple[str, str]]:
    modules = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith(">") or line.startswith("path\t"):
            continue
        fields = [field.strip() for field in line.split("\t") if field.strip()]
        if len(fields) != 5 or "@" not in fields[1]:
            raise ValueError(f"invalid tools.tsv row: {line}")
        module, version = fields[1].rsplit("@", 1)
        if not module.startswith(ORG) or not VERSION.fullmatch(version):
            raise ValueError(f"module must name an OpenAbstractions semantic version: {fields[1]}")
        modules.add((module, version))
    if not modules:
        raise ValueError("tools.tsv names no program modules")
    return sorted(modules)


def repository_tag(module: str, version: str) -> tuple[str, str]:
    if not module.startswith(ORG) or not VERSION.fullmatch(version):
        raise ValueError(f"unsupported OpenAbstractions module version: {module}@{version}")
    rest = module[len(ORG):]
    repo, slash, subdir = rest.partition("/")
    if not repo or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
        raise ValueError(f"invalid repository in module path: {module}")
    return f"https://github.com/openabstractions/{repo}", f"{subdir + '/' if slash else ''}{version}"


def resolve_tag(runner: Runner, module: str, version: str) -> dict[str, str]:
    repository, tag = repository_tag(module, version)
    ref = f"refs/tags/{tag}"
    raw = checked(runner, ["git", "ls-remote", "--tags", repository, ref, ref + "^{}"])
    found = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in (ref, ref + "^{}") and re.fullmatch(r"[0-9a-f]{40}", parts[0]):
            found[parts[1]] = parts[0]
    if ref not in found:
        raise RuntimeError(f"missing public tag {repository} {tag}")
    commit = found.get(ref + "^{}", found[ref])
    return {"repository": repository, "tag": tag, "tag_object": found[ref], "commit": commit}


def download(runner: Runner, module: str, version: str, cwd: str, env: dict[str, str]) -> dict:
    raw = checked(runner, ["go", "mod", "download", "-json", f"{module}@{version}"], cwd=cwd, env=env)
    value = json.loads(raw)
    if value.get("Error") or value.get("Replace"):
        raise RuntimeError(f"download is replaced or unresolved: {module}@{version}")
    if not value.get("Sum") or not value.get("GoModSum"):
        raise RuntimeError(f"download lacks verified module and go.mod sums: {module}@{version}")
    return value


def verify(tools: Path, runner: Runner = run) -> dict:
    env = dict(os.environ, GOWORK="off", GOFLAGS="-mod=readonly", GOTOOLCHAIN="local",
               GOPRIVATE="", GONOSUMDB="", GOSUMDB="sum.golang.org",
               GOPROXY="https://proxy.golang.org,direct")
    go_version = checked(runner, ["go", "version"], env=env).strip()
    records = []
    tag_cache: dict[tuple[str, str], dict[str, str]] = {}
    download_cache: dict[tuple[str, str], dict] = {}

    def cached_tag(path: str, version: str) -> dict[str, str]:
        key = (path, version)
        if key not in tag_cache:
            tag_cache[key] = resolve_tag(runner, path, version)
        return tag_cache[key]

    def cached_download(path: str, version: str, cwd: str) -> dict:
        key = (path, version)
        if key not in download_cache:
            download_cache[key] = download(runner, path, version, cwd, env)
        return download_cache[key]

    for requested, requested_version in read_modules(tools):
        expected = cached_tag(requested, requested_version)
        with tempfile.TemporaryDirectory(prefix="oa-module-provenance-") as tmp:
            Path(tmp, "go.mod").write_text(
                f"module provenance.invalid/check\n\ngo 1.26\n\nrequire {requested} {requested_version}\n",
                encoding="utf-8")
            # Populate go.sum without permitting any go.mod edit, then inspect the selected graph.
            checked(runner, ["go", "mod", "download", "all"], cwd=tmp, env=env)
            selected = list(json_values(checked(runner, ["go", "list", "-m", "-json", "all"], cwd=tmp, env=env)))
            matches = [item for item in selected if item.get("Path") == requested]
            if len(matches) != 1 or matches[0].get("Version") != requested_version:
                raise RuntimeError(f"selected graph does not contain exact input {requested}@{requested_version}")
            closure = []
            for item in selected:
                if item.get("Replace") or item.get("Error"):
                    raise RuntimeError(f"selected module is replaced or unresolved: {item.get('Path')}")
                if item.get("Main"):
                    continue
                path, version = item.get("Path"), item.get("Version")
                if not path or not version or not IMMUTABLE.fullmatch(version):
                    raise RuntimeError(f"selected dependency lacks an immutable version: {path}@{version}")
                got = cached_download(path, version, tmp)
                row = {"path": path, "version": version, "sum": got["Sum"], "go_mod_sum": got["GoModSum"]}
                origin = got.get("Origin") or {}
                if path.startswith(ORG):
                    tag = cached_tag(path, version)
                    actual = origin.get("Hash")
                    if actual != tag["commit"]:
                        raise RuntimeError(f"Origin.Hash mismatch for {path}@{version}: expected {tag['commit']}, got {actual}")
                    row.update({"expected_commit": tag["commit"], "origin_hash": actual,
                                "repository": tag["repository"], "tag": tag["tag"]})
                closure.append(row)
            records.append({"input": {"path": requested, "version": requested_version,
                                       "expected_commit": expected["commit"]}, "selected": closure})
    return {"schema": 1, "go_version": go_version, "tools": str(tools), "modules": records}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = verify(args.tools)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
