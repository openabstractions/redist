"""Package the PyTorch owner's verified local runtime inputs deterministically.

The same-source pytorchd `setup inputs` command emits enginefiles.Manifest.
That manifest owns the file roster and byte pins. This producer copies those
inputs into the reduced bundle and reports its measured artifact identity.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import sys
import zipfile


BUNDLE_NAME = "pytorch-2.11.0-rocm7.13.0-cpython3.12.10-gfx1151-inputs.zip"
MANIFEST_NAME = BUNDLE_NAME.removesuffix(".zip") + ".manifest.json"
SOURCE_NAME = BUNDLE_NAME.removesuffix("-inputs.zip") + "-source.zip"
SHA = re.compile(r"[0-9a-f]{64}\Z")
BLOCK_SIZE = 1 << 20


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate PyTorch input manifest key: " + key)
        result[key] = value
    return result


def manifest_files(manifest: dict) -> list[dict]:
    """Validate the existing owner format and its package-relative paths."""
    if (not isinstance(manifest, dict) or set(manifest) != {"Files"}
            or not isinstance(manifest["Files"], list) or not manifest["Files"]):
        raise ValueError("invalid PyTorch input manifest")
    files = manifest["Files"]
    names = set()
    previous = ""
    for entry in files:
        if (not isinstance(entry, dict) or set(entry) != {"Path", "Size", "SHA256"}
                or not isinstance(entry["Path"], str)
                or type(entry["Size"]) is not int or not 0 <= entry["Size"] < 1 << 63
                or not isinstance(entry["SHA256"], str) or not SHA.fullmatch(entry["SHA256"])):
            raise ValueError("invalid PyTorch input file pin")
        name = entry["Path"]
        parts = name.split("/")
        if (len(parts) < 2 or any(part in ("", ".", "..") for part in parts)
                or any(character in name for character in "\\:\x00")
                or parts[0] not in ("python", "source", "wheels")
                or parts[0] == "wheels" and len(parts) != 2):
            raise ValueError("invalid PyTorch input package path: " + name)
        if name in names or name <= previous:
            raise ValueError("PyTorch input roster must be unique and sorted by Path")
        names.add(name)
        previous = name
    return files


def load_manifest(path: Path) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    manifest_files(value)
    return value


def stream_identity(stream) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: stream.read(BLOCK_SIZE), b""):
        size += len(block)
        digest.update(block)
    return size, digest.hexdigest()


def measured(path: Path) -> tuple[int, str]:
    with Path(path).open("rb") as stream:
        return stream_identity(stream)


def _input_paths(python_home: Path, wheels: list[Path], source_repo: Path,
                 files: list[dict]) -> list[Path]:
    selected = []
    for entry in files:
        prefix, relative = entry["Path"].split("/", 1)
        expected = (entry["Size"], entry["SHA256"])
        if prefix == "wheels":
            candidates = (candidate for folder in wheels
                          for candidate in sorted(Path(folder).rglob(relative)))
            match = next((candidate for candidate in candidates
                          if candidate.is_file() and candidate.stat().st_size == entry["Size"]
                          and measured(candidate) == expected), None)
            if match is None:
                raise ValueError("no supplied wheel matches the current pin: " + entry["Path"])
        else:
            root = python_home if prefix == "python" else source_repo
            match = Path(root).joinpath(*relative.split("/"))
            if not match.is_file() or measured(match) != expected:
                raise ValueError("PyTorch input differs from the current pin: " + entry["Path"])
        selected.append(match)
    return selected


def _zip_info(entry: dict) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(entry["Path"], date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.file_size = entry["Size"]
    return info


def _verify_archive(bundle: Path, files: list[dict]) -> None:
    with Path(bundle).open("rb") as headers, zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != [entry["Path"] for entry in files]:
            raise ValueError("PyTorch bundle member roster differs from the manifest")
        if archive.comment:
            raise ValueError("PyTorch bundle has noncanonical metadata")
        for info, entry in zip(archive.infolist(), files):
            large = [value for value in (info.file_size, info.compress_size, info.header_offset)
                     if value > zipfile.ZIP64_LIMIT]
            extra = struct.pack("<HH" + "Q" * len(large), 1, 8 * len(large), *large) if large else b""
            flags = 0 if entry["Path"].isascii() else 0x800
            canonical = _zip_info(entry)
            canonical.CRC, canonical.compress_size = info.CRC, info.compress_size
            zip64 = entry["Size"] * 1.05 > zipfile.ZIP64_LIMIT
            local_header = canonical.FileHeader(zip64=zip64)
            headers.seek(info.header_offset)
            if headers.read(len(local_header)) != local_header:
                raise ValueError("PyTorch bundle has noncanonical local metadata: " + entry["Path"])
            version = zipfile.ZIP64_VERSION if zip64 or large else zipfile.DEFAULT_VERSION
            if (info.compress_type != zipfile.ZIP_STORED
                    or info.date_time != (1980, 1, 1, 0, 0, 0)
                    or info.create_system != 3 or info.external_attr != 0o100644 << 16
                    or info.internal_attr != 0 or info.comment or info.extra != extra
                    or info.flag_bits != flags
                    or info.create_version != version or info.extract_version != version
                    or info.compress_size != entry["Size"] or info.file_size != entry["Size"]):
                raise ValueError("PyTorch bundle has noncanonical metadata: " + entry["Path"])
            with archive.open(info) as stream:
                if stream_identity(stream) != (entry["Size"], entry["SHA256"]):
                    raise ValueError("PyTorch bundle file differs from the manifest: " + entry["Path"])


def verify_bundle(bundle: Path, manifest: dict) -> dict:
    bundle = Path(bundle)
    files = manifest_files(manifest)
    if bundle.name != BUNDLE_NAME or not bundle.is_file():
        raise ValueError("PyTorch bundle filename differs from the selected artifact")
    _verify_archive(bundle, files)
    size, digest = measured(bundle)
    return {"name": bundle.name, "size_bytes": size, "sha256": digest}


def derive(python_home: Path, wheels: list[Path], source_repo: Path,
           bundle: Path, manifest: dict) -> dict:
    files = manifest_files(manifest)
    bundle = Path(bundle)
    if bundle.name != BUNDLE_NAME:
        raise ValueError("PyTorch bundle filename differs from the selected artifact")
    inputs = _input_paths(Path(python_home), wheels, Path(source_repo), files)
    bundle.parent.mkdir(parents=True, exist_ok=True)
    partial = bundle.with_name(bundle.name + ".partial")
    if partial.exists():
        raise FileExistsError("unfinished PyTorch bundle exists: " + str(partial))
    try:
        with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_STORED) as output:
            for entry, source in zip(files, inputs):
                size, digest = 0, hashlib.sha256()
                with source.open("rb") as stream, output.open(_zip_info(entry), "w") as member:
                    for block in iter(lambda: stream.read(BLOCK_SIZE), b""):
                        member.write(block)
                        size += len(block)
                        digest.update(block)
                if (size, digest.hexdigest()) != (entry["Size"], entry["SHA256"]):
                    raise ValueError("PyTorch input changed during bundle writing: " + entry["Path"])
        _verify_archive(partial, files)
        size, digest = measured(partial)
        partial.replace(bundle)
        return {"name": bundle.name, "size_bytes": size, "sha256": digest}
    finally:
        partial.unlink(missing_ok=True)


# Source fragment for installer/pytorch_engine.py, before main().
INPUT_REPOSITORY = "openabstractions/redist"
INPUT_OWNER = "openabstractions/abstraction-provider-pytorch"
# Derived 2026-11-01 from python.org CPython 3.12.10 without its __pycache__
# folders, the 25 lean-lock wheels and the Hummingbird-XT pins; two
# derivations gave the same bytes. The 0.4.0 pair (1,680,150,940 and 132,827
# bytes) carried the deriving account's byte caches and could not be rebuilt.
INPUT_PINS = {
    BUNDLE_NAME: {"size_bytes": 1673323779,
                  "sha256": "f8260fd18d204793d8971a0e91a6e7ed1d15c6f8a2113ad8c5f1344e4218e4f6"},
    MANIFEST_NAME: {"size_bytes": 88994,
                    "sha256": "ba3c4c1dfd0a5ea3d7a5276771e2c68bfd3906c53b0972405d9d7ff385182c8e"},
    SOURCE_NAME: {"size_bytes": 44252,
                  "sha256": "2dc411095e511ac05bb449acb4f488afe0af4d0b7c2fdab39eca3d7d204b2ee6"},
}


def release_assets(version: str) -> dict:
    """The retained runtime inputs keep their exact final release URLs."""
    if version != 'v0.8.0':
        raise ValueError('PyTorch runtime release differs from the frozen v0.8.0 inputs')
    return {name: dict(pin, url='https://github.com/openabstractions/redist/releases/download/' + version + '/' + name)
            for name, pin in INPUT_PINS.items()}


def catalogue_row() -> dict:
    """The retained R54 engine row; source identifies its archived inputs."""
    return dict(id='pytorch', binary_zip=BUNDLE_NAME,
        binary_sha256=INPUT_PINS[BUNDLE_NAME]['sha256'], binary_bytes=INPUT_PINS[BUNDLE_NAME]['size_bytes'],
        source_zip=SOURCE_NAME, source_sha256=INPUT_PINS[SOURCE_NAME]['sha256'],
        source_bytes=INPUT_PINS[SOURCE_NAME]['size_bytes'],
        source_commit='6ba0c4d0a388eb00020a87b4be9266bcada26eb9',
        source_url='https://github.com/openabstractions/abstractions/commit/6ba0c4d0a388eb00020a87b4be9266bcada26eb9',
        signer='unsigned', version='2.11.0', platform='windows/amd64', peak_bytes=3221225472,
        license='PSF-2.0, BSD-3-Clause and bundled notices', publisher='OpenAbstractions',
        install_identity='pt', action='archive_per_user')


def verify_release_inputs(directory: Path) -> dict:
    directory = Path(directory)
    for name, pin in INPUT_PINS.items():
        path = directory / name
        if path.is_symlink() or path.is_junction() or not path.is_file():
            raise ValueError('PyTorch release input is not an ordinary file: ' + name)
        if measured(path) != (pin['size_bytes'], pin['sha256']):
            raise ValueError('PyTorch release input differs from the frozen size/hash: ' + name)
    manifest = load_manifest(directory / MANIFEST_NAME)
    if verify_bundle(directory / BUNDLE_NAME, manifest) != dict(name=BUNDLE_NAME, **INPUT_PINS[BUNDLE_NAME]):
        raise ValueError('PyTorch runtime ZIP differs from its reviewed complete owner manifest')
    return {name: dict(pin) for name, pin in INPUT_PINS.items()}


def copy_release_inputs(directory: Path, destination: Path) -> dict:
    """Copy the verified pair through the existing draft/release assembly."""
    pins = verify_release_inputs(directory)
    created = []
    try:
        for name in pins:
            target = Path(destination) / name
            with (Path(directory) / name).open('rb') as reader, target.open('xb') as writer:
                created.append(target)
                shutil.copyfileobj(reader, writer, length=BLOCK_SIZE)
        verify_release_inputs(destination)
    except BaseException:
        for target in reversed(created):
            target.unlink()
        raise
    return pins


def prepare(pytorchd: Path, python_home: Path, wheels: list[Path], source_repo: Path,
            output: Path, *, run=None) -> dict:
    """Write the owner manifest and the bundle a checkout build reads.

    The same-source `pytorchd setup inputs` command emits the manifest; its
    bytes and the derived bundle must equal INPUT_PINS. Reads local files
    only; nothing is downloaded or started besides that read-only command."""
    import subprocess
    run = run or subprocess.run
    output = Path(output)
    command = [str(pytorchd), "setup", "inputs", "--python-home", str(python_home), "--source", str(source_repo)]
    for folder in wheels:
        command += ["--wheels", str(folder)]
    result = run(command, capture_output=True, check=False)
    if result.returncode:
        raise ValueError("pytorchd setup inputs failed: " + result.stderr.decode("utf-8", "replace").strip())
    manifest_bytes = result.stdout
    pin = INPUT_PINS[MANIFEST_NAME]
    actual = (len(manifest_bytes), hashlib.sha256(manifest_bytes).hexdigest())
    if actual != (pin["size_bytes"], pin["sha256"]):
        raise ValueError(f"PyTorch input manifest differs from the reviewed pin: {actual[0]} bytes sha256 {actual[1]}")
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / MANIFEST_NAME
    if manifest_path.exists() and manifest_path.read_bytes() != manifest_bytes:
        raise FileExistsError("a different PyTorch input manifest is already prepared: " + str(manifest_path))
    manifest_path.write_bytes(manifest_bytes)
    manifest = load_manifest(manifest_path)
    bundle = output / BUNDLE_NAME
    if bundle.exists():
        identity = verify_bundle(bundle, manifest)
    else:
        identity = derive(python_home, wheels, source_repo, bundle, manifest)
    if identity != {"name": BUNDLE_NAME, **INPUT_PINS[BUNDLE_NAME]}:
        raise ValueError("PyTorch input bundle differs from the reviewed pin: " + json.dumps(identity, sort_keys=True))
    return identity


def input_source(path: Path) -> str:
    """The installer source owner binds both optional PyTorch inputs to one commit."""
    if Path(path).stat().st_size > 1024 * 1024:
        raise ValueError("PyTorch input source metadata is too large")
    selected = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith(">"):
            continue
        fields = line.split()
        if fields[:1] not in (["pytorchimage"], ["pytorchengine"]):
            continue
        if (len(fields) != 3 or fields[0] in selected or fields[1] != INPUT_OWNER
                or not re.fullmatch(r"[0-9a-f]{40}", fields[2])):
            raise ValueError("PyTorch input source is absent, duplicated or unpinned")
        selected[fields[0]] = fields[2]
    if set(selected) != {"pytorchimage", "pytorchengine"} or len(set(selected.values())) != 1:
        raise ValueError("PyTorch input and adapter sources must name the same exact commit")
    return selected["pytorchimage"]


def input_seed(source: str, version: str, owner: str) -> tuple[str, dict]:
    if (not re.fullmatch(r"[0-9a-f]{40}", source or "")
            or not re.fullmatch(r"[0-9a-f]{40}", owner or "")
            or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version or "")):
        raise ValueError("PyTorch input seed needs exact source, owner and candidate version")
    tag = "oa-inputs-pytorch-" + source
    identity = {"schema": 1, "purpose": "pytorch-reviewed-native-inputs",
                "candidate_source": source, "candidate_version": version,
                "input_owner_repository": INPUT_OWNER, "input_owner_commit": owner,
                "origin": "reviewed-local-derivation",
                "files": {name: dict(pin) for name, pin in INPUT_PINS.items()}}
    return tag, identity


def input_assets(release: dict, source: str, version: str, owner: str,
                 *, complete: bool) -> dict:
    """Check the owned draft and server-measured digests without name substitution."""
    tag, identity = input_seed(source, version, owner)
    body = json.dumps(identity, sort_keys=True) + "\n"
    if (not isinstance(release, dict) or type(release.get("id")) is not int
            or release["id"] < 1 or release.get("draft") is not True
            or release.get("tag_name") != tag or release.get("target_commitish") != source
            or not isinstance(release.get("body"), str)
            or release["body"].replace("\r\n", "\n") != body
            or not isinstance(release.get("assets"), list) or len(release["assets"]) > len(INPUT_PINS)):
        raise ValueError("PyTorch input origin must be this source's unmodified draft")
    selected = {}
    ids = set()
    for asset in release["assets"]:
        name = asset.get("name") if isinstance(asset, dict) else None
        if name not in INPUT_PINS or name in selected:
            raise ValueError("PyTorch input draft contains foreign or duplicate assets")
        pin = INPUT_PINS[name]
        if (type(asset.get("id")) is not int or asset["id"] < 1 or asset["id"] in ids
                or asset.get("state") != "uploaded" or type(asset.get("size")) is not int
                or asset["size"] != pin["size_bytes"]
                or asset.get("digest") != "sha256:" + pin["sha256"]):
            raise ValueError("PyTorch input draft asset differs from reviewed bytes")
        ids.add(asset["id"])
        selected[name] = {"id": asset["id"], "name": name, **pin}
    if complete and set(selected) != set(INPUT_PINS):
        raise ValueError("PyTorch input draft is missing an exact input asset")
    return selected


def input_tag(tag: dict | None, source: str, *, required=True) -> None:
    if (tag is None and required) or (tag is not None and (not isinstance(tag, dict)
                            or not isinstance(tag.get("object"), dict)
                            or tag.get("object", {}).get("type") != "commit"
                            or tag["object"].get("sha") != source)):
        raise ValueError("PyTorch input draft tag differs from the exact source")


def input_run(run: dict, run_id: int, source: str, attempt: int) -> None:
    if (not isinstance(run, dict) or run.get("id") != run_id
            or run.get("head_sha") != source or run.get("run_attempt") != attempt
            or run.get("repository", {}).get("full_name") != INPUT_REPOSITORY
            or run.get("head_repository", {}).get("full_name") != INPUT_REPOSITORY
            or run.get("path") != ".github/workflows/candidate.yml"
            or run.get("event") != "workflow_dispatch"):
        raise ValueError("PyTorch input run is not this exact same-repository manual candidate")


def input_environment(environment, source, run_id, attempt):
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": INPUT_REPOSITORY,
                "GITHUB_SHA": source, "GITHUB_RUN_ID": str(run_id),
                "GITHUB_RUN_ATTEMPT": str(attempt)}
    if (any(type(value) is not int or value < 1 for value in (run_id, attempt))
            or any(environment.get(key) != value for key, value in expected.items())):
        raise ValueError("PyTorch input receipt requires the actual same-repository CI run")


def input_receipt(source, version, owner, run_id, attempt, release_id, assets, manifest):
    tag, _ = input_seed(source, version, owner)
    files = manifest_files(manifest)
    groups = {group: sum(item["Path"].startswith(group + "/") for item in files)
              for group in ("python", "wheels", "source")}
    return {"schema": 1, "mode": "github-actions",
            "qualification": "reviewed-input-byte-intake", "origin": "reviewed-local-derivation",
            "candidate_source": source, "candidate_version": version,
            "run_id": run_id, "run_attempt": attempt, "platform": "win32-x64",
            "input_owner_repository": INPUT_OWNER, "input_owner_commit": owner,
            "seed": {"repository": INPUT_REPOSITORY, "release_id": release_id,
                     "tag": tag, "assets": assets}, "files": len(files), "groups": groups,
            "verification": "canonical complete roster and every member size/SHA256 PASS"}


def receive_assets(output: Path, repository: str, assets: dict, *, fetch, download, created: list) -> None:
    """Receive exact release-asset bytes; the caller owns origin and output cleanup."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not assets:
        raise ValueError("invalid input repository or empty asset selection")
    ids = set()
    for name, pin in assets.items():
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) or name in (".", "..")
                or type(pin.get("id")) is not int or pin["id"] < 1 or pin["id"] in ids
                or pin.get("name") != name or type(pin.get("size_bytes")) is not int
                or pin["size_bytes"] < 0 or not SHA.fullmatch(pin.get("sha256", ""))):
            raise ValueError("invalid input asset identity")
        ids.add(pin["id"])
        direct = fetch(f"repos/{repository}/releases/assets/{pin['id']}")
        if (not isinstance(direct, dict) or direct.get("id") != pin["id"]
                or direct.get("name") != name or direct.get("state") != "uploaded"
                or direct.get("size") != pin["size_bytes"]
                or direct.get("digest") != "sha256:" + pin["sha256"]):
            raise ValueError("direct input asset differs from selected identity")
    for name, pin in assets.items():
        target = Path(output) / name
        with target.open('xb'):
            pass
        created.append(target)
        download(["api", "-H", "Accept: application/octet-stream",
                  f"repos/{repository}/releases/assets/{pin['id']}"], target)
        if measured(target) != (pin["size_bytes"], pin["sha256"]):
            raise ValueError("downloaded input bytes differ from selected identity")


def intake_inputs(output: Path, sources: Path, source: str, version: str,
                  release_id: int, bundle_id: int, manifest_id: int,
                  run_id: int, attempt: int, *, fetch, optional_fetch, download,
                  environment: dict, source_id=None) -> dict:
    """Read the exact draft assets and attest byte intake in the genuine current CI run."""
    input_environment(environment, source, run_id, attempt)
    if any(type(value) is not int or value < 1 for value in (release_id, bundle_id, manifest_id)):
        raise ValueError("PyTorch input seed requires positive exact IDs")
    if SOURCE_NAME in INPUT_PINS and (type(source_id) is not int or source_id < 1):
        raise ValueError('PyTorch source archive requires a positive exact asset ID')
    owner = input_source(sources)
    tag, _ = input_seed(source, version, owner)
    input_run(fetch(f"repos/{INPUT_REPOSITORY}/actions/runs/{run_id}"), run_id, source, attempt)
    release = fetch(f"repos/{INPUT_REPOSITORY}/releases/{release_id}")
    assets = input_assets(release, source, version, owner, complete=True)
    if release["id"] != release_id or (assets[BUNDLE_NAME]["id"], assets[MANIFEST_NAME]["id"]) != (bundle_id, manifest_id):
        raise ValueError("PyTorch input asset IDs differ from the reviewed seed")
    if SOURCE_NAME in assets and assets[SOURCE_NAME]['id'] != source_id:
        raise ValueError('PyTorch source archive asset ID differs from the reviewed seed')
    input_tag(optional_fetch(f"repos/{INPUT_REPOSITORY}/git/ref/tags/{tag}"), source)
    output = Path(output)
    if output.exists():
        raise FileExistsError("PyTorch intake output already exists")
    output.mkdir(parents=True)
    created = []
    try:
        receive_assets(output, INPUT_REPOSITORY, assets, fetch=fetch, download=download, created=created)
        if measured(output / MANIFEST_NAME) != (INPUT_PINS[MANIFEST_NAME]["size_bytes"],
                                               INPUT_PINS[MANIFEST_NAME]["sha256"]):
            raise ValueError("PyTorch downloaded owner manifest differs")
        manifest = load_manifest(output / MANIFEST_NAME)
        actual = verify_bundle(output / BUNDLE_NAME, manifest)
        if actual != {"name": BUNDLE_NAME, **INPUT_PINS[BUNDLE_NAME]}:
            raise ValueError("PyTorch downloaded input bundle differs")
        receipt = input_receipt(source, version, owner, run_id, attempt, release_id, assets, manifest)
        target = output / "pytorch-input-receipt.json"
        created.append(target)
        target.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        return receipt
    except Exception:
        for target in reversed(created):
            target.unlink(missing_ok=True)
        # Preserve any unowned file that appeared while intake was running.
        if not any(output.iterdir()):
            output.rmdir()
        raise


def consume_inputs(output: Path, sources: Path, source: str, version: str,
                   release_id: int, bundle_id: int, manifest_id: int, artifact_id: int,
                   run_id: int, attempt: int, *, publication, environment: dict, source_id=None) -> dict:
    """Bind the newest intake job and exact immutable artifact before Windows packaging."""
    import shutil
    import tempfile
    input_environment(environment, source, run_id, attempt)
    if any(type(value) is not int or value < 1 for value in (release_id, bundle_id, manifest_id, artifact_id)):
        raise ValueError("PyTorch input consumer requires positive exact IDs")
    if SOURCE_NAME in INPUT_PINS and (type(source_id) is not int or source_id < 1):
        raise ValueError('PyTorch source archive requires a positive exact asset ID')
    owner = input_source(sources)
    run, jobs, artifacts = publication.inspect(INPUT_REPOSITORY, run_id)
    input_run(run, run_id, source, attempt)
    selected_jobs = [job for job in jobs if job.get("name") == "pytorch-input"]
    if (len(selected_jobs) != 1 or selected_jobs[0].get("head_sha") != source
            or selected_jobs[0].get("status") != "completed"
            or selected_jobs[0].get("conclusion") != "success"
            or type(selected_jobs[0].get("run_attempt")) is not int
            or not 1 <= selected_jobs[0]["run_attempt"] <= attempt):
        raise ValueError("newest PyTorch intake job did not pass")
    intake_attempt = selected_jobs[0]["run_attempt"]
    selected = [item for item in artifacts if item.get("name") == f"abstraction-pytorch-inputs-{intake_attempt}"]
    if len(selected) != 1:
        raise ValueError("PyTorch input artifact is missing or ambiguous")
    artifact = selected[0]
    maximum = sum(pin["size_bytes"] for pin in INPUT_PINS.values()) + 2 * 1024 * 1024
    if (type(artifact.get("id")) is not int or artifact["id"] != artifact_id or artifact.get("expired") is not False
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest", ""))
            or type(artifact.get("size_in_bytes")) is not int or not 1 <= artifact["size_in_bytes"] <= maximum
            or artifact.get("workflow_run", {}).get("id") != run_id
            or artifact.get("workflow_run", {}).get("head_sha") != source):
        raise ValueError("PyTorch input artifact identity, digest or retention differs")
    identities = [(BUNDLE_NAME, bundle_id), (MANIFEST_NAME, manifest_id)]
    if SOURCE_NAME in INPUT_PINS:
        identities.append((SOURCE_NAME, source_id))
    if len({identity for _, identity in identities}) != len(identities):
        raise ValueError('PyTorch input asset IDs must be distinct')
    assets = {name: {"id": identity, "name": name, **INPUT_PINS[name]} for name, identity in identities}
    output = Path(output)
    if output.exists():
        raise FileExistsError("PyTorch consumer output already exists")
    expected_files = {*INPUT_PINS, "pytorch-input-receipt.json"}
    created = []
    output.mkdir(parents=True)
    try:
        with tempfile.TemporaryDirectory(prefix="oa-pytorch-input-artifact-") as temporary:
            blob = Path(temporary) / "artifact.zip"
            publication.download(["api", f"repos/{INPUT_REPOSITORY}/actions/artifacts/{artifact_id}/zip"], blob)
            if measured(blob) != (artifact["size_in_bytes"], artifact["digest"][7:]):
                raise ValueError("PyTorch input artifact bytes differ from GitHub digest")
            with zipfile.ZipFile(blob) as archive:
                entries = archive.infolist()
                if len(entries) != len(expected_files) or {item.filename for item in entries} != expected_files:
                    raise ValueError("PyTorch input artifact requires exactly the pinned root-level files and receipt")
                for item in entries:
                    size_ok = (item.file_size == INPUT_PINS[item.filename]["size_bytes"]
                               if item.filename in INPUT_PINS else item.file_size <= 1024 * 1024)
                    kind = (item.external_attr >> 16) & 0o170000
                    if item.is_dir() or kind not in (0, 0o100000) or item.flag_bits & 1 or not size_ok:
                        raise ValueError("PyTorch input artifact member type/size differs")
                    target = output / item.filename
                    created.append(target)
                    with archive.open(item) as incoming, target.open("xb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing, length=BLOCK_SIZE)
        if measured(output / MANIFEST_NAME) != (INPUT_PINS[MANIFEST_NAME]["size_bytes"], INPUT_PINS[MANIFEST_NAME]["sha256"]):
            raise ValueError("PyTorch input artifact manifest differs")
        manifest = load_manifest(output / MANIFEST_NAME)
        if verify_bundle(output / BUNDLE_NAME, manifest) != {"name": BUNDLE_NAME, **INPUT_PINS[BUNDLE_NAME]}:
            raise ValueError("PyTorch input artifact bundle differs")
        if SOURCE_NAME in INPUT_PINS and measured(output / SOURCE_NAME) != (
                INPUT_PINS[SOURCE_NAME]['size_bytes'], INPUT_PINS[SOURCE_NAME]['sha256']):
            raise ValueError('PyTorch input source archive differs from its reviewed pin')
        expected = input_receipt(source, version, owner, run_id, intake_attempt, release_id, assets, manifest)
        if json.loads((output / "pytorch-input-receipt.json").read_text(encoding="utf-8")) != expected:
            raise ValueError("PyTorch intake receipt differs from the exact source/run/seed bytes")
        receipt = {"schema": 1, "mode": "github-actions-artifact-consumption",
                   "candidate_source": source, "candidate_version": version,
                   "run_id": run_id, "run_attempt": attempt, "intake_attempt": intake_attempt,
                   "artifact": {key: artifact[key] for key in ("id", "name", "digest")},
                   "input_owner_commit": owner, "seed": expected["seed"],
                   "verification": "immutable artifact, exact intake receipt and canonical bundle PASS"}
        target = output / "pytorch-consumer-receipt.json"
        created.append(target)
        target.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        return receipt
    except Exception:
        for target in reversed(created):
            target.unlink(missing_ok=True)
        if not any(output.iterdir()):
            output.rmdir()
        raise


def input_publication():
    # Existing publication/streaming owners in source and public redist layouts.
    root = Path(__file__).resolve().parent.parent
    scripts = root / "scripts"
    if not (scripts / "promote.py").is_file():
        scripts = root / "research/org-edits/redist"
    sys.path.insert(0, str(scripts))
    import promote
    return promote


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest="operation")
    derive_parser = operations.add_parser("derive", help="package verified local owner inputs")
    derive_parser.add_argument("--manifest", type=Path, required=True)
    derive_parser.add_argument("--python-home", type=Path, required=True)
    derive_parser.add_argument("--wheels", type=Path, nargs="+", action="append", required=True)
    derive_parser.add_argument("--source", type=Path, required=True)
    derive_parser.add_argument("--bundle", type=Path, required=True)
    verify_parser = operations.add_parser("verify", help="verify a derived bundle against owner inputs")
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--bundle", type=Path, required=True)
    prepare_parser = operations.add_parser(
        "prepare", help="write the reviewed manifest and bundle a checkout build reads (default "
                        ".build/engines/" + BUNDLE_NAME.removesuffix("-inputs.zip") + ")")
    prepare_parser.add_argument("--pytorchd", type=Path, required=True,
                                help="pytorchd.exe built from this checkout's abstraction-provider-pytorch")
    prepare_parser.add_argument("--python-home", type=Path, required=True,
                                help="python.org's CPython 3.12.10 x64 folder")
    prepare_parser.add_argument("--wheels", type=Path, nargs="+", action="append", required=True,
                                help="folders holding the lean lock's 25 wheels")
    prepare_parser.add_argument("--source", type=Path, required=True,
                                help="the Hummingbird-XT repository at its reviewed commit")
    prepare_parser.add_argument("--out", type=Path,
                                default=Path(__file__).resolve().parent.parent / ".build" / "engines"
                                / BUNDLE_NAME.removesuffix("-inputs.zip"))
    for operation, help_text in (
            ("intake", "verify exact authenticated draft assets and attest genuine CI input intake"),
            ("consume", "verify the newest successful intake job and immutable same-run artifact")):
        intake = operations.add_parser(operation, help=help_text)
        intake.add_argument("--sources", type=Path, required=True)
        intake.add_argument("--source", required=True)
        intake.add_argument("--version", required=True)
        intake.add_argument("--release-id", type=int, required=True)
        intake.add_argument("--bundle-asset-id", type=int, required=True)
        intake.add_argument("--manifest-asset-id", type=int, required=True)
        intake.add_argument("--source-asset-id", type=int)
        intake.add_argument("--run-id", type=int, required=True)
        intake.add_argument("--attempt", type=int, required=True)
        intake.add_argument("--output", type=Path, required=True)
        if operation == "consume":
            intake.add_argument("--artifact-id", type=int, required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.operation is None:
        parser.print_help()
        return
    if args.operation in ("intake", "consume"):
        import os
        publication = input_publication()
        if args.operation == "intake":
            result = intake_inputs(args.output, args.sources, args.source, args.version,
                               args.release_id, args.bundle_asset_id, args.manifest_asset_id,
                               args.run_id, args.attempt, fetch=publication.api,
                               optional_fetch=publication.optional_api, download=publication.download,
                               environment=dict(os.environ), source_id=args.source_asset_id)
        else:
            result = consume_inputs(args.output, args.sources, args.source, args.version,
                                    args.release_id, args.bundle_asset_id, args.manifest_asset_id,
                                    args.artifact_id, args.run_id, args.attempt,
                                    publication=publication, environment=dict(os.environ), source_id=args.source_asset_id)
        print(json.dumps(result, sort_keys=True))
        return
    if args.operation == "prepare":
        wheels = [folder for group in args.wheels for folder in group]
        result = prepare(args.pytorchd, args.python_home, wheels, args.source, args.out)
        print(json.dumps(result, sort_keys=True))
        return
    manifest = load_manifest(args.manifest)
    if args.operation == "derive":
        wheels = [folder for group in args.wheels for folder in group]
        result = derive(args.python_home, wheels, args.source, args.bundle, manifest)
    else:
        result = verify_bundle(args.bundle, manifest)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
