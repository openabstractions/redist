"""Inspect a packaging candidate or draft its exact verified artifacts.

--status is read-only. Promotion requires the successful candidate's exact
redist commit, version and run ID. It drafts the packages of
verified-release-N and the signed OpenAbstractions-Setup-X.Y.Z.exe of
setup-bundle-N from the same run attempt, with every file in one
SHA256SUMS. No compiler, installer or package builder is invoked.
Authentication uses the existing gh environment.
"""
import argparse
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

# Both the private source and public projection keep this dependency beside us.
# Load that exact file even when this module is loaded through oa's file loader.
_app_assets_spec = importlib.util.spec_from_file_location(
    'oa_promotion_app_assets', Path(__file__).resolve().with_name('app_assets.py'))
_app_assets = importlib.util.module_from_spec(_app_assets_spec)
_app_assets_spec.loader.exec_module(_app_assets)
MAX_RELEASE_ASSET_BYTES = _app_assets.MAX_RELEASE_ASSET_BYTES
measured, roster, validate_release = _app_assets.measured, _app_assets.roster, _app_assets.validate_release

REQUIRED_JOBS = {'candidate', 'windows-build', 'windows-native-build', 'windows-pe-sign',
                 'windows', 'windows-app-msi', 'windows-msi-sign', 'verify', 'linux',
                 'linux-verify', 'macos', 'draft', 'bundle', 'windows-bundle-sign',
                 'windows-bundle-verify'}
SETUP_ARTIFACT = 'setup-bundle-'
# GitHub reruns "all of the failed jobs and their dependent jobs" in a new
# attempt (https://docs.github.com/en/rest/actions/workflow-runs#re-run-failed-jobs-from-a-workflow-run).
# Every job except bundle is draft or upstream of it, so its failure reruns
# draft and bundle and the new attempt makes both promoted artifacts.
UNFINISHED = ('failure', 'cancelled', 'timed_out')
SETUP_RECEIPT = 'bundle-receipt.json'
SETUP_SUMS = 'SHA256SUMS.setup'
SETUP_CORE = ('OpenAbstractions', 'abstraction-x64.msi')


def release_facts_owner():
    """Use the existing public sibling or its owning private source."""
    import types
    target = Path(__file__).with_name('release_facts.py')
    if not target.is_file(): target = Path(__file__).resolve().parents[3] / 'release/facts.py'
    owner = types.ModuleType('oa_promoted_release_facts'); owner.__file__ = str(target)
    exec(compile(target.read_bytes(), str(target), 'exec'), owner.__dict__)
    return owner


def final_release_facts(metadata, directory, names, setup_receipt):
    """Project proofs already validated by unpack_verified/unpack_setup."""
    assets = []
    for name in names:
        size, checksum = measured(lambda name=name: (directory / name).open('rb'))
        assets.append({'name': name, 'artifact': {'sha256': checksum, 'bytes': size}})
    signatures = {'result': 'pass', 'files': list(setup_receipt.get('signatures', {}).values()) +
                  [row['signature'] for row in setup_receipt.get('chain', []) if 'signature' in row]}
    return release_facts_owner().producer_record(metadata, assets, unsigned_platforms=['linux'], setup_signatures=signatures)


def windows_signing_directory():
    windows = Path(__file__).resolve().parent.parent / 'windows'
    if not windows.is_dir():
        windows = Path(__file__).resolve().parents[3] / 'installer'
    return windows


def windows_policy_bytes():
    return (windows_signing_directory() / 'certum_simplysign.json').read_bytes()


def windows_signature_proof(receipt):
    """Use the same reviewed certificate policy as the independent Windows verifier."""
    windows = windows_signing_directory()
    policy_bytes = windows_policy_bytes()
    spec = importlib.util.spec_from_file_location('oa_promote_windows_signing', windows / 'windows_signing.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.verify_receipt(receipt, json.loads(policy_bytes), policy_sha256=hashlib.sha256(policy_bytes).hexdigest())
    return receipt


def command(args, *, timeout=120):
    result = subprocess.run(['gh', *args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise ValueError(result.stderr.decode('utf-8', errors='replace').strip())
    return result.stdout


def download(args, path):
    """Write a GitHub binary response without buffering it in Python memory."""
    with Path(path).open('wb') as target:
        result = subprocess.run(['gh', *args], stdout=target, stderr=subprocess.PIPE, timeout=1200)
    if result.returncode:
        raise ValueError(result.stderr.decode('utf-8', errors='replace').strip())


def same_files(first, second):
    with Path(first).open('rb') as left, Path(second).open('rb') as right:
        while True:
            a, b = left.read(1024 * 1024), right.read(1024 * 1024)
            if a != b:
                return False
            if not a:
                return True


class ReadAPIError(ValueError):
    """A read failed before any returned JSON could be validated."""
    def __init__(self, path, category, raw=b'', *, status=None, exit_code=None):
        endpoint = path.split('?', 1)[0]
        if not re.fullmatch(r'[A-Za-z0-9_./-]{1,180}', endpoint):
            endpoint = '<redacted>'
        self.status = status
        self.observation = dict(endpoint=endpoint, category=category, status=status,
                                exit_code=exit_code, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        super().__init__('GitHub READ acquisition failed: ' + json.dumps(self.observation, sort_keys=True))


def api(path):
    try:
        result = subprocess.run(['gh', 'api', path], capture_output=True, timeout=120)
    except subprocess.TimeoutExpired as exc:
        raise ReadAPIError(path, 'timeout', exc.stdout or b'') from None
    except OSError:
        raise ReadAPIError(path, 'start-failed') from None
    if result.returncode:
        status = re.search(rb'\(HTTP (\d{3})\)', result.stderr)
        raise ReadAPIError(path, 'nonzero', result.stdout,
                           status=int(status[1]) if status else None, exit_code=result.returncode)
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ReadAPIError(path, 'invalid-json', result.stdout) from None


def optional_api(path):
    try:
        return api(path)
    except ReadAPIError as exc:
        if exc.status == 404:
            return None
        raise


def release_by_tag(repo, version):
    """Find authenticated drafts too; the by-tag endpoint returns published releases."""
    release = optional_api(f'repos/{repo}/releases/tags/{version}')
    if release is not None:
        if release.get('tag_name') != version:
            raise ValueError('release tag lookup differs')
        return release
    matches = []
    # https://docs.github.com/en/rest/releases/releases#list-releases
    for page in range(1, 101):
        rows = api(f'repos/{repo}/releases?per_page=100&page={page}')
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError('release listing shape differs')
        matches.extend(row for row in rows if row.get('tag_name') == version)
        if len(matches) > 1:
            raise ValueError('release tag lookup is ambiguous')
        if len(rows) < 100:
            return matches[0] if matches else None
    raise ValueError('release listing exceeded 100 pages')


def pages(path, key, fetch=api):
    result = []
    for page in range(1, 101):
        data = fetch(f'{path}{"&" if "?" in path else "?"}per_page=100&page={page}')
        entries = data[key]
        result.extend(entries)
        if len(entries) < 100:
            return result
    raise ValueError('API pagination exceeded 100 pages')


def inspect(repo, run_id, fetch=api):
    root = f'repos/{repo}/actions/runs/{run_id}'
    run = fetch(root)
    # Failed-job retries retain earlier successful builders. Select the newest
    # attempt of EACH job, including a new failure/skip over an older success.
    jobs = pages(root + '/jobs?filter=all', 'jobs', fetch)
    newest = {}
    for job in jobs:
        newest[job['name']] = max(newest.get(job['name'], 0), job.get('run_attempt', 1))
    jobs = [j for j in jobs if j.get('run_attempt', 1) == newest[j['name']]]
    artifacts = pages(root + '/artifacts', 'artifacts', fetch)
    return run, jobs, artifacts


def candidate_run(repo, run_id, source, run, jobs):
    """The run is a successful manual candidate.yml run at the exact commit."""
    if (run.get('id') != run_id or run.get('head_sha') != source
            or run.get('head_repository', {}).get('full_name') != repo
            or run.get('repository', {}).get('full_name') != repo
            or run.get('path') != '.github/workflows/candidate.yml'
            or run.get('event') != 'workflow_dispatch'
            or run.get('status') != 'completed' or run.get('conclusion') != 'success'):
        raise ValueError('candidate must be a successful manual candidate.yml run in this repository at the exact dispatch commit')
    names = [job.get('name') for job in jobs]
    if not REQUIRED_JOBS.issubset(names) or len(names) != len(set(names)):
        raise ValueError('candidate is missing required jobs or has ambiguous job names')
    for job in jobs:
        if job.get('name') in ('windows-signing-probe', 'windows-signing-probe-build') and job.get('conclusion') == 'skipped':
            continue
        if (job.get('head_sha') != source or job.get('status') != 'completed'
                or job.get('conclusion') != 'success'):
            raise ValueError('candidate job did not pass: ' + str(job.get('name')))


def run_artifact(name, source, artifacts):
    """The one retained artifact of exactly this name, with a digest and the
    candidate's source as its provenance."""
    found = [a for a in artifacts if a.get('name') == name]
    if len(found) != 1 or found[0].get('expired') is not False:
        raise ValueError(name + ' is missing, ambiguous or expired; rebuild and qualify a new candidate')
    artifact = found[0]
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', '')):
        raise ValueError('GitHub artifact has no SHA-256 digest: ' + name)
    if artifact.get('workflow_run', {}).get('head_sha') != source:
        raise ValueError('artifact provenance differs from candidate source: ' + name)
    return artifact


def verified_artifact(repo, run_id, source, run, jobs, artifacts):
    candidate_run(repo, run_id, source, run, jobs)
    return run_artifact(f'verified-release-{run["run_attempt"]}', source, artifacts)


def setup_artifact(repo, run_id, source, run, jobs, artifacts):
    """The signed Setup bundle of the same run and attempt, by exact name,
    under the same run and job checks as the verified release."""
    candidate_run(repo, run_id, source, run, jobs)
    return run_artifact(f'{SETUP_ARTIFACT}{run["run_attempt"]}', source, artifacts)


def setup_name(version):
    return f'OpenAbstractions-Setup-{version[1:]}.exe'


def msi_name(version, arch):
    """Name the public core MSI from the release version, preserving old Jobs."""
    match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', version)
    if not match or arch not in ('x64', 'arm64'):
        raise ValueError('core MSI needs an exact release version and architecture')
    if tuple(map(int, match.groups())) <= (0, 4, 0):
        return f'abstraction-{arch}.msi'
    return f'abstraction-{version[1:]}-{arch}.msi'


def public_asset_names(directory, assets, version):
    """Materialize future public filenames after validating signed intermediates.

    Burn and signature receipts retain their verified internal names and hashes.
    Both candidate acceptance and publication consume this exact public mapping.
    Historical release layouts through 0.4.0 remain byte-for-byte readable.
    """
    names = {f'abstraction-{arch}.msi': msi_name(version, arch) for arch in ('x64', 'arm64')}
    if all(old == new for old, new in names.items()):
        return assets
    already_named = set(names.values()) <= set(assets) and not names.keys() & set(assets)
    if len(assets) != len(set(assets)) or (not names.keys() <= set(assets) and not already_named):
        raise ValueError('public core MSI inventory is incomplete or ambiguous')
    directory = Path(directory)
    checksums = {}
    for line in (directory / 'SHA256SUMS').read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *](\S+)', line)
        if not match or match[2] in checksums:
            raise ValueError('malformed or duplicate public package checksum')
        checksums[match[2]] = match[1]
    if set(checksums) != set(assets) - {'SHA256SUMS'}:
        raise ValueError('public checksum inventory differs from verified assets')
    if already_named:
        if any(not (directory / new).is_file() or (directory / old).exists() for old, new in names.items()):
            raise ValueError('resumed public MSI inventory differs from verified assets')
        notes = (directory / 'NOTES.md').read_text(encoding='utf-8')
        if any(old in notes for old in names):
            raise ValueError('resumed public notes retain intermediate MSI names')
        return sorted(assets)
    for old, new in names.items():
        if not (directory / old).is_file() or (directory / new).exists():
            raise ValueError('public MSI source is missing or destination already exists: ' + new)
    notes = (directory / 'NOTES.md').read_text(encoding='utf-8')
    for old, new in names.items():
        (directory / old).rename(directory / new)
        notes = notes.replace(old, new)
    (directory / 'SHA256SUMS').write_text(''.join(
        checksum + '  ' + names.get(name, name) + '\n' for name, checksum in checksums.items()),
        encoding='utf-8', newline='')
    (directory / 'NOTES.md').write_text(notes, encoding='utf-8', newline='')
    return sorted(names.get(name, name) for name in assets)


def unpack_setup(blob, digest, destination, version, packages, *, receipt_sink=None):
    """Check the Setup artifact and write the files it publishes.

    packages maps each verified-release package to its SHA-256; the bundle's
    core MSI must be that release's abstraction-x64.msi. Returns the published
    names, with the bundle first, and their SHA-256 values."""
    outer = ((len(blob), hashlib.sha256(blob).hexdigest()) if isinstance(blob, bytes)
             else measured(lambda: Path(blob).open('rb')))
    if 'sha256:' + outer[1] != digest:
        raise ValueError('downloaded Setup artifact digest differs from GitHub')
    with zipfile.ZipFile(io.BytesIO(blob) if isinstance(blob, bytes) else blob) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]
        if len(names) != len(set(names)):
            raise ValueError('duplicate Setup artifact entries')
        for item in entries:
            if (item.is_dir() or '/' in item.filename or '\\' in item.filename
                    or item.filename in ('.', '..')
                    or (item.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError('Setup artifact entries must be ordinary root-level files')
        for name in (SETUP_RECEIPT, SETUP_SUMS):
            if name not in names or archive.getinfo(name).file_size > 1024 * 1024:
                raise ValueError('Setup artifact metadata is missing or too large: ' + name)
        receipt = json.loads(archive.read(SETUP_RECEIPT))
        exe = setup_name(version)
        bundle = receipt.get('bundle') if isinstance(receipt, dict) else None
        if not isinstance(bundle, dict) or bundle.get('name') != exe:
            raise ValueError('Setup receipt names no ' + exe)
        if bundle.get('signed') is not True:
            raise ValueError('Setup receipt must prove the required signed bundle')
        signatures = receipt.get('signatures', {})
        windows_signature_proof({'schema': 1, 'result': 'pass', 'policy_sha256': receipt.get('policy_sha256'),
                                 'files': [signatures.get('engine', {}), signatures.get('bundle', {})]})
        if signatures['bundle'].get('sha256') != bundle.get('sha256') or signatures['bundle'].get('bytes') != bundle.get('bytes'):
            raise ValueError('Setup signature proof differs from its final bytes')
        chain = receipt.get('chain')
        if not isinstance(chain, list) or not chain or not all(isinstance(entry, dict) for entry in chain):
            raise ValueError('Setup receipt has no package chain')
        core = chain[0]
        windows_signature_proof({'schema': 1, 'result': 'pass', 'policy_sha256': receipt.get('policy_sha256'),
                                 'files': [entry.get('signature', {}) for entry in chain]})
        if any(entry['signature'].get('sha256') != entry.get('sha256')
               or entry['signature'].get('bytes') != entry.get('bytes') for entry in chain):
            raise ValueError('Setup chain signature proof differs from signed MSI pins')
        if (core.get('id'), core.get('name')) != SETUP_CORE or core.get('sha256') != packages.get(SETUP_CORE[1]):
            raise ValueError('the Setup bundle does not carry this release\'s abstraction-x64.msi')
        published = {exe: (bundle.get('sha256'), bundle.get('bytes'))}
        for entry in chain[1:]:
            name = entry.get('name')
            if (not isinstance(name, str)
                    or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}-' + re.escape(version[1:]) + r'\.msi', name)
                    or name in published or name in packages):
                raise ValueError('Setup receipt names an unexpected application package')
            published[name] = (entry.get('sha256'), entry.get('bytes'))
        if set(names) != set(published) | {SETUP_RECEIPT, SETUP_SUMS}:
            raise ValueError('Setup artifact file set differs from its receipt')
        checksums = {}
        for line in archive.read(SETUP_SUMS).decode('utf-8').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64}) [ *](\S+)', line)
            if not match or match[2] in checksums:
                raise ValueError('malformed or duplicate Setup checksum')
            checksums[match[2]] = match[1]
        if set(checksums) != set(published) | {SETUP_RECEIPT}:
            raise ValueError('Setup checksum file does not cover exactly the bundle, its packages and receipt')
        for name in checksums:
            size, checksum = measured(lambda: archive.open(name))
            if checksum != checksums[name]:
                raise ValueError('Setup checksum mismatch: ' + name)
            if name in published and published[name] != (checksum, size):
                raise ValueError('Setup receipt differs from the file: ' + name)
            if size >= MAX_RELEASE_ASSET_BYTES:
                raise ValueError('release asset must be under 2 GiB: ' + name)
        for name in published:
            with archive.open(name) as source, (destination / name).open('wb') as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
    if receipt_sink is not None:
        receipt_sink.update(receipt)
    return list(published), {name: checksums[name] for name in published}


def unpack_verified(blob, digest, destination, run, version):
    outer = ((len(blob), hashlib.sha256(blob).hexdigest()) if isinstance(blob, bytes)
             else measured(lambda: Path(blob).open('rb')))
    if 'sha256:' + outer[1] != digest:
        raise ValueError('downloaded artifact digest differs from GitHub')
    with zipfile.ZipFile(io.BytesIO(blob) if isinstance(blob, bytes) else blob) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]
        if len(names) != len(set(names)):
            raise ValueError('duplicate artifact entries')
        for item in entries:
            if (item.is_dir() or '/' in item.filename or '\\' in item.filename
                    or item.filename in ('.', '..')
                    or (item.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError('artifact entries must be ordinary root-level files')
        for name in ('candidate.json', 'NOTES.md', 'SHA256SUMS'):
            if archive.getinfo(name).file_size > 1024 * 1024:
                raise ValueError('verified release metadata is too large: ' + name)
        metadata = json.loads(archive.read('candidate.json'))
        expected = {'schema': 1, 'source': run['head_sha'], 'version': version,
                    'run_id': run['id'], 'run_attempt': run['run_attempt']}
        if any(metadata.get(k) != value for k, value in expected.items()):
            raise ValueError('artifact metadata differs from requested candidate')
        if metadata.get('kind') != 'release-candidate':
            raise ValueError('signing probes cannot substitute for final release candidates')
        windows_proof = windows_signature_proof(metadata.get('windows_signing', {}))
        signed_core = {entry.get('name'): entry for entry in windows_proof['files']}
        for name in ('abstraction-x64.msi', 'abstraction-arm64.msi'):
            entry = signed_core.get('core/' + name, {})
            if (entry.get('sha256'), entry.get('bytes')) != (hashlib.sha256(archive.read(name)).hexdigest(), archive.getinfo(name).file_size):
                raise ValueError('Windows MSI bytes differ from required signature proof')
        if not isinstance(metadata.get('preview'), bool) or metadata.get('macos') not in ('signed', 'unsigned', 'partial'):
            raise ValueError('candidate is missing explicit preview/signing state')
        number = version[1:]
        packages = {'abstraction-x64.msi', 'abstraction-arm64.msi',
                    f'abstraction-{number}-linux-amd64.tar.gz', f'abstraction-{number}-linux-arm64.tar.gz'}
        if metadata['macos'] == 'signed':
            packages.add(f'abstraction-{number}-macos-universal.pkg')
        app_pins = Path(__file__).resolve().parent.parent / 'apps.json'
        if not app_pins.exists():  # private monorepo tests use the authored file before splitting
            app_pins = Path(__file__).resolve().parents[3] / 'monitor/internal/setup/adopter_assets.json'
        app_rows = roster(app_pins, admission=metadata.get('release_admission'))
        if tuple(map(int, number.split('-')[0].split('.'))) >= (0, 8, 0):
            from release_facts import validate_public_admission
            if metadata.get('release_admission') != app_rows.admission:
                raise ValueError('candidate declaration differs from the exact source producer capsule')
            if metadata.get('app_roster_sha256') != hashlib.sha256(app_pins.read_bytes()).hexdigest():
                raise ValueError('candidate source roster bytes differ from prepared producer source')
            # Candidate unpack is also used before installed rehearsal. This
            # validates the declaration; completed delivery remains external.
            validate_public_admission(app_rows.admission, number, app_rows, run['head_sha'])
        if any(row['release_tag'] != version for row in app_rows):
            raise ValueError('optional app pin release tag differs from candidate')
        app_packages = validate_release(app_rows, metadata.get('apps', []), archive.open)
        packages.update(app_packages)
        if set(names) != packages | {'candidate.json', 'NOTES.md', 'SHA256SUMS'}:
            raise ValueError('artifact file set differs from declared packages')
        for name in packages | {'SHA256SUMS'}:
            if archive.getinfo(name).file_size >= MAX_RELEASE_ASSET_BYTES:
                raise ValueError('release asset must be under 2 GiB: ' + name)
        checksums = {}
        for line in archive.read('SHA256SUMS').decode('utf-8').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64}) [ *](\S+)', line)
            if not match or match[2] in checksums:
                raise ValueError('malformed or duplicate package checksum')
            checksums[match[2]] = match[1]
        if set(checksums) != packages:
            raise ValueError('checksum file does not cover exactly the packages')
        for name, checksum in checksums.items():
            if measured(lambda: archive.open(name))[1] != checksum:
                raise ValueError('package checksum mismatch: ' + name)
        fact_assets = [{'name': name, 'artifact': {'sha256': checksum, 'bytes': archive.getinfo(name).file_size}}
                       for name, checksum in checksums.items()]
        required_facts = tuple(map(int, number.split('-')[0].split('.'))) >= (0, 8, 0)
        if required_facts and 'release_facts' not in metadata:
            raise ValueError('candidate release facts differ from measured producer inputs')
        if 'release_facts' in metadata:
            expected_facts = release_facts_owner().producer_record(metadata, fact_assets, unsigned_platforms=['linux'])
            if metadata['release_facts'] != expected_facts:
                raise ValueError('candidate release facts differ from measured producer inputs')
        if not archive.read('NOTES.md').strip():
            raise ValueError('release notes are empty')
        for name in names:
            with archive.open(name) as source, (destination / name).open('wb') as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
    return sorted(packages) + ['SHA256SUMS'], metadata


def status(repo, run_id, run, jobs, artifacts):
    print(f"{repo} | run {run_id} | attempt {run.get('run_attempt')}")
    print(f"Source: {run.get('head_sha')}  Branch: {run.get('head_branch')}")
    print(f"Workflow: {run.get('path')}  State: {run.get('status')} / {run.get('conclusion') or 'pending'}")
    print(run.get('html_url', ''))
    for job in jobs:
        state = job.get('conclusion') or job.get('status')
        print(f"  {state:16} {job['name']}")
        for step in job.get('steps', []):
            if step.get('conclusion') in ('failure', 'cancelled', 'timed_out'):
                print('    ' + step['name'])
    for artifact in artifacts:
        print(f"  artifact {artifact['name']} | {'EXPIRED' if artifact.get('expired') else 'retained'}")
    if run.get('status') != 'completed':
        print('Next: wait for this run; no new candidate is needed.')
    elif run.get('path') == '.github/workflows/release.yml':
        if run.get('conclusion') == 'success':
            print('Promotion/release workflow completed. Inspect the draft or published release; no rebuild is needed.')
        else:
            print('Next: inspect promotion logs and any partial tag/draft. For the new artifact-only workflow,')
            print('dispatch release.yml at the same commit with the same candidate_run/version and resume=true')
            print('after the tag exists. Existing assets are checked; only missing assets are uploaded.')
    elif run.get('conclusion') != 'success':
        conclusion = {job.get('name'): job.get('conclusion') for job in jobs}
        if conclusion.get('bundle') in UNFINISHED and conclusion.get('draft') == 'success':
            # Bundle has no dependent job, so a failed-jobs rerun runs it alone
            # in a new attempt: it looks for verified-release-<new attempt>,
            # which no draft made, and promotion takes both artifacts of the
            # current attempt.
            print('Next: inspect failed logs; bundle did not finish after draft succeeded, so a transient')
            print('failure with unchanged inputs needs a new draft as well; rerun all jobs once:')
            print(f'  gh run rerun {run_id} -R {repo}')
        else:
            print('Next: inspect failed logs; for a transient failure with unchanged inputs, retry failed jobs once:')
            print(f'  gh run rerun {run_id} --failed -R {repo}')
        print('A source/workflow fix needs a new candidate; preserve this failed run.')
    else:
        try:
            verified_artifact(repo, run_id, run['head_sha'], run, jobs, artifacts)
            setup_artifact(repo, run_id, run['head_sha'], run, jobs, artifacts)
        except ValueError as exc:
            print('Promotion unavailable: ' + str(exc))
        else:
            print('Next: dispatch release.yml from this same branch commit with candidate_run=' + str(run_id)
                  + ' and the candidate version. Promotion downloads these artifacts without rebuilding.')


# Source fragment for research/org-edits/redist/promote.py, before main().
def pytorch_inputs_module():
    import importlib.util
    root = Path(__file__).resolve().parent.parent
    path = root / "windows/pytorch_engine.py"
    if not path.is_file():
        path = Path(__file__).resolve().parents[3] / "installer/pytorch_engine.py"
    spec = importlib.util.spec_from_file_location("oa_pytorch_input_owner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def owned_input_draft(repository, tag, source, identity, title, *, fetch=api, mutate=command, allow_create=True):
    """Find/create one exact owned staging draft; creates no Git ref or asset."""
    prefix = f"repos/{repository}"
    body = json.dumps(identity, sort_keys=True) + "\n"
    found = []
    for page in range(1, 101):
        batch = fetch(prefix + f"/releases?per_page=100&page={page}")
        if not isinstance(batch, list):
            raise ValueError("malformed input draft lookup")
        found.extend(item for item in batch if item.get("tag_name") == tag)
        if len(batch) < 100:
            break
    else:
        raise ValueError("input draft lookup exceeds bounded pagination")
    if len(found) > 1:
        raise ValueError("input draft identity is ambiguous")
    if found:
        release = found[0]
    else:
        if not allow_create:
            raise ValueError("PyTorch input tag exists without its owned draft")
        payload = {"tag_name": tag, "target_commitish": source, "name": title,
                   "draft": True, "prerelease": True, "make_latest": "false", "body": body}
        with tempfile.TemporaryDirectory(prefix="oa-input-seed-") as temporary:
            request = Path(temporary) / "request.json"
            request.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            release = json.loads(mutate(["api", "--method", "POST", prefix + "/releases", "--input", str(request)]))
    if (not isinstance(release, dict) or type(release.get("id")) is not int or release["id"] < 1
            or release.get("draft") is not True
            or release.get("tag_name") != tag or release.get("target_commitish") != source
            or release.get("body", "").replace("\r\n", "\n") != body):
        raise ValueError("input origin differs from its owned staging draft")
    return release


def seed_pytorch_inputs(directory, sources, source, version, *, fetch=api,
                        optional_fetch=optional_api, mutate=command, engine=None):
    """Create or resume one owned draft containing only the retained native input pair."""
    engine = engine or pytorch_inputs_module()
    owner = engine.input_source(sources)
    tag, identity = engine.input_seed(source, version, owner)
    directory = Path(directory)
    for name, pin in engine.INPUT_PINS.items():
        path = directory / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size != pin["size_bytes"]:
            raise ValueError("retained PyTorch input size/name differs: " + name)
    # The small owner manifest is checked locally. The upload service computes
    # the large ZIP's digest; CI verifies every member after authenticated intake.
    if engine.measured(directory / engine.MANIFEST_NAME) != (
            engine.INPUT_PINS[engine.MANIFEST_NAME]["size_bytes"],
            engine.INPUT_PINS[engine.MANIFEST_NAME]["sha256"]):
        raise ValueError("retained PyTorch owner manifest differs")
    prefix = f"repos/{engine.INPUT_REPOSITORY}"
    tag_state = optional_fetch(prefix + "/git/ref/tags/" + tag)
    engine.input_tag(tag_state, source, required=False)
    release = owned_input_draft(engine.INPUT_REPOSITORY, tag, source, identity,
                               "Reviewed PyTorch input transport " + source[:12], fetch=fetch, mutate=mutate,
                               allow_create=tag_state is None)
    assets = engine.input_assets(release, source, version, owner, complete=False)
    # The owned draft is created first so an interrupted direct-ref creation can
    # be retried against its exact identity, with no tag or asset replacement.
    tag_state = optional_fetch(prefix + "/git/ref/tags/" + tag)
    engine.input_tag(tag_state, source, required=False)
    if tag_state is None:
        mutate(["api", "--method", "POST", prefix + "/git/refs",
                "-f", "ref=refs/tags/" + tag, "-f", "sha=" + source])
    engine.input_tag(optional_fetch(prefix + "/git/ref/tags/" + tag), source)
    missing = [name for name in engine.INPUT_PINS if name not in assets]
    if missing:
        # No --clobber: a concurrent same-name upload refuses instead of replacing bytes.
        mutate(["release", "upload", tag, "--repo", engine.INPUT_REPOSITORY,
                *[str(directory / name) for name in missing]], timeout=1200)
    release_id = release["id"]
    release = fetch(prefix + "/releases/" + str(release_id))
    if release.get("id") != release_id:
        raise ValueError("PyTorch input draft ID changed after upload")
    assets = engine.input_assets(release, source, version, owner, complete=True)
    engine.input_tag(optional_fetch(prefix + "/git/ref/tags/" + tag), source)
    return {"schema": 1, "mode": "draft-input-seed", "repository": engine.INPUT_REPOSITORY,
            "candidate_source": source, "candidate_version": version,
            "input_owner_repository": engine.INPUT_OWNER, "input_owner_commit": owner,
            "release_id": release["id"], "tag": tag, "assets": assets}


def seed_pytorch_main(argv):
    parser = argparse.ArgumentParser(description="Seed or resume one exact PyTorch input draft; owner authorization precedes this external mutation.")
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True, help="the exact prepared redist windows/sources.tsv")
    parser.add_argument("--source", required=True, help="exact reviewed public redist commit")
    parser.add_argument("--version", required=True, help="candidate MAJOR.MINOR.PATCH")
    parser.add_argument("--output", type=Path, required=True, help="retain the actual release/asset IDs; never a CI receipt")
    args = parser.parse_args(argv)
    checkout = args.sources.resolve().parent.parent
    head = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain=v1", "--untracked-files=all"], text=True).strip()
    if (args.sources.resolve() != checkout / "windows/sources.tsv"
            or Path(__file__).resolve() != checkout / "scripts/promote.py"
            or head != args.source or dirty):
        parser.error("input seeding requires the clean exact prepared public redist checkout")
    # Reject a foreign output before external mutation. Identical retry receipts are retained.
    old = None
    if args.output.exists():
        old = json.loads(args.output.read_text(encoding="utf-8"))
        if (not isinstance(old, dict) or old.get("mode") != "draft-input-seed"
                or old.get("candidate_source") != args.source or old.get("candidate_version") != args.version):
            parser.error("seed receipt output belongs to another input operation")
    receipt = seed_pytorch_inputs(args.inputs, args.sources, args.source, args.version)
    if old is not None and old != receipt:
        raise ValueError("existing seed receipt identity changed; preserve it and inspect the draft")
    if old is None:
        with args.output.open("x", encoding="utf-8") as target:
            target.write(json.dumps(receipt, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0


def main(argv=None):
    internal = list(sys.argv[1:] if argv is None else argv)
    if internal[:1] == ['--msi-name']:
        names = argparse.ArgumentParser(description='Print a public core MSI name without reading or changing release state.')
        names.add_argument('--msi-name', required=True, metavar='vMAJOR.MINOR.PATCH')
        names.add_argument('--arch', required=True, choices=('x64', 'arm64'))
        selected = names.parse_args(internal)
        print(msi_name(selected.msi_name, selected.arch))
        return 0
    if internal[:1] == ["seed-pytorch-inputs"]:
        return seed_pytorch_main(internal[1:])
    parser = argparse.ArgumentParser(description=__doc__, epilog="For exact draft input transport: seed-pytorch-inputs --help.")
    parser.add_argument('--repo', default=os.environ.get('GH_REPO', 'openabstractions/redist'))
    parser.add_argument('--run', type=int, required=True, help='exact candidate workflow run ID')
    parser.add_argument('--status', action='store_true', help='read-only run, job, retained artifact and next-action summary')
    parser.add_argument('--version', help='vMAJOR.MINOR.PATCH of the verified packages')
    parser.add_argument('--source', help='exact redist commit running the promotion workflow')
    parser.add_argument('--resume', action='store_true', help='recover a partial promotion at the same tag/commit; verify existing draft assets and upload only missing files')
    parser.add_argument('--expected-attempt', type=int, help='bind local accepted artifacts to this candidate attempt')
    parser.add_argument('--verified-artifact-id', type=int)
    parser.add_argument('--verified-artifact-digest')
    parser.add_argument('--setup-artifact-id', type=int)
    parser.add_argument('--setup-artifact-digest')
    args = parser.parse_args(argv)
    accepted = (args.expected_attempt, args.verified_artifact_id, args.verified_artifact_digest,
                args.setup_artifact_id, args.setup_artifact_digest)
    if any(value is not None for value in accepted) and (any(value is None for value in accepted)
            or min(args.expected_attempt, args.verified_artifact_id, args.setup_artifact_id) < 1
            or any(not re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in
                   (args.verified_artifact_digest, args.setup_artifact_digest))):
        parser.error('accepted candidate requires exact attempt, artifact IDs and SHA256 digests together')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo) or args.run < 1:
        parser.error('expected owner/repository and a positive run ID')
    if not args.status and (not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', args.version or '')
                            or not re.fullmatch(r'[0-9a-f]{40}', args.source or '')):
        parser.error('promotion needs --version vMAJOR.MINOR.PATCH and --source full lowercase SHA')
    if not args.status and tuple(map(int, args.version[1:].split('.'))) >= (0, 8, 0):
        raise ValueError('final promotion pending authenticated external installed-admission producer intake; build declaration is pending qualification')
    run, jobs, artifacts = inspect(args.repo, args.run)
    if args.status:
        status(args.repo, args.run, run, jobs, artifacts)
        return 0
    artifact = verified_artifact(args.repo, args.run, args.source, run, jobs, artifacts)
    setup = setup_artifact(args.repo, args.run, args.source, run, jobs, artifacts)
    if accepted[0] is not None and accepted != (run.get('run_attempt'), artifact['id'], artifact['digest'], setup['id'], setup['digest']):
        raise ValueError('candidate artifacts differ from the exact installed acceptance identities')
    with tempfile.TemporaryDirectory(prefix='oa-promotion-') as tmp:
        directory = Path(tmp)
        retained = directory / 'candidate-artifact.zip'
        download(['api', f'repos/{args.repo}/actions/artifacts/{artifact["id"]}/zip'], retained)
        assets, metadata = unpack_verified(retained, artifact['digest'], directory, run, args.version)
        sums = directory / 'SHA256SUMS'
        lines = sums.read_bytes().decode('utf-8').splitlines()
        packages = {line[66:]: line[:64] for line in lines}
        retained_setup = directory / 'setup-artifact.zip'
        download(['api', f'repos/{args.repo}/actions/artifacts/{setup["id"]}/zip'], retained_setup)
        setup_receipt = {}
        setup_assets, setup_sums = unpack_setup(retained_setup, setup['digest'], directory, args.version, packages, receipt_sink=setup_receipt)
        notes = directory / 'NOTES.md'
        if 'release_facts' not in metadata and '`' + setup_name(args.version) + '`' not in notes.read_text(encoding='utf-8'):
            raise ValueError('release notes do not name the signed ' + setup_name(args.version))
        # The published checksum file is the verified release's, then one
        # line per Setup file in the sha256sum format it already uses.
        lines += [setup_sums[name] + '  ' + name for name in setup_assets]
        sums.write_bytes(''.join(line + '\n' for line in lines).encode('utf-8'))
        assets = sorted(set(assets) | set(setup_assets))
        assets = public_asset_names(directory, assets, args.version)
        if 'release_facts' in metadata:
            record = final_release_facts(metadata, directory, assets, setup_receipt)
            notes.write_text(release_facts_owner().render_notes(notes.read_text(encoding='utf-8'), record), encoding='utf-8')
            if '`' + setup_name(args.version) + '`' not in notes.read_text(encoding='utf-8'):
                raise ValueError('candidate facts omit the exact measured Setup bundle')
        body = notes.read_text(encoding='utf-8') + f'\n\nVerified candidate: https://github.com/{args.repo}/actions/runs/{args.run}\n'
        notes.write_text(body, encoding='utf-8')
        # Create-only refs preserve existing tags. A failed lookup cannot authorize
        # mutation; the API refuses concurrent or existing tags atomically.
        release = None
        if args.resume:
            tag = api(f'repos/{args.repo}/git/ref/tags/{args.version}')
            if tag.get('object', {}).get('type') != 'commit' or tag['object'].get('sha') != args.source:
                raise ValueError('resume requires the existing tag to point directly to the verified commit')
            release = release_by_tag(args.repo, args.version)
        else:
            command(['api', '--method', 'POST', f'repos/{args.repo}/git/refs',
                     '-f', 'ref=refs/tags/' + args.version, '-f', 'sha=' + args.source])
        if release:
            if (release.get('draft') is not True or release.get('tag_name') != args.version
                    or release.get('body', '').replace('\r\n', '\n') != body):
                raise ValueError('resume requires this candidate\'s unmodified draft release')
            existing = release.get('assets', [])
            names = [item['name'] for item in existing]
            if len(names) != len(set(names)) or not set(names).issubset(assets):
                raise ValueError('existing draft has unexpected or duplicate assets')
            for item in existing:
                existing_path = directory / ('existing-' + str(item['id']))
                download(['api', '-H', 'Accept: application/octet-stream',
                          f'repos/{args.repo}/releases/assets/{item["id"]}'], existing_path)
                if not same_files(existing_path, directory / item['name']):
                    raise ValueError('existing draft asset differs: ' + item['name'])
            assets = [name for name in assets if name not in names]
        else:
            command(['release', 'create', args.version, '--repo', args.repo, '--verify-tag',
                     '--target', args.source, '--draft', '--title', args.version,
                     '--notes-file', str(notes)])
        if assets:
            command(['release', 'upload', args.version, '--repo', args.repo,
                     *[str(directory / name) for name in assets]])
    print(f'Drafted {args.version} from verified run {args.run}; packages were not rebuilt.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, subprocess.TimeoutExpired) as exc:
        print('REFUSED: ' + str(exc), file=sys.stderr)
        sys.exit(1)
