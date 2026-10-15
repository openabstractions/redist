"""Exact public source and bounded download inputs for optional app producers.

This tool only prepares inputs. It cannot authorize a release or turn a local
qualification receipt into a hosted producer receipt.
"""

import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request

from app_assets import (optional_app_sources, roster, select_windows_addon_artifact,
                        select_windows_wheel_artifact)


COMMIT = re.compile(r'[0-9a-f]{40}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
CHARTER = 'openabstractions/abstractions'


def exact_rows(path, header):
    lines = [line for line in Path(path).read_text(encoding='utf-8').splitlines()
             if line and not line.startswith('>')]
    parsed = list(csv.reader(lines, delimiter='\t'))
    if not parsed or tuple(parsed[0]) != header:
        raise ValueError('invalid public source roster: ' + str(path))
    rows = [dict(zip(header, fields)) for fields in parsed[1:]]
    if any(len(fields) != len(header) for fields in parsed[1:]):
        raise ValueError('malformed public source roster: ' + str(path))
    return rows


def source_pins(app, npm_pins, pypi_pins, app_pins, app_roster, *, producer_only=False,
                adopter_commit=None):
    enabled = {row['id'] for row in roster(app_roster)}
    if producer_only and enabled:
        raise ValueError('producer-only requires an empty Setup catalog')
    if app not in enabled and not producer_only:
        raise ValueError('optional app is not enabled by apps.json: ' + app)
    if app != 'comfyui':
        raise ValueError('unknown optional app producer')
    npm = exact_rows(npm_pins, ('package', 'repository', 'commit', 'directory'))
    charter = [row for row in npm if row['repository'] == CHARTER]
    if len(charter) != 1 or charter[0]['package'] != '@openabstractions/opencode':
        raise ValueError('npm.tsv must name one exact public charter source')
    selected = exact_rows(pypi_pins, ('package', 'repository', 'commit', 'directory'))
    if producer_only:
        if not isinstance(adopter_commit, str) or not COMMIT.fullmatch(adopter_commit):
            raise ValueError('producer-only requires the reviewed exact ComfyUI adopter commit')
        extra = {'repository': 'openabstractions/adopter-comfyui', 'commit': adopter_commit}
    else:
        if adopter_commit is not None:
            raise ValueError('enabled app must use the authored app source roster')
        extra = optional_app_sources(app_pins, roster(app_roster))['comfyui']
    selected = [*selected, {'repository': extra['repository'], 'commit': extra['commit']}]
    selected.append(charter[0])
    by_repo = {}
    for row in selected:
        repo, commit = row['repository'], row['commit']
        if not re.fullmatch(r'[A-Za-z0-9._-]+/[A-Za-z0-9._-]+', repo) or not COMMIT.fullmatch(commit):
            raise ValueError('invalid exact public source pin: ' + repo)
        if repo in by_repo and by_repo[repo] != commit:
            raise ValueError('conflicting source pins: ' + repo)
        by_repo[repo] = commit
    if by_repo.get(CHARTER) != charter[0]['commit']:
        raise ValueError('charter public source pin differs')
    return by_repo


# Exact split.manifest destinations. The HTML outputs belong to the website,
# not the charter: they are declared evidence, never charter diff exceptions.
CATALOG_PATH = 'monitor/internal/setup/adopter_assets.json'
J_RECORD_PATH = 'docs/results/focused/shared-javascript-capabilities-windows.json'
MATRIX_PATH = 'docs/results/MATRIX.txt'
CHARTER_DERIVED_PATHS = frozenset((CATALOG_PATH, J_RECORD_PATH, MATRIX_PATH))


def pinned_input_receipt(pins, source_root, input_root):
    """Keep actual producer inputs outside its immutable shipped source pair."""
    for repo, commit in pins.items():
        root = Path(source_root) / repo.split('/', 1)[1]
        head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
        dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain=v1',
                                         '--untracked-files=all'], text=True).strip()
        if head != commit or dirty:
            raise ValueError('producer source checkout differs: ' + repo)
    files = {}
    for path in sorted(Path(input_root).rglob('*')):
        relative = path.relative_to(input_root)
        if relative.parts[0] in ('upstream', 'build'):
            continue  # exact upstream pins/build recipe live in the unchanged source
        if path.is_symlink():
            raise ValueError('symlinked app producer input')
        if path.is_file():
            files[relative.as_posix()] = {'bytes': path.stat().st_size, 'sha256': sha_file(path)}
    if not files:
        raise ValueError('producer input receipt has no measured build inputs')
    return {'schema': 1, 'sources': dict(pins), 'build_inputs': files}


def compare_consumer_sources(producer, current, source_root, derivation):
    """Refuse functional drift; permit only reviewed catalog/derived exports."""
    if (not isinstance(producer, dict) or set(producer) != {'schema', 'sources', 'build_inputs'}
            or producer['schema'] != 1 or not isinstance(producer['sources'], dict)
            or not isinstance(producer['build_inputs'], dict) or not producer['build_inputs']):
        raise ValueError('invalid pinned producer input receipt')
    old = producer['sources']
    if set(old) != set(current) or CHARTER not in old:
        raise ValueError('producer source roster differs from consumer')
    for repo, commit in old.items():
        if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
            raise ValueError('producer input has an invalid source commit')
        if repo != CHARTER and commit != current[repo]:
            raise ValueError('functional producer source changed: ' + repo)
    for name, item in producer['build_inputs'].items():
        if (not isinstance(name, str) or name.startswith('/') or '\\' in name
                or any(part in ('', '.', '..') for part in name.split('/'))
                or not isinstance(item, dict) or set(item) != {'bytes', 'sha256'}
                or type(item['bytes']) is not int or item['bytes'] < 0
                or not isinstance(item['sha256'], str) or not SHA.fullmatch(item['sha256'])):
            raise ValueError('invalid immutable producer build input')
    charter = Path(source_root) / 'abstractions'
    head = subprocess.check_output(['git', '-C', str(charter), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(charter), 'status', '--porcelain=v1',
                                     '--untracked-files=all'], text=True).strip()
    if head != current[CHARTER] or dirty:
        raise ValueError('consumer charter source differs')
    # This exact immutable dependency may not be in the current shallow clone.
    if subprocess.run(['git', '-C', str(charter), 'cat-file', '-e', old[CHARTER] + '^{commit}'],
                      capture_output=True).returncode:
        subprocess.run(['git', '-C', str(charter), 'fetch', '--quiet', '--depth=1',
                        'origin', old[CHARTER]], check=True)
    changed = set(subprocess.check_output(['git', '-C', str(charter), 'diff', '--name-only',
                                           old[CHARTER], head, '--'], text=True).splitlines())
    if not changed <= CHARTER_DERIVED_PATHS:
        raise ValueError('functional charter producer input changed: ' + ', '.join(sorted(changed - CHARTER_DERIVED_PATHS)))
    if changed:
        expected = {CATALOG_PATH, J_RECORD_PATH, MATRIX_PATH, 'coverage.html', 'languages.html',
                    'record_input_digest', 'record_digest', 'generator_receipt_sha256'}
        if (not isinstance(derivation, dict) or set(derivation) != expected
                or any(not isinstance(value, str) or not SHA.fullmatch(value) for value in derivation.values())):
            raise ValueError('catalog change lacks exact current recorder/generator evidence')
        for path in (CATALOG_PATH, J_RECORD_PATH, MATRIX_PATH):
            if sha_file(charter / path) != derivation[path]:
                raise ValueError('current derived output differs: ' + path)
        record = json.loads((charter / J_RECORD_PATH).read_text(encoding='utf-8'))
        checksum = record.pop('record_digest', None)
        canonical = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        if (checksum != hashlib.sha256(canonical).hexdigest() or checksum != derivation['record_digest']
                or record.get('inputs_digest') != derivation['record_input_digest']
                or record.get('schema') != 2 or record.get('result', {}).get('exit') != 0
                or record.get('definition', {}).get('id') != 'shared-javascript-capabilities-windows'):
            raise ValueError('current J recorder evidence differs')
    return {'producer_charter': old[CHARTER], 'consumer_charter': head,
            'changed_paths': sorted(changed), 'derivation': derivation,
            'sources': dict(current), 'build_inputs': producer['build_inputs']}


def checkout(repo, commit, root, *, remote_url=None):
    dest = Path(root) / repo.split('/', 1)[1]
    if dest.exists():
        raise FileExistsError('source destination already exists: ' + str(dest))
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'init', '--quiet', str(dest)], check=True)
    subprocess.run(['git', '-C', str(dest), 'remote', 'add', 'origin',
                    remote_url or 'https://github.com/' + repo + '.git'], check=True)
    subprocess.run(['git', '-C', str(dest), 'fetch', '--quiet', '--depth=1', 'origin', commit], check=True)
    subprocess.run(['git', '-C', str(dest), 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], check=True)
    head = subprocess.check_output(['git', '-C', str(dest), 'rev-parse', 'HEAD'], text=True).strip()
    status = subprocess.check_output(['git', '-C', str(dest), 'status', '--porcelain=v1',
                                      '--untracked-files=all'], text=True).strip()
    if head != commit or status:
        raise ValueError('public source checkout differs: ' + repo)
    return dest


def checked_download(url, destination, expected_sha256, expected_bytes=None, max_bytes=2 << 30):
    if not url.startswith('https://') or not SHA.fullmatch(expected_sha256):
        raise ValueError('download lacks a reviewed HTTPS URL and SHA-256')
    if (type(max_bytes) is not int or max_bytes <= 0
            or expected_bytes is not None and expected_bytes > max_bytes):
        raise ValueError('download exceeds bounded input policy')
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError('download destination already exists: ' + str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + '.partial')
    if partial.exists():
        raise FileExistsError('partial download already exists: ' + str(partial))
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(url, timeout=120) as response, partial.open('xb') as output:
            while block := response.read(1 << 20):
                size += len(block)
                if size > max_bytes or expected_bytes is not None and size > expected_bytes:
                    raise ValueError('download exceeds reviewed byte size: ' + url)
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != expected_sha256 or expected_bytes is not None and size != expected_bytes:
            raise ValueError('download differs from reviewed digest/size: ' + url)
        partial.replace(destination)
    finally:
        partial.unlink(missing_ok=True)
    return {'name': destination.name, 'sha256': digest.hexdigest(), 'bytes': size}


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def imported(path):
    path = Path(path)
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location('oa_exact_app_package', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight(app, charter, destination, minimum_free_gib):
    if minimum_free_gib < 1:
        raise ValueError('disposable runner must retain at least one GiB free')
    Path(destination).mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(destination).free
    if app != 'comfyui':
        raise ValueError('unknown optional app producer')
    package = imported(Path(charter) / 'scripts/package_comfyui_app.py')
    # Downloaded inputs still have to fit *before* repack's own preflight.
    input_bytes = package.SOURCE_BYTES + sum(row[0] for row in package.CPU_WHEELS.values())
    required = package.required_free_bytes(minimum_free_after_build_bytes=minimum_free_gib << 30)
    required += input_bytes + (2 << 30)  # source checkouts and input artifacts
    if free < required:
        raise OSError(f'{app} producer needs {required:,} free bytes before downloads; has {free:,}')
    print(json.dumps({'app': app, 'free_bytes': free, 'required_free_bytes': required,
                      'minimum_free_after_build_gib': minimum_free_gib}, sort_keys=True))


def comfy_source_checkouts(source_root, input_root):
    package = imported(Path(source_root) / 'abstractions/scripts/package_comfyui_app.py')
    upstream = Path(input_root) / 'upstream'
    checkout('Comfy-Org/ComfyUI_frontend', package.FRONTEND_COMMIT, upstream)
    for name, (commit, _) in package.ADDITIONAL_SOURCES.items():
        repo = {'embedded-docs': 'Comfy-Org/embedded-docs',
                'pygit2': 'libgit2/pygit2', 'libgit2': 'libgit2/libgit2'}[name]
        checkout(repo, commit, upstream)


def successful_hosted_input(run_id, source, select, prefix):
    """Select an unexpired artifact from one successful job of this exact run."""
    token, repo = os.environ.get('GH_TOKEN'), os.environ.get('GH_REPO')
    if (not token or not repo or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)
            or type(run_id) is not int or run_id <= 0 or not COMMIT.fullmatch(source)):
        raise ValueError('GitHub artifact selection requires trusted run and source')
    def pages(kind):
        found = []
        for page in range(1, 101):
            query = 'filter=all&' if kind == 'jobs' else ''
            url = f'https://api.github.com/repos/{repo}/actions/runs/{run_id}/{kind}?{query}per_page=100&page={page}'
            request = urllib.request.Request(url, headers={
                'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'})
            with urllib.request.urlopen(request, timeout=60) as response:
                batch = json.load(response)[kind]
            if not isinstance(batch, list):
                raise ValueError('malformed GitHub run ' + kind)
            found.extend(batch)
            if len(batch) < 100:
                return found
        raise ValueError('GitHub run ' + kind + ' exceeds bounded pagination')
    selected = select(pages('jobs'), pages('artifacts'), run_id, source)
    match = re.fullmatch(re.escape(prefix) + r'-([1-9][0-9]*)', selected['name'])
    return {'artifact': selected['name'], 'run_attempt': int(match[1])}


def successful_wheel_input(run_id, source):
    return successful_hosted_input(run_id, source, select_windows_wheel_artifact,
                                   'abstraction-pypi-win32-x64')


def successful_addon_input(run_id, source):
    return successful_hosted_input(run_id, source, select_windows_addon_artifact,
                                   'abstraction-npm-win32-x64')


def verified_addon_tarball(artifact_dir, version):
    """Bind the Windows addon tarball to every checksum from its selected JS artifact."""
    artifact_dir = Path(artifact_dir)
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', version):
        raise ValueError('invalid candidate npm version')
    checksums = artifact_dir / 'SHA256SUMS.npm.win32-x64'
    rows = {}
    for line in checksums.read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ?([A-Za-z0-9_.-]+\.tgz)', line)
        if not match or match[2] in rows:
            raise ValueError('malformed or duplicate Windows npm checksum')
        rows[match[2]] = match[1]
    actual = {path.name for path in artifact_dir.glob('*.tgz')}
    if len(rows) != 10 or actual != set(rows):
        raise ValueError('Windows npm artifact differs from exact package roster')
    for name, expected in rows.items():
        if sha_file(artifact_dir / name) != expected:
            raise ValueError('Windows npm artifact has a mismatched tarball: ' + name)
    target = artifact_dir / f'openabstractions-ipc-win32-x64-{version}.tgz'
    if target.name not in rows:
        raise ValueError('Windows npm artifact lacks the pinned IPC platform addon')
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('pins', 'checkout', 'preflight', 'download-comfy',
                                             'select-wheels', 'select-addon', 'verify-addon-artifact'))
    parser.add_argument('--app', choices=('comfyui',), required=True)
    parser.add_argument('--npm-pins', default='npm.tsv')
    parser.add_argument('--pypi-pins', default='pypi.tsv')
    parser.add_argument('--app-pins', default='app-sources.tsv')
    parser.add_argument('--roster', default='apps.json')
    parser.add_argument('--source-root', default='sources')
    parser.add_argument('--input-root', default='app-build-inputs')
    parser.add_argument('--minimum-free-gib', type=int, default=1)
    parser.add_argument('--candidate-source')
    parser.add_argument('--run-id', type=int)
    parser.add_argument('--candidate-version')
    parser.add_argument('--producer-only', action='store_true')
    parser.add_argument('--adopter-commit', default=None)
    args = parser.parse_args(argv)
    if args.operation == 'select-wheels':
        print(json.dumps(successful_wheel_input(args.run_id, args.candidate_source), sort_keys=True))
        return
    if args.operation == 'select-addon':
        print(json.dumps(successful_addon_input(args.run_id, args.candidate_source), sort_keys=True))
        return
    if args.operation == 'verify-addon-artifact':
        print(verified_addon_tarball(args.input_root, args.candidate_version))
        return
    pins = source_pins(args.app, args.npm_pins, args.pypi_pins, args.app_pins, args.roster,
                       producer_only=args.producer_only, adopter_commit=args.adopter_commit)
    if args.operation == 'pins':
        print(json.dumps(pins, sort_keys=True))
    elif args.operation == 'checkout':
        for repo, commit in pins.items():
            checkout(repo, commit, args.source_root)
    elif args.operation == 'preflight':
        preflight(args.app, Path(args.source_root) / 'abstractions', Path(args.input_root),
                  args.minimum_free_gib)
    else:
        package = imported(Path(args.source_root) / 'abstractions/scripts/package_comfyui_app.py')
        dest = Path(args.input_root)
        comfy_source_checkouts(args.source_root, dest)
        checked_download(package.SOURCE_URL, dest / 'ComfyUI_windows_portable_amd.7z',
                         package.SOURCE_SHA256, package.SOURCE_BYTES)
        for name, (size, sha256, _) in package.CPU_WHEELS.items():
            family = name.split('-', 1)[0]
            checked_download(package.CPU_WHEEL_PROVENANCE[family][0], dest / 'cpu-wheels' / name,
                             sha256, size)


if __name__ == '__main__':
    main()
