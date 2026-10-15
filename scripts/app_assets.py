"""Internal verified-release contract for optional adopter ZIP/source pairs."""

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile


IDS = frozenset({'comfyui'})
PIN_FIELDS = ('id', 'binary_zip', 'binary_sha256', 'binary_bytes',
              'source_zip', 'source_sha256', 'source_bytes', 'source_commit',
              'source_url', 'signer', 'version', 'platform', 'peak_bytes',
              'license', 'publisher', 'install_identity', 'action')
FIELDS = (*PIN_FIELDS, 'release_tag')
# ComfyUI's private-Python RECORD-set digest (private_python_records_sha256 in
# its OA-PROVENANCE.json). Setup's catalog requires it for comfyui and refuses
# it for any other app; the launcher receives it as --records.
RECORDS_FIELD = 'records_sha256'


def row_fields(row):
    """The pin fields an app row carries, including app-specific file pins."""
    if row.get('id') == 'comfyui':
        return (*FIELDS, RECORDS_FIELD)
    return FIELDS
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\.zip\Z')
TAG = re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+\Z')
# GitHub Release assets must be strictly smaller than 2 GiB.
MAX_RELEASE_ASSET_BYTES = 2 * 1024 * 1024 * 1024
PYPI_COLUMNS = ('package', 'repository', 'commit', 'directory')
APP_SOURCE_COLUMNS = ('app', 'repository', 'commit')
PUBLIC_REPOSITORY = re.compile(r'openabstractions/[A-Za-z0-9._-]+\Z')
CANDIDATE_VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?\Z')


def python_package_pins(path):
    """Read the existing release Python source authority without shell field splitting."""
    lines = [line for line in Path(path).read_text(encoding='utf-8').splitlines()
             if line and not line.startswith('>')]
    rows = list(csv.reader(lines, delimiter='\t'))
    if not rows or tuple(rows[0]) != PYPI_COLUMNS:
        raise ValueError('invalid Python source roster header')
    pins = []
    for fields in rows[1:]:
        if len(fields) != len(PYPI_COLUMNS):
            raise ValueError('malformed Python source roster row')
        row = dict(zip(PYPI_COLUMNS, fields))
        if (not re.fullmatch(r'abstraction-[a-z0-9-]+', row['package'])
                or any(old['package'] == row['package'] for old in pins)
                or not PUBLIC_REPOSITORY.fullmatch(row['repository'])
                or not COMMIT.fullmatch(row['commit'])
                or row['directory'] != 'py'):
            raise ValueError('invalid Python source roster row')
        pins.append(row)
    if not pins or pins[0]['package'] != 'abstraction-ipc' or pins[0]['repository'] != 'openabstractions/abstraction-identity':
        raise ValueError('Python source roster must begin with native IPC')
    return pins


def optional_app_sources(path, rows):
    return optional_app_sources_text(Path(path).read_text(encoding='utf-8'), rows)


def optional_app_sources_text(source, rows):
    """Require the extra public adopter commit only for enabled ComfyUI."""
    lines = [line for line in source.splitlines()
             if line and not line.startswith('>')]
    parsed = list(csv.reader(lines, delimiter='\t'))
    if not parsed or tuple(parsed[0]) != APP_SOURCE_COLUMNS:
        raise ValueError('invalid optional app public source roster')
    sources = {}
    for fields in parsed[1:]:
        if (len(fields) != 3 or fields[0] != 'comfyui'
                or fields[1] != 'openabstractions/adopter-comfyui'
                or not COMMIT.fullmatch(fields[2]) or fields[0] in sources):
            raise ValueError('unreviewed optional app public source pin')
        sources[fields[0]] = {'repository': fields[1], 'commit': fields[2]}
    required = {'comfyui'} if any(row['id'] == 'comfyui' for row in rows) else set()
    if set(sources) != required:
        raise ValueError('enabled ComfyUI lacks exact public adopter source pin')
    return sources


def _wheel_metadata(path, distribution, version, platform_tag):
    dist = distribution.replace('-', '_')
    info = f'{dist}-{version}.dist-info'
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError('wheel contains duplicate or corrupt files: ' + path.name)
        metadata = archive.read(info + '/METADATA').decode('utf-8')
        wheel = archive.read(info + '/WHEEL').decode('utf-8')
        if (f'Name: {distribution}' not in metadata.splitlines()
                or f'Version: {version}' not in metadata.splitlines()
                or f'Tag: {platform_tag}' not in wheel.splitlines()):
            raise ValueError('wheel name, version or platform metadata differs: ' + path.name)
        record_name = info + '/RECORD'
        records = list(csv.reader(io.StringIO(archive.read(record_name).decode('utf-8'))))
        if len(records) != len(names) or {row[0] for row in records} != set(names):
            raise ValueError('wheel RECORD file set differs: ' + path.name)
        for name, digest, size in records:
            if name == record_name:
                if digest or size:
                    raise ValueError('wheel RECORD self-hash is invalid')
                continue
            data = archive.read(name)
            expected = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode('ascii')
            if digest != expected or size != str(len(data)):
                raise ValueError('wheel RECORD hash/size differs: ' + name)


def _verified_python_checkout(checkout, pin):
    """The entire repository is an input: py/, root LICENSE and native sources."""
    head = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain=v1',
                                     '--untracked-files=all'], text=True).strip()
    license_file = checkout / 'LICENSE'
    tracked_license = subprocess.check_output(['git', '-C', str(checkout), 'ls-files', '--', 'LICENSE'],
                                              text=True).strip()
    if (head != pin['commit'] or dirty or not (checkout / pin['directory'] / 'pyproject.toml').is_file()
            or not license_file.is_file() or license_file.is_symlink() or tracked_license != 'LICENSE'):
        raise ValueError('Python package source checkout differs: ' + pin['repository'])
    tracked = subprocess.check_output(['git', '-C', str(checkout), 'ls-files', '-z']).split(b'\0')
    if any((checkout / item.decode('utf-8')).is_symlink() for item in tracked if item):
        raise ValueError('Python package source checkout contains a tracked link: ' + pin['repository'])


def _wheel_matches_python_source(path, checkout, pin, version):
    """The wheel contains exactly the pinned Python bytes, metadata and license."""
    native = pin['package'] == 'abstraction-ipc'
    source = checkout / pin['directory']
    with zipfile.ZipFile(path) as archive:
        actual = {name: archive.read(name) for name in archive.namelist()}
    if native:
        from py_wheels import read_metadata
        project = source / 'abstraction' / 'ipc'
        source_files = {}
        for file in project.rglob('*'):
            if file.is_symlink():
                raise ValueError('Python package source contains a link: ' + str(file))
            if file.is_file():
                source_files[file.relative_to(source).as_posix()] = file.read_bytes()
        wheel_files = {name: data for name, data in actual.items()
                       if name.startswith('abstraction/ipc/') and not name.startswith('abstraction/ipc/_native/')}
        if wheel_files != source_files:
            raise ValueError('native wheel Python files differ from pinned source')
        info = 'abstraction_ipc-' + version + '.dist-info'
        description, requires_python = read_metadata(source)
        expected_metadata = ('Metadata-Version: 2.1\nName: abstraction-ipc\nVersion: ' + version + '\n'
                             + 'Summary: ' + description + '\nRequires-Python: ' + requires_python
                             + '\nLicense-File: LICENSE\n').encode()
        if actual.get(info + '/METADATA') != expected_metadata or actual.get(info + '/LICENSE') != (checkout / 'LICENSE').read_bytes():
            raise ValueError('native wheel metadata or license differs from pinned source')
    else:
        from py_pure_wheels import metadata
        name, wheel_version, expected = metadata(source, checkout / 'LICENSE')
        if name != pin['package'] or wheel_version != '0.0.0' or actual != expected:
            raise ValueError('pure wheel bytes differ from pinned source')


def windows_wheel_receipt(pins_path, wheels_dir, sources_dir, source, run_id, attempt, version, native_library):
    """Bind checked Windows wheel bytes to the exact published pypi.tsv sources."""
    if (not isinstance(source, str) or not COMMIT.fullmatch(source)
            or not isinstance(version, str) or not CANDIDATE_VERSION.fullmatch(version)
            or type(run_id) is not int or run_id <= 0
            or type(attempt) is not int or attempt <= 0):
        raise ValueError('invalid candidate source or run identity')
    pins = python_package_pins(pins_path)
    entries = []
    expected = set()
    for pin in pins:
        repository = pin['repository'].split('/')[1]
        checkout = Path(sources_dir) / repository
        _verified_python_checkout(checkout, pin)
        native = pin['package'] == 'abstraction-ipc'
        wheel_version = version if native else '0.0.0'
        platform_tag = 'py3-none-win_amd64' if native else 'py3-none-any'
        filename = f"{pin['package'].replace('-', '_')}-{wheel_version}-{platform_tag}.whl"
        expected.add(filename)
        path = Path(wheels_dir) / filename
        if not path.is_file():
            raise ValueError('missing Python wheel: ' + filename)
        _wheel_metadata(path, pin['package'], wheel_version, platform_tag)
        _wheel_matches_python_source(path, checkout, pin, wheel_version)
        size, digest = measured(lambda: path.open('rb'))
        if not 0 < size < MAX_RELEASE_ASSET_BYTES:
            raise ValueError('Windows Python wheel exceeds release asset limit: ' + filename)
        entry = {'distribution': pin['package'], 'repository': pin['repository'],
                 'commit': pin['commit'], 'directory': pin['directory'],
                 'filename': filename, 'bytes': size, 'sha256': digest}
        if native:
            from py_wheels import check
            check(path)
            native_path = Path(native_library)
            if not native_path.is_file():
                raise ValueError('native IPC library is missing')
            entry['native_library_sha256'] = measured(lambda: native_path.open('rb'))[1]
        entries.append(entry)
    if {path.name for path in Path(wheels_dir).glob('*.whl')} != expected:
        raise ValueError('Windows Python wheelhouse contains unlisted packages')
    return {'schema': 1, 'candidate_source': source, 'candidate_version': version, 'run_id': run_id,
            'run_attempt': attempt, 'platform': 'win32-x64', 'wheels': entries}


def select_successful_windows_artifact(jobs, artifacts, run_id, source, job_name, artifact_prefix):
    """Select one retained successful same-run Windows producer artifact across retries."""
    successful = {job.get('run_attempt') for job in jobs
                  if job.get('name') == job_name and job.get('run_id') == run_id
                  and job.get('head_sha') == source
                  and job.get('status') == 'completed' and job.get('conclusion') == 'success'
                  and type(job.get('run_attempt')) is int and job['run_attempt'] > 0}
    matches = []
    for artifact in artifacts:
        match = re.fullmatch(re.escape(artifact_prefix) + r'-([1-9][0-9]*)', artifact.get('name', ''))
        observed_run = artifact.get('workflow_run', {})
        if (match and int(match[1]) in successful and not artifact.get('expired')
                and observed_run.get('id') == run_id and observed_run.get('head_sha') == source
                and type(artifact.get('id')) is int):
            matches.append((int(match[1]), artifact))
    if not matches:
        raise ValueError('no successful retained ' + job_name + ' artifact')
    matches.sort(key=lambda item: item[0], reverse=True)
    if len(matches) > 1 and matches[0][0] == matches[1][0]:
        raise ValueError('duplicate ' + job_name + ' artifact for selected attempt')
    return matches[0][1]


def select_windows_wheel_artifact(jobs, artifacts, run_id, source):
    """Select a retained successful Windows Python artifact across run retries."""
    return select_successful_windows_artifact(jobs, artifacts, run_id, source,
                                              'python (win32-x64)', 'abstraction-pypi-win32-x64')


def select_windows_addon_artifact(jobs, artifacts, run_id, source):
    """Select the exact successful Windows npm build that carries the Node addon."""
    return select_successful_windows_artifact(jobs, artifacts, run_id, source,
                                              'javascript (win32-x64)', 'abstraction-npm-win32-x64')


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate app pin JSON key: ' + key)
        result[key] = value
    return result


def roster(path):
    return roster_text(Path(path).read_text(encoding='utf-8'))


def roster_text(source):
    """Validate split catalog bytes before producer and public release phases."""
    document = json.loads(source, object_pairs_hook=strict_object)
    if (not isinstance(document, dict) or set(document) != {'schema', 'release_tag', 'apps'}
            or type(document['schema']) is not int or document['schema'] != 1
            or not isinstance(document['release_tag'], str) or not TAG.fullmatch(document['release_tag'])
            or not isinstance(document['apps'], list)):
        raise ValueError('invalid optional app pin schema')
    rows = []
    for entry in document['apps']:
        expected = (set(row_fields(entry)) - {'release_tag'} if isinstance(entry, dict)
                    and entry.get('id') in IDS else set(PIN_FIELDS))
        if not isinstance(entry, dict) or set(entry) != expected:
            raise ValueError('malformed optional app pin row')
        if RECORDS_FIELD in entry and (not isinstance(entry[RECORDS_FIELD], str) or not SHA.fullmatch(entry[RECORDS_FIELD])):
            raise ValueError('unreviewed optional app roster row')
        row = dict(entry, release_tag=document['release_tag'])
        if (not isinstance(row['id'], str) or row['id'] not in IDS
                or any(old['id'] == row['id'] for old in rows)
                or not all(isinstance(row[key], str) and NAME.fullmatch(row[key]) for key in ('binary_zip', 'source_zip'))
                or row['binary_zip'] == row['source_zip']
                or any(not isinstance(row[key], str) or not SHA.fullmatch(row[key])
                       for key in ('binary_sha256', 'source_sha256'))
                or any(type(row[key]) is not int or not 0 < row[key] < MAX_RELEASE_ASSET_BYTES
                       for key in ('binary_bytes', 'source_bytes'))
                or type(row['peak_bytes']) is not int or not row['binary_bytes'] <= row['peak_bytes'] <= 2**63 - 1
                or not isinstance(row['source_commit'], str) or not COMMIT.fullmatch(row['source_commit'])
                or not isinstance(row['source_url'], str)
                or not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commit/[0-9a-f]{40}', row['source_url'])
                or not row['source_url'].endswith('/' + row['source_commit'])
                or row['signer'] != 'unsigned' or row['platform'] != 'windows/amd64'
                or row['action'] != 'archive_per_user'
                or not isinstance(row['install_identity'], str)
                or not re.fullmatch(r'[a-z0-9][a-z0-9-]*', row['install_identity'])
                or any(not isinstance(row[key], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', row[key])
                       for key in ('version', 'license', 'publisher'))):
            raise ValueError('unreviewed optional app roster row')
        rows.append(row)
    names = [row[key] for row in rows for key in ('binary_zip', 'source_zip')]
    if len(names) != len(set(names)):
        raise ValueError('duplicate optional app asset name')
    return rows


def select_producers(rows, outputs):
    """Use the successful producer's identity, including across draft retries."""
    selected = []
    for row in rows:
        output = outputs.get(row['id'])
        if (not isinstance(output, dict) or set(output) != {'artifact', 'source_commit'}
                or not isinstance(output['artifact'], str)
                or not re.fullmatch(r'oa-app-' + row['id'] + r'-[1-9][0-9]*', output['artifact'])
                or output['source_commit'] != row['source_commit']):
            raise ValueError('optional app has no matching successful producer output: ' + row['id'])
        selected.append((row['id'], output['artifact']))
    return selected


def measured(open_file):
    checksum = hashlib.sha256()
    size = 0
    with open_file() as source:
        while chunk := source.read(1024 * 1024):
            checksum.update(chunk)
            size += len(chunk)
    return size, checksum.hexdigest()


def prepare_producer(row, directory, candidate_source, run_id, attempt, mode='github-actions'):
    """Write one app pair's byte receipt outside both deterministic ZIPs."""
    from app_pair_receipt import inspect
    directory = Path(directory)
    if (mode not in ('github-actions', 'local-qualification')
            or not isinstance(candidate_source, str) or not COMMIT.fullmatch(candidate_source)
            or type(run_id) is not int or run_id <= 0
            or type(attempt) is not int or attempt <= 0):
        raise ValueError('invalid app producer identity')
    binary = directory / row['binary_zip']
    source = directory / row['source_zip']
    pair = inspect(row['id'], binary, source, require_clean_paths=True)
    binary_item = dict(pair['binary'], source_name=row['source_zip'], source_sha256=pair['source']['sha256'])
    app = {'schema': 1, **row, 'binary': binary_item, 'source': pair['source']}
    validate_pair(row, app, lambda name: (directory / name).open('rb'))
    pair_bytes = (json.dumps(pair, sort_keys=True) + '\n').encode('utf-8')
    (directory / 'pair-receipt.json').write_bytes(pair_bytes)
    (directory / 'app.json').write_text(json.dumps(app, sort_keys=True) + '\n', encoding='utf-8')
    producer = {'schema': 1, 'mode': mode, 'app': row['id'], 'candidate_source': candidate_source,
                'run_id': run_id, 'run_attempt': attempt, 'artifact': f"oa-app-{row['id']}-{attempt}",
                'source_commit': row['source_commit'],
                'pair_receipt_sha256': hashlib.sha256(pair_bytes).hexdigest(),
                'binary': pair['binary'], 'source': pair['source']}
    (directory / 'producer.json').write_text(json.dumps(producer, sort_keys=True) + '\n', encoding='utf-8')
    return app, producer


def verify_producer(row, directory, candidate_source, run_id, artifact):
    """Reinspect same-run bytes and require their external hosted attestation."""
    from app_pair_receipt import inspect
    directory = Path(directory)
    observed = json.loads((directory / 'producer.json').read_text(encoding='utf-8'),
                          object_pairs_hook=strict_object)
    pair_bytes = (directory / 'pair-receipt.json').read_bytes()
    pair = json.loads(pair_bytes, object_pairs_hook=strict_object)
    exact = {'schema', 'mode', 'app', 'candidate_source', 'run_id', 'run_attempt',
             'artifact', 'source_commit', 'pair_receipt_sha256', 'binary', 'source'}
    match = re.fullmatch(r'oa-app-' + row['id'] + r'-([1-9][0-9]*)', artifact)
    if (not isinstance(observed, dict) or set(observed) != exact or observed['schema'] != 1
            or observed['mode'] != 'github-actions' or observed['app'] != row['id']
            or observed['candidate_source'] != candidate_source or observed['run_id'] != run_id
            or not match or observed['artifact'] != artifact
            or observed['run_attempt'] != int(match[1])
            or observed['source_commit'] != row['source_commit']
            or observed['pair_receipt_sha256'] != hashlib.sha256(pair_bytes).hexdigest()):
        raise ValueError('optional app producer is not bound to this successful candidate run')
    actual = inspect(row['id'], directory / row['binary_zip'], directory / row['source_zip'],
                     require_clean_paths=True)
    if pair != actual or observed['binary'] != actual['binary'] or observed['source'] != actual['source']:
        raise ValueError('optional app producer pair receipt differs from shipped ZIP bytes')


def predecessor_pins(text):
    """Literal reviewed dependencies in candidate.yml, never a release catalog."""
    pins = json.loads(text, object_pairs_hook=strict_object)
    if not isinstance(pins, dict) or not set(pins) <= IDS:
        raise ValueError('invalid app predecessor selection')
    for item in pins.values():
        fields = {'candidate_source', 'run_id', 'artifact_id', 'artifact_digest',
                  'inputs_sha256', 'derivation'}
        if (not isinstance(item, dict) or set(item) != fields
                or not isinstance(item['candidate_source'], str) or not COMMIT.fullmatch(item['candidate_source'])
                or any(type(item[key]) is not int or item[key] <= 0 for key in ('run_id', 'artifact_id'))
                or not isinstance(item['artifact_digest'], str)
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', item['artifact_digest'])
                or not isinstance(item['inputs_sha256'], str) or not SHA.fullmatch(item['inputs_sha256'])
                or not isinstance(item['derivation'], dict)):
            raise ValueError('invalid immutable app predecessor identity')
    return pins


def hosted_predecessor(repo, app, pin, fetch=None):
    """Authenticate the original job before trusting any downloaded sidecar."""
    import promote
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or app not in IDS:
        raise ValueError('invalid app producer repository')
    run, jobs, artifacts = promote.inspect(repo, pin['run_id'], fetch or promote.api)
    if (run.get('id') != pin['run_id'] or run.get('head_sha') != pin['candidate_source']
            or run.get('repository', {}).get('full_name') != repo
            or run.get('head_repository', {}).get('full_name') != repo
            or run.get('path') != '.github/workflows/candidate.yml'
            or run.get('event') != 'workflow_dispatch' or run.get('status') != 'completed'):
        raise ValueError('app predecessor is not this repository manual producer source')
    selected_jobs = [job for job in jobs if job.get('name') == 'app_' + app]
    if len(selected_jobs) != 1:
        raise ValueError('app predecessor has missing or ambiguous newest job')
    job = selected_jobs[0]
    attempt = job.get('run_attempt')
    if (job.get('run_id') != pin['run_id'] or job.get('head_sha') != pin['candidate_source']
            or job.get('status') != 'completed' or job.get('conclusion') != 'success'
            or type(attempt) is not int or attempt <= 0):
        raise ValueError('newest app predecessor job did not pass')
    matches = [artifact for artifact in artifacts if artifact.get('id') == pin['artifact_id']]
    if len(matches) != 1:
        raise ValueError('exact app predecessor artifact is missing or ambiguous')
    artifact = matches[0]
    if (artifact.get('name') != f'oa-app-{app}-{attempt}' or artifact.get('expired') is not False
            or artifact.get('digest') != pin['artifact_digest']
            or artifact.get('workflow_run', {}).get('id') != pin['run_id']
            or artifact.get('workflow_run', {}).get('head_sha') != pin['candidate_source']):
        raise ValueError('app predecessor artifact identity/digest/expiry differs')
    if (type(artifact.get('size_in_bytes')) is not int
            or not 0 < artifact['size_in_bytes'] < 2 * MAX_RELEASE_ASSET_BYTES + (16 << 20)
            or type(job.get('id')) is not int or job['id'] <= 0):
        raise ValueError('app predecessor has unbounded size or missing job identity')
    return {'repository': repo, 'candidate_source': pin['candidate_source'], 'run_id': pin['run_id'],
            'run_attempt': attempt, 'job_id': job['id'], 'artifact_id': pin['artifact_id'],
            'artifact': artifact['name'], 'artifact_digest': artifact['digest']}


def unpack_predecessor(blob, digest, directory, row):
    """Stream a fixed producer roster; bound metadata before JSON inspection."""
    if 'sha256:' + measured(lambda: Path(blob).open('rb'))[1] != digest:
        raise ValueError('app predecessor download differs from API digest')
    directory = Path(directory)
    if directory.exists():
        raise FileExistsError('app predecessor destination already exists')
    expected = {'app.json', 'producer.json', 'pair-receipt.json', 'inputs.json',
                row['binary_zip'], row['source_zip']}
    with zipfile.ZipFile(blob) as archive:
        members = archive.infolist()
        names = [item.filename for item in members]
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValueError('app predecessor has extra/missing/duplicate files')
        for item in members:
            limit = MAX_RELEASE_ASSET_BYTES if item.filename.endswith('.zip') else 4 << 20
            if (item.is_dir() or '/' in item.filename or '\\' in item.filename
                    or (item.external_attr >> 16) & 0o170000 == 0o120000
                    or not 0 <= item.file_size < limit):
                raise ValueError('unsafe or oversized app predecessor entry')
        directory.mkdir(parents=True)
        for item in members:
            with archive.open(item) as source, (directory / item.filename).open('xb') as output:
                shutil.copyfileobj(source, output, 1 << 20)


def prepare_measured_producer(app, directory, candidate_source, run_id, attempt,
                              version, upstream_commit, inputs):
    """Measure the first genuine pair without enabling an authored catalog row."""
    from app_pair_receipt import inspect
    if (app not in IDS or not isinstance(version, str) or not CANDIDATE_VERSION.fullmatch(version)
            or not isinstance(upstream_commit, str) or not COMMIT.fullmatch(upstream_commit)):
        raise ValueError('unreviewed app bootstrap identity')
    input_bytes = (json.dumps(inputs, sort_keys=True) + '\n').encode()
    if len(input_bytes) >= 4 << 20:
        raise ValueError('app producer input metadata exceeds bounded roster')
    names = app_output_names(app)
    directory = Path(directory)
    pair = inspect(app, directory / names['binary_zip'], directory / names['source_zip'], require_clean_paths=True)
    if pair['identity']['upstream_commit'] != upstream_commit:
        raise ValueError('measured app source differs from producer input')
    with zipfile.ZipFile(directory / names['binary_zip']) as archive:
        peak = sum(item.file_size for item in archive.infolist()) + pair['binary']['bytes'] + pair['source']['bytes']
    owner = 'Comfy-Org/ComfyUI'
    row = dict(id=app, **names, binary_sha256=pair['binary']['sha256'], binary_bytes=pair['binary']['bytes'],
               source_sha256=pair['source']['sha256'], source_bytes=pair['source']['bytes'],
               source_commit=upstream_commit, source_url=f'https://github.com/{owner}/commit/{upstream_commit}',
               signer='unsigned', version=version, platform='windows/amd64', peak_bytes=peak,
               license='GPL-3.0', publisher='OpenAbstractions',
               install_identity=app, action='archive_per_user', release_tag='v' + version)
    row[RECORDS_FIELD] = pair['identity'][RECORDS_FIELD]
    roster_text(json.dumps({'schema': 1, 'release_tag': row['release_tag'],
                            'apps': [{key: value for key, value in row.items() if key != 'release_tag'}]}))
    prepare_producer(row, directory, candidate_source, run_id, attempt)
    (directory / 'inputs.json').write_bytes(input_bytes)
    return row


def app_output_names(app):
    if app not in IDS:
        raise ValueError('unknown optional app producer')
    return {'binary_zip': 'ComfyUI-OA-windows-x64.zip', 'source_zip': 'ComfyUI-OA-source.zip'}


def consume_predecessor(row, pin, directory, candidate_source, run_id, attempt,
                        current_sources, source_root, catalog_sha256, repo, fetch=None):
    """Bind actual P to current C without rewriting P's original source/run."""
    from app_producer_inputs import compare_consumer_sources
    identity = hosted_predecessor(repo, row['id'], pin, fetch)
    directory = Path(directory)
    verify_producer(row, directory, identity['candidate_source'], identity['run_id'], identity['artifact'])
    input_bytes = (directory / 'inputs.json').read_bytes()
    if hashlib.sha256(input_bytes).hexdigest() != pin['inputs_sha256']:
        raise ValueError('immutable app producer inputs differ from reviewed dependency')
    proof = compare_consumer_sources(json.loads(input_bytes, object_pairs_hook=strict_object),
                                     current_sources, source_root, pin['derivation'])
    if not COMMIT.fullmatch(candidate_source) or type(run_id) is not int or run_id <= 0 or type(attempt) is not int or attempt <= 0:
        raise ValueError('invalid current app consumer identity')
    receipt = {'schema': 1, 'candidate_source': candidate_source, 'run_id': run_id,
               'run_attempt': attempt, 'app': row['id'], 'catalog_sha256': catalog_sha256,
               'predecessor': identity, 'inputs_sha256': pin['inputs_sha256'], 'source_comparison': proof}
    (directory / 'consumer.json').write_text(json.dumps(receipt, sort_keys=True) + '\n', encoding='utf-8')
    return receipt


def verify_consumer(row, pin, directory, candidate_source, run_id, artifact, catalog_sha256,
                    current_sources, repo, fetch=None):
    """Reauthenticate P and bind the successful current app job's C receipt."""
    from app_producer_inputs import CHARTER, CHARTER_DERIVED_PATHS
    identity = hosted_predecessor(repo, row['id'], pin, fetch)
    directory = Path(directory)
    receipt = json.loads((directory / 'consumer.json').read_text(encoding='utf-8'), object_pairs_hook=strict_object)
    match = re.fullmatch(r'oa-app-' + row['id'] + r'-([1-9][0-9]*)', artifact)
    fields = {'schema', 'candidate_source', 'run_id', 'run_attempt', 'app', 'catalog_sha256',
              'predecessor', 'inputs_sha256', 'source_comparison'}
    if (not isinstance(receipt, dict) or set(receipt) != fields or receipt['schema'] != 1
            or not match or receipt['run_attempt'] != int(match[1])
            or receipt['candidate_source'] != candidate_source or receipt['run_id'] != run_id
            or receipt['app'] != row['id'] or receipt['catalog_sha256'] != catalog_sha256
            or receipt['predecessor'] != identity or receipt['inputs_sha256'] != pin['inputs_sha256']):
        raise ValueError('app consumer is not bound to this exact catalog/source/run')
    input_bytes = (directory / 'inputs.json').read_bytes()
    if hashlib.sha256(input_bytes).hexdigest() != pin['inputs_sha256']:
        raise ValueError('immutable app producer inputs changed')
    inputs = json.loads(input_bytes, object_pairs_hook=strict_object)
    proof = receipt['source_comparison']
    if (not isinstance(proof, dict)
            or set(proof) != {'producer_charter', 'consumer_charter', 'changed_paths', 'derivation', 'sources', 'build_inputs'}
            or proof['sources'] != current_sources or proof['build_inputs'] != inputs['build_inputs']
            or proof['producer_charter'] != inputs['sources'][CHARTER]
            or proof['consumer_charter'] != current_sources[CHARTER]
            or proof['derivation'] != pin['derivation']
            or not isinstance(proof['changed_paths'], list)
            or not set(proof['changed_paths']) <= CHARTER_DERIVED_PATHS
            or set(inputs['sources']) != set(current_sources)
            or any(commit != current_sources[repo] for repo, commit in inputs['sources'].items() if repo != CHARTER)):
        raise ValueError('app consumer functional source binding differs')
    verify_producer(row, directory, identity['candidate_source'], identity['run_id'], identity['artifact'])


def validate_pair(row, manifest, open_file):
    """Return canonical metadata only after both producer files match exactly."""
    fields = row_fields(row)
    if not isinstance(manifest, dict) or set(manifest) != {'schema', *fields, 'binary', 'source'}:
        raise ValueError('optional app producer manifest has unexpected fields')
    if type(manifest['schema']) is not int or manifest['schema'] != 1 or any(manifest[key] != row[key] for key in fields):
        raise ValueError('optional app producer differs from reviewed roster')
    files = {}
    for role, expected_name in (('binary', row['binary_zip']), ('source', row['source_zip'])):
        item = manifest[role]
        required = {'name', 'sha256', 'bytes'} | ({'source_sha256', 'source_name'} if role == 'binary' else set())
        if (not isinstance(item, dict) or set(item) != required
                or item['name'] != expected_name or not isinstance(item['sha256'], str)
                or not SHA.fullmatch(item['sha256']) or type(item['bytes']) is not int
                or not 0 < item['bytes'] < MAX_RELEASE_ASSET_BYTES
                or item['sha256'] != row[role + '_sha256']
                or item['bytes'] != row[role + '_bytes']):
            raise ValueError('optional app file metadata is invalid')
        try:
            size, checksum = measured(lambda: open_file(expected_name))
        except (KeyError, FileNotFoundError) as exc:
            raise ValueError('optional app file is missing: ' + expected_name) from exc
        if size != item['bytes'] or checksum != item['sha256']:
            raise ValueError('optional app file hash/size mismatch: ' + expected_name)
        files[role] = dict(item)
    if (files['binary']['source_sha256'] != files['source']['sha256']
            or files['binary']['source_name'] != files['source']['name']):
        raise ValueError('optional app binary/source pair differs')
    return {'schema': 1, **row, **files}


def stage(rows, inputs, dist, metadata_path, *, candidate_source=None, run_id=None, outputs=None,
          predecessors=None, catalog_sha256=None, current_sources=None, repo=None, fetch=None):
    """Verify same-run producer outputs already downloaded to inputs/ID/."""
    dist = Path(dist)
    if not set(predecessors or {}) <= {row['id'] for row in rows}:
        raise ValueError('app predecessor is absent from current catalog')
    apps = []
    checksums = []
    for row in rows:
        source = Path(inputs) / row['id']
        expected = {'app.json', 'producer.json', 'pair-receipt.json', row['binary_zip'], row['source_zip']}
        pin = (predecessors or {}).get(row['id'])
        if pin:
            expected.update(('inputs.json', 'consumer.json'))
        if not source.is_dir() or {p.name for p in source.iterdir()} != expected:
            raise ValueError('optional app producer artifact missing or contains extra files: ' + row['id'])
        output = outputs.get(row['id']) if isinstance(outputs, dict) else None
        if (not isinstance(output, dict) or set(output) != {'artifact', 'source_commit'}
                or output['source_commit'] != row['source_commit']):
            raise ValueError('optional app producer output is absent: ' + row['id'])
        if pin:
            verify_consumer(row, pin, source, candidate_source, run_id, output['artifact'], catalog_sha256,
                            current_sources[row['id']], repo, fetch)
        else:
            verify_producer(row, source, candidate_source, run_id, output['artifact'])
        manifest = json.loads((source / 'app.json').read_text(encoding='utf-8'), object_pairs_hook=strict_object)
        apps.append(validate_pair(row, manifest, lambda name: (source / name).open('rb')))
        for name in (row['binary_zip'], row['source_zip']):
            if (dist / name).exists():
                raise ValueError('optional app asset collides with another package: ' + name)
            shutil.copyfile(source / name, dist / name)
            checksums.append(f'{measured(lambda: (dist / name).open("rb"))[1]}  {name}\n')
    Path(metadata_path).write_text(json.dumps(apps, sort_keys=True) + '\n', encoding='utf-8')
    (dist / 'SHA256SUMS.apps').write_text(''.join(checksums), encoding='utf-8')
    return apps


def validate_release(rows, apps, open_file):
    if not isinstance(apps, list) or len(apps) != len(rows):
        raise ValueError('candidate optional app roster differs from reviewed source')
    if any(not isinstance(item, dict) or not isinstance(item.get('id'), str) for item in apps):
        raise ValueError('malformed optional app metadata')
    by_id = {item['id']: item for item in apps}
    if len(by_id) != len(rows) or set(by_id) != {row['id'] for row in rows}:
        raise ValueError('duplicate or malformed optional app metadata')
    canonical = [validate_pair(row, by_id[row['id']], open_file) for row in rows]
    if canonical != apps:
        raise ValueError('optional app metadata differs from reviewed roster')
    return {row[key] for row in rows for key in ('binary_zip', 'source_zip')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage', 'prepare', 'prepare-first', 'consume'))
    parser.add_argument('--roster', required=True)
    parser.add_argument('--inputs')
    parser.add_argument('--dist')
    parser.add_argument('--metadata')
    parser.add_argument('--outputs', help='JSON mapping of successful same-run app job outputs')
    parser.add_argument('--app', choices=tuple(sorted(IDS)))
    parser.add_argument('--directory')
    parser.add_argument('--candidate-source')
    parser.add_argument('--run-id', type=int)
    parser.add_argument('--run-attempt', type=int)
    parser.add_argument('--local-qualification', action='store_true')
    parser.add_argument('--source-root', default='sources')
    parser.add_argument('--input-root', default='app-build-inputs')
    parser.add_argument('--npm-pins', default='npm.tsv')
    parser.add_argument('--pypi-pins', default='pypi.tsv')
    parser.add_argument('--app-pins', default='app-sources.tsv')
    parser.add_argument('--adopter-commit')
    parser.add_argument('--upstream-commit')
    parser.add_argument('--candidate-version')
    parser.add_argument('--predecessors', default='{}', help='literal reviewed dependencies from candidate source')
    args = parser.parse_args(argv)
    rows = roster(args.roster)
    pins = predecessor_pins(args.predecessors)
    if args.operation in ('prepare-first', 'consume'):
        from app_producer_inputs import source_pins, pinned_input_receipt
        if (not args.app or not args.directory or args.run_id is None or args.run_attempt is None
                or os.environ.get('GITHUB_ACTIONS') != 'true'):
            parser.error('first producer/consumer requires GitHub Actions and exact app/run identity')
        first = args.operation == 'prepare-first'
        sources = source_pins(args.app, args.npm_pins, args.pypi_pins, args.app_pins, args.roster,
                              producer_only=first, adopter_commit=args.adopter_commit if first else None)
        if first:
            inputs = pinned_input_receipt(sources, args.source_root, args.input_root)
            row = prepare_measured_producer(args.app, args.directory, args.candidate_source,
                                            args.run_id, args.run_attempt, args.candidate_version,
                                            args.upstream_commit, inputs)
            print(json.dumps(row, sort_keys=True))
        else:
            import promote
            pin = pins.get(args.app)
            row = next((row for row in rows if row['id'] == args.app), None)
            if pin is None or row is None:
                parser.error('consume requires one enabled app and its reviewed predecessor')
            repo = os.environ.get('GH_REPO', '')
            identity = hosted_predecessor(repo, args.app, pin)
            blob = Path(args.input_root) / f"predecessor-{pin['artifact_id']}.zip"
            blob.parent.mkdir(parents=True, exist_ok=True)
            if blob.exists():
                raise FileExistsError('app predecessor download already exists')
            promote.download(['api', f"repos/{repo}/actions/artifacts/{pin['artifact_id']}/zip"], blob)
            unpack_predecessor(blob, identity['artifact_digest'], args.directory, row)
            consume_predecessor(row, pin, args.directory, args.candidate_source, args.run_id,
                                args.run_attempt, sources, args.source_root,
                                measured(lambda: Path(args.roster).open('rb'))[1], repo)
        return
    if args.operation == 'prepare':
        if not args.app or not args.directory or args.run_id is None or args.run_attempt is None:
            parser.error('prepare requires app, directory and run identity')
        if not args.local_qualification and os.environ.get('GITHUB_ACTIONS') != 'true':
            parser.error('hosted producer receipt requires GitHub Actions; use --local-qualification offline')
        selected = next((row for row in rows if row['id'] == args.app), None)
        if selected is None:
            parser.error('app is not enabled in the authored candidate roster')
        prepare_producer(selected, args.directory, args.candidate_source, args.run_id,
                         args.run_attempt, mode='local-qualification' if args.local_qualification else 'github-actions')
    else:
        if not args.inputs or not args.dist or not args.metadata:
            parser.error('stage requires inputs, dist and metadata')
        outputs = json.loads(Path(args.outputs).read_text(encoding='utf-8'), object_pairs_hook=strict_object) if args.outputs else None
        current = None
        if pins:
            from app_producer_inputs import source_pins
            current = {row['id']: source_pins(row['id'], args.npm_pins, args.pypi_pins,
                       args.app_pins, args.roster) for row in rows if row['id'] in pins}
        stage(rows, args.inputs, args.dist, args.metadata, candidate_source=args.candidate_source,
              run_id=args.run_id, outputs=outputs, predecessors=pins,
              catalog_sha256=measured(lambda: Path(args.roster).open('rb'))[1],
              current_sources=current, repo=os.environ.get('GH_REPO', ''))


if __name__ == '__main__':
    main()
