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
FINAL_PRODUCERS = {'verify': ('windows-msi-sign','windows-msi-signed'),
                   'windows-app-delivery': ('windows-app-sign','windows-app-signed')}
PIN_FIELDS = ('id', 'binary_zip', 'binary_sha256', 'binary_bytes',
              'source_zip', 'source_sha256', 'source_bytes', 'source_commit',
              'source_url', 'signer', 'version', 'platform', 'peak_bytes',
              'license', 'publisher', 'install_identity', 'action')
FIELDS = (*PIN_FIELDS, 'release_tag')
# ComfyUI's private-Python RECORD-set digest (private_python_records_sha256 in
# its OA-PROVENANCE.json). Setup's catalog requires it for comfyui and refuses
# it for any other app; the launcher receives it as --records.
RECORDS_FIELD = 'records_sha256'
DESKTOP_VARIANT = 'oa-comfyui-desktop'
NATIVE_VARIANT = 'oa-comfyui-native'
HOST_VARIANTS = (DESKTOP_VARIANT, NATIVE_VARIANT)
DESKTOP_FIELDS = tuple(key for key in FIELDS if key not in
                       {'signer', 'action', 'install_identity'}) + ('variant',)
DESKTOP_PART_FIELDS = tuple(key for key in DESKTOP_FIELDS if key not in
                           {'source_zip','source_sha256','source_bytes'}) + ('corresponding_source','backend')
NATIVE_FIELDS = (*DESKTOP_PART_FIELDS, 'install_identity', 'action', 'application_program', 'service_program','archive_tool_program','record_bytes','record_roots','marker_bytes')


def multipart_row(row):
    return row.get('variant') in HOST_VARIANTS and 'corresponding_source' in row


def delivery_names(row):
    return [row['binary_zip'],*(part['name'] for part in row['corresponding_source']['archive']['parts'])] if multipart_row(row) else [row['binary_zip'],row['source_zip']]


def verify_data_release(row,fetch=None):
    """Require already published exact DATA assets before product publication."""
    if not multipart_row(row):return None
    from app_pair_receipt import validate_backend_resource,validate_corresponding_source,data_part_url
    import promote
    backend=validate_backend_resource(row['backend']);offer=validate_corresponding_source(row['corresponding_source'])
    if offer['data_release']!=backend['data_release']:raise ValueError('source offer has another DATA release')
    location=backend['data_release'];expected={}
    for archive in (backend['archive'],backend['corresponding_source'],offer['archive']):
        for part in archive['parts']:
            key=part['name'].casefold()
            if key in expected and expected[key]!=part:raise ValueError('DATA archive names alias different bytes')
            expected[key]=part
    document=(fetch or promote.api)(f"repos/{location['repository']}/releases/tags/{location['tag']}")
    if (not isinstance(document,dict) or type(document.get('id')) is not int or document['id']<=0
            or document.get('tag_name')!=location['tag'] or document.get('draft') is not False
            or not isinstance(document.get('assets'),list) or len(document['assets'])>64):
        raise ValueError('source-selected immutable DATA release is not published/available')
    found={};ids=set()
    for asset in document['assets']:
        if (not isinstance(asset,dict) or not isinstance(asset.get('name'),str)
                or asset['name'].casefold() in found or type(asset.get('id')) is not int or asset['id']<=0 or asset['id'] in ids):
            raise ValueError('DATA release has ambiguous API asset identity')
        key=asset['name'].casefold();part=expected.get(key)
        if (part is None or asset['name']!=part['name'] or type(asset.get('size')) is not int
                or asset['size']!=part['bytes'] or asset.get('digest')!='sha256:'+part['sha256']
                or asset.get('state')!='uploaded' or asset.get('browser_download_url')!=data_part_url(location,part['name'])):
            raise ValueError('DATA release asset differs from exact source-selected parts')
        found[key]=asset['id'];ids.add(asset['id'])
    if set(found)!=set(expected):raise ValueError('DATA release omits required runtime/corresponding source parts')
    return dict(repository=location['repository'],tag=location['tag'],release_id=document['id'],assets=found)


def row_fields(row):
    """The pin fields an app row carries, including app-specific file pins."""
    if row.get('id') == 'comfyui' and row.get('variant') == NATIVE_VARIANT:
        return NATIVE_FIELDS
    if row.get('id') == 'comfyui' and row.get('variant') == DESKTOP_VARIANT:
        return DESKTOP_PART_FIELDS if multipart_row(row) else DESKTOP_FIELDS
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
    from py_wheels import NATIVE_FAMILIES
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
                or row['directory'] not in ('py', 'python', 'py-native')
                or (row['package'] in NATIVE_FAMILIES and row['directory'] != NATIVE_FAMILIES[row['package']]['directory'])
                or (row['package'] not in NATIVE_FAMILIES and row['directory'] == 'py-native')):
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
    from py_wheels import NATIVE_FAMILIES
    family = NATIVE_FAMILIES.get(pin['package'])
    native = family is not None
    source = checkout / pin['directory']
    with zipfile.ZipFile(path) as archive:
        actual = {name: archive.read(name) for name in archive.namelist()}
    if native:
        from py_wheels import read_metadata
        project = source / family['module']
        source_files = {}
        for file in project.rglob('*'):
            if file.is_symlink():
                raise ValueError('Python package source contains a link: ' + str(file))
            if file.is_file():
                source_files[file.relative_to(source).as_posix()] = file.read_bytes()
        wheel_files = {name: data for name, data in actual.items()
                       if name.startswith(family['module'] + '/') and not name.startswith(family['module'] + '/_native/')}
        if wheel_files != source_files:
            raise ValueError('native wheel Python files differ from pinned source')
        info = family['wheel'] + '-' + version + '.dist-info'
        expected_names = set(source_files) | {family['module'] + '/_native/' + family['libraries']['win_amd64']}
        expected_names.update(info + '/' + name for name in ('METADATA', 'WHEEL', 'LICENSE', 'RECORD'))
        if set(actual) != expected_names:
            raise ValueError('native wheel file set differs from pinned source and fixed library')
        description, requires_python = read_metadata(source, pin['package'])
        expected_metadata = ('Metadata-Version: 2.1\nName: ' + pin['package'] + '\nVersion: ' + version + '\n'
                             + 'Summary: ' + description + '\nRequires-Python: ' + requires_python
                             + '\nLicense-File: LICENSE\n').encode()
        if actual.get(info + '/METADATA') != expected_metadata or actual.get(info + '/LICENSE') != (checkout / 'LICENSE').read_bytes():
            raise ValueError('native wheel metadata or license differs from pinned source')
    else:
        from py_pure_wheels import metadata
        name, wheel_version, expected = metadata(source, checkout / 'LICENSE',
                                                  None if version == '0.0.0' else version)
        if name != pin['package'] or wheel_version != version or actual != expected:
            raise ValueError('pure wheel bytes differ from pinned source')


def windows_wheel_receipt(pins_path, wheels_dir, sources_dir, source, run_id, attempt, version, native_library,
                          *, facade_native_library=None):
    """Bind checked Windows wheel bytes to the exact published pypi.tsv sources."""
    if (not isinstance(source, str) or not COMMIT.fullmatch(source)
            or not isinstance(version, str) or not CANDIDATE_VERSION.fullmatch(version)
            or type(run_id) is not int or run_id <= 0
            or type(attempt) is not int or attempt <= 0):
        raise ValueError('invalid candidate source or run identity')
    pins = python_package_pins(pins_path)
    from py_wheels import pure_wheel_version, NATIVE_FAMILIES
    entries = []
    expected = set()
    for pin in pins:
        repository = pin['repository'].split('/')[1]
        checkout = Path(sources_dir) / repository
        _verified_python_checkout(checkout, pin)
        native = pin['package'] in NATIVE_FAMILIES
        wheel_version = version if native else pure_wheel_version(version)
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
            library = native_library if pin['package'] == 'abstraction-ipc' else facade_native_library
            if library is None:
                raise ValueError('native family library is missing: ' + pin['package'])
            native_path = Path(library)
            if not native_path.is_file():
                raise ValueError('native family library is missing: ' + pin['package'])
            entry['native_library_sha256'] = measured(lambda: native_path.open('rb'))[1]
            family = NATIVE_FAMILIES[pin['package']]
            with zipfile.ZipFile(path) as archive:
                bundled = archive.read(family['module'] + '/_native/' + family['libraries']['win_amd64'])
            if hashlib.sha256(bundled).hexdigest() != entry['native_library_sha256']:
                raise ValueError('native wheel library differs from selected producer bytes')
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


class AppRoster(list):
    """Preserve the existing roster's release identity across its consumers."""
    def __init__(self, rows, version, admission=None):
        super().__init__(rows)
        self.version, self.admission = version, admission


def admission_selection(rows, version=None, admission=None):
    version = version or getattr(rows, 'version', None)
    version = version or next((r['release_tag'].removeprefix('v') for r in rows if 'release_tag' in r), '0.4.0')
    if tuple(map(int, version.split('.'))) < (0, 8, 0):
        return
    try:
        import release_facts as facts
    except ImportError:
        from release import facts
    facts.validate_public_admission(admission or getattr(rows, 'admission', None), version, rows)


def roster(path, *, admission=None):
    return roster_text(Path(path).read_text(encoding='utf-8'), admission=admission)


def roster_text(source, *, admission=None):
    """Validate split catalog bytes before producer and public release phases."""
    document = json.loads(source, object_pairs_hook=strict_object)
    if (not isinstance(document, dict) or set(document) not in ({'schema', 'release_tag', 'apps'},
            {'schema', 'release_tag', 'apps', 'release_admission'})
            or type(document['schema']) is not int or document['schema'] not in (1,2)
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
        modern=multipart_row(row)
        if modern:
            from app_pair_receipt import validate_backend_resource,validate_corresponding_source,NATIVE_BACKEND_ROOT,NATIVE_CONTROL_ROOT
            validate_backend_resource(row['backend']);validate_corresponding_source(row['corresponding_source'])
            if row['corresponding_source']['data_release']!=row['backend']['data_release']:
                raise ValueError('Desktop source offer differs from source-selected DATA release')
        if (document['schema']==2)!=modern:
            raise ValueError('optional app catalog schema differs from row representation')
        if (not isinstance(row['id'], str) or row['id'] not in IDS
                or any(old['id'] == row['id'] for old in rows)
                or not all(isinstance(row[key], str) and NAME.fullmatch(row[key]) for key in (('binary_zip',) if modern else ('binary_zip', 'source_zip')))
                or not modern and row['binary_zip'] == row['source_zip']
                or any(not isinstance(row[key], str) or not SHA.fullmatch(row[key])
                       for key in (('binary_sha256',) if modern else ('binary_sha256', 'source_sha256')))
                or any(type(row[key]) is not int or not 0 < row[key] < MAX_RELEASE_ASSET_BYTES
                       for key in (('binary_bytes',) if modern else ('binary_bytes', 'source_bytes')))
                or type(row['peak_bytes']) is not int or not row['binary_bytes'] <= row['peak_bytes'] <= 2**63 - 1
                or not isinstance(row['source_commit'], str) or not COMMIT.fullmatch(row['source_commit'])
                or not isinstance(row['source_url'], str)
                or not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commit/[0-9a-f]{40}', row['source_url'])
                or not row['source_url'].endswith('/' + row['source_commit'])
                or row['platform'] != 'windows/amd64'
                or (row.get('variant') == NATIVE_VARIANT and
                    (row.get('install_identity') != NATIVE_VARIANT or row.get('action') != 'archive_per_user' or not modern
                     or type(row.get('record_bytes')) is not int or not 0<row['record_bytes']<=2**63-1
                     or type(row.get('marker_bytes')) is not int or not 0<row['marker_bytes']<=16<<20
                     or not isinstance(row.get('record_roots'),list) or len(row['record_roots'])!=2
                     or row['record_roots']!=[NATIVE_BACKEND_ROOT,NATIVE_CONTROL_ROOT]
                     or len({name.casefold() for name in row['record_roots']})!=2
                     or any(not isinstance(row.get(key),str) or not row[key] or '\\' in row[key]
                            or any(part in ('','..','.') or ':' in part for part in row[key].split('/'))
                            for key in ('application_program','service_program','archive_tool_program'))))
                or (row.get('variant') not in HOST_VARIANTS and
                    (row['signer'] != 'unsigned' or row['action'] != 'archive_per_user'
                     or not isinstance(row['install_identity'], str)
                     or not re.fullmatch(r'[a-z0-9][a-z0-9-]*', row['install_identity'])))
                or (row.get('variant') in HOST_VARIANTS and
                    not re.fullmatch(r'https://github\.com/openabstractions/adopter-comfyui/commit/[0-9a-f]{40}', row['source_url']))
                or any(not isinstance(row[key], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', row[key])
                       for key in ('version', 'license', 'publisher'))):
            raise ValueError('unreviewed optional app roster row')
        rows.append(row)
    names=[]
    for row in rows:
        names.append(row['binary_zip'])
        names.extend(part['name'] for part in row['corresponding_source']['archive']['parts']) if multipart_row(row) else names.append(row['source_zip'])
    if len(names) != len(set(names)):
        raise ValueError('duplicate optional app asset name')
    declared = document.get('release_admission')
    if admission is not None and declared is not None and admission != declared:
        raise ValueError('candidate admission differs from source producer declaration')
    rows = AppRoster(rows, document['release_tag'].removeprefix('v'), declared if declared is not None else admission)
    admission_selection(rows)
    return rows


def select_producers(rows, outputs):
    """Use the successful producer's identity, including across draft retries."""
    admission_selection(rows)
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


def _native_row_matches(row,actual):
    if row.get('variant')!=NATIVE_VARIANT:return
    identity=actual['identity']
    if (set(row)!=set(NATIVE_FIELDS) or row.get('install_identity')!=NATIVE_VARIANT or
            row.get('action')!='archive_per_user' or identity.get('programs')!={
                'application':row['application_program'],'service':row['service_program']} or
            row['archive_tool_program']!=identity.get('archive_tool_program')):
        raise ValueError('native archive catalog program/tool facts differ from authenticated pair')
    if any(row[key]!=identity[key] for key in ('record_bytes','record_roots','marker_bytes')):
        raise ValueError('native archive record terms differ from authenticated pair')
    if row['backend']!=identity['backend']:
        raise ValueError('native archive backend differs from authenticated pair')
    expected_peak=(identity['host_expanded_bytes']+actual['binary']['bytes']+row['backend']['archive']['bytes']+
                   identity['backend_expanded_bytes']+identity['record_bytes']+identity['marker_bytes']+(64<<10))
    if row['peak_bytes']!=expected_peak:
        raise ValueError('native archive peak omits or changes authenticated install lifetimes')


def prepare_producer(row, directory, candidate_source, run_id, attempt, mode='github-actions', *,
                     desktop_context=None, producer_job=None):
    """Write one app pair's byte receipt outside both deterministic ZIPs."""
    from app_pair_receipt import inspect,inspect_desktop_set
    directory = Path(directory)
    if (mode not in ('github-actions', 'local-qualification')
            or not isinstance(candidate_source, str) or not COMMIT.fullmatch(candidate_source)
            or type(run_id) is not int or run_id <= 0
            or type(attempt) is not int or attempt <= 0):
        raise ValueError('invalid app producer identity')
    binary = directory / row['binary_zip']
    modern=multipart_row(row)
    source = None if modern else directory / row['source_zip']
    desktop = row.get('variant') in HOST_VARIANTS
    if desktop and (mode != 'github-actions' or producer_job not in FINAL_PRODUCERS or desktop_context is None):
        raise ValueError('custom Desktop final producer requires its exact native delivery job')
    pair = (inspect_desktop_set(binary,directory,row['corresponding_source']['archive'],require_clean_paths=True,desktop_context=desktop_context)
        if modern else inspect(row['id'], binary, source, require_clean_paths=True,
                   **({'desktop_context': desktop_context} if desktop else {})))
    if pair.get('schema') != (3 if modern else 2 if desktop else 1):
        raise ValueError('custom Desktop capsule requires its native/Burn owner, not a legacy portable row')
    if desktop and row['license'] != pair['identity']['license']:
        raise ValueError('final row differs from source-owned Desktop licence')
    _native_row_matches(row,pair)
    binary_item = pair['binary'] if modern else dict(pair['binary'], source_name=row['source_zip'], source_sha256=pair['source']['sha256'])
    app = {'schema': 2 if modern else 1, **row, 'binary': binary_item, 'source': pair['source']}
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


def receive_backend(directory, intake, *, expected_artifact, expected_input,
                    candidate_source, run_id, run_attempt, archive_owner=None, archive_tool=None,
                    metadata=None):
    """Receive an intermediate AMD backend from the existing authenticated API intake.

    This is never an app catalog/publish receipt. The final signed Desktop pair
    is built later by the existing native/sign/package/bind owners.
    """
    from app_pair_receipt import checked_zip, read_backend_producer, ArchiveSetReader, _archive_pin, BACKEND_RUNTIME_MANIFEST_BYTES
    directory = Path(directory)
    if metadata is not None and (type(metadata) is not dict or metadata):
        raise ValueError('backend metadata destination must be empty')
    if (intake.get('schema') != 1 or intake.get('kind') != 'windows-artifact-intake'
            or intake.get('source') != candidate_source or intake.get('run_id') != run_id
            or intake.get('run_attempt') != run_attempt or intake.get('artifact') != expected_artifact
            or type(run_id) is not int or run_id <= 0 or type(run_attempt) is not int or run_attempt <= 0
            or not isinstance(candidate_source, str) or not COMMIT.fullmatch(candidate_source)
            or set(expected_artifact) != {'id', 'name', 'sha256'}
            or type(expected_artifact['id']) is not int or expected_artifact['id'] <= 0
            or expected_artifact['name'] != 'oa-backend-comfyui-' + str(run_attempt)
            or not SHA.fullmatch(str(expected_artifact['sha256']))
            or set(expected_input) != {'bytes', 'sha256'} or type(expected_input['bytes']) is not int
            or not 0 < expected_input['bytes'] <= (4 << 20) or not SHA.fullmatch(str(expected_input['sha256']))):
        raise ValueError('backend differs from selected source/API artifact identity')
    listed = intake.get('files')
    names = {row.get('name') for row in listed} if isinstance(listed, list) and all(isinstance(row, dict) for row in listed) else set()
    if (not isinstance(listed, list) or len(listed) != len(names) or not 3 <= len(names) <= 33
            or 'backend-producer.json' not in names
            or {path.name for path in directory.iterdir()} != names):
        raise ValueError('backend artifact has unexpected intermediate members')
    pins = {}
    for row in listed:
        _archive_pin(row)
        path = directory / row['name']
        if (set(row) != {'name', 'bytes', 'sha256'} or path.is_symlink() or path.is_junction()
                or not path.is_file() or type(row['bytes']) is not int
                or not 0 < row['bytes'] < (4 << 20 if row['name'].endswith('.json') else MAX_RELEASE_ASSET_BYTES)
                or measured(lambda: path.open('rb')) != (row['bytes'], row['sha256'])):
            raise ValueError('backend bytes differ from authenticated intake')
        pins[row['name']] = row
    receipt = read_backend_producer(directory / 'backend-producer.json',
        expected_receipt=pins['backend-producer.json'], expected_input=dict(expected_input, name='backend-inputs.json'),
        candidate_source=candidate_source, run_id=run_id, run_attempt=run_attempt)
    required_names = {'backend-producer.json'}
    for key in ('archive', 'source_pair'):
        required_names.update(part['name'] for part in (receipt[key]['parts'] if receipt['schema'] == 3 else [receipt[key]]))
    if names != required_names:
        raise ValueError('backend intake includes unpinned archive members')
    from contextlib import ExitStack
    with ExitStack() as stack:
        if receipt['schema'] == 2:
            archive = stack.enter_context(checked_zip(directory / receipt['archive']['name'], bounded_members=True))
            members = set(archive.namelist())
            manifest_raw = archive.read('manifest.json')
            sources = stack.enter_context(checked_zip(directory / receipt['source_pair']['name'], bounded_members=True))
        else:
            if archive_owner is None or archive_tool is None:
                raise ValueError('schema3 backend metadata requires explicit source-selected archive tool owner')
            members, manifest_raw = archive_owner.backend_archive_metadata(directory, receipt['archive'], archive_tool)
            stream = stack.enter_context(ArchiveSetReader(directory, receipt['source_pair'], format='zip'))
            sources = stack.enter_context(checked_zip(stream, bounded_members=True,
                expanded_limit=archive_owner.backend_limits()['expanded_bytes']))
        required = {'standalone-env/python.exe', 'standalone-env/uv.exe', 'ComfyUI/main.py', 'manifest.json',
                    'ComfyUI/custom_nodes/abstraction_downloads/__init__.py', 'requirements-amd-win.txt'}
        if not required <= members or 'ComfyUI/manager_requirements.txt' in members:
            raise ValueError('backend lacks standalone/OA layout or retains Manager requirements')
        if len(manifest_raw) > BACKEND_RUNTIME_MANIFEST_BYTES: raise ValueError('backend manifest exceeds metadata bound')
        manifest = json.loads(manifest_raw, object_pairs_hook=strict_object)
        if (sources.getinfo('backend-source.json').file_size > 4 << 20
                or sources.getinfo('OA-Backend-Source/backend-inputs.json').file_size != expected_input['bytes']):
            raise ValueError('backend source metadata exceeds bound')
        source = json.loads(sources.read('backend-source.json'), object_pairs_hook=strict_object)
        descriptor = sources.read('OA-Backend-Source/backend-inputs.json')
        if len(descriptor) != expected_input['bytes'] or hashlib.sha256(descriptor).hexdigest() != expected_input['sha256']:
            raise ValueError('backend source lacks the selected immutable input descriptor')
        if (manifest.get('id') != 'win-amd' or manifest.get('manager') is not False
                or manifest.get('input_descriptor_sha256') != expected_input['sha256']
                or source.get('schema') != 1 or source.get('input_descriptor_sha256') != expected_input['sha256']
                or not SHA.fullmatch(str(manifest.get('private_python_seal', {}).get('records_sha256')))):
            raise ValueError('backend/source pair lacks exact AMD/source/seal binding')
        seen = set()
        for row in source.get('files', []):
            if set(row) != {'name', 'bytes', 'sha256'} or row['name'] in seen:
                raise ValueError('backend corresponding source roster is invalid')
            seen.add(row['name'])
            raw = sources.read(row['name'])
            if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('backend corresponding source differs from pinned roster')
        if not {'builder/scripts/build_local.py', 'ComfyUI/main.py'} <= seen:
            raise ValueError('backend corresponding source is incomplete')
    # Publish only after all held source readers have completed final validation.
    if metadata is not None:
        metadata.update(descriptor=descriptor, manifest=manifest_raw)
    return receipt


def receive_backend_resources(directory, intake, *, archive_owner, archive_tool, metadata, **context):
    """Join API authority, full corresponding source and the signed resource DATA."""
    from app_pair_receipt import (ArchiveSetReader, checked_zip, validate_backend_resource,
                                  validate_data_release, _archive_pin, BACKEND_RUNTIME_ENTRIES)
    if type(metadata) is not dict or metadata: raise ValueError('backend metadata destination must be empty')
    observed = {}
    receipt = receive_backend(directory, intake, archive_owner=archive_owner, archive_tool=archive_tool,
                              metadata=observed, **context)
    if receipt['schema'] == 2:
        metadata.update(observed)
        return receipt, None
    policy_raw = archive_owner.BACKEND_POLICY.read_bytes()
    policy = json.loads(policy_raw, object_pairs_hook=strict_object)
    release = validate_data_release(policy.get('data_release'))
    directory = Path(directory)
    with ArchiveSetReader(directory, receipt['source_pair'], format='zip') as stream, checked_zip(stream, bounded_members=True,
            expanded_limit=archive_owner.backend_limits()['expanded_bytes']) as sources:
        if sources.read('backend-amd-v1.json') != policy_raw:
            raise ValueError('backend corresponding source policy differs from selected source')
        tool = policy['archive_tool']
        for row in [tool['source'], *tool['notices']]:
            name = 'OA-Backend-Source/archive-tool/' + ('notices/' if row in tool['notices'] else '') + row['name']
            info = sources.getinfo(name)
            if info.file_size != row['bytes']: raise ValueError('backend tool source/notice size differs')
            digest = hashlib.sha256()
            with sources.open(info) as data:
                for chunk in iter(lambda:data.read(1 << 20),b''): digest.update(chunk)
            if digest.hexdigest() != row['sha256']: raise ValueError('backend tool source/notice hash differs')
    raw_receipt = (directory/'backend-producer.json').read_bytes()
    expected_receipt = next(row for row in intake['files'] if row['name']=='backend-producer.json')
    if (len(raw_receipt),hashlib.sha256(raw_receipt).hexdigest()) != (expected_receipt['bytes'],expected_receipt['sha256']):
        raise ValueError('backend producer receipt changed during resource assembly')
    manifest = json.loads(observed['manifest'], object_pairs_hook=strict_object)
    if (manifest.get('comfyui_ref') != manifest.get('comfyui_commit')
            or not isinstance(manifest.get('runtime_files'),dict)
            or not 0 < len(manifest['runtime_files']) <= BACKEND_RUNTIME_ENTRIES):
        raise ValueError('backend manifest lacks its exact runtime file closure')
    total = 0
    names = set()
    for name,pin in manifest['runtime_files'].items():
        if (not isinstance(name,str) or name=='manifest.json' or '\\' in name or ':' in name
                or any(ord(c)<32 for c in name) or any(part in ('','.','..') for part in name.split('/'))
                or name.casefold() in names or not isinstance(pin,dict) or set(pin)!={'bytes','sha256'}
                or type(pin['bytes']) is not int or pin['bytes']<0 or not SHA.fullmatch(str(pin['sha256']))):
            raise ValueError('invalid backend runtime file pin')
        names.add(name.casefold());total += pin['bytes']
    if total+len(observed['manifest'])>archive_owner.backend_limits()['expanded_bytes']:
        raise ValueError('backend runtime file closure exceeds source policy')
    def pin(name,raw):return dict(name=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    resource = dict(schema=2,variant='win-amd',comfyui_ref=manifest['comfyui_ref'],
        python_version=manifest['python_version'],archive=receipt['archive'],corresponding_source=receipt['source_pair'],
        data_release=release,provenance=dict(producer_receipt=expected_receipt,
            input_descriptor=pin('backend-inputs.json',observed['descriptor']),
            manifest=pin('backend-manifest.json',observed['manifest']),backend_policy=pin('backend-amd-v1.json',policy_raw)))
    validate_backend_resource(resource)
    observed.update(producer_receipt=raw_receipt,backend_policy=policy_raw)
    metadata.update(observed)
    return receipt,resource


def verify_producer(row, directory, candidate_source, run_id, artifact, *, final_intake=None,
                    selected_sources=None, desktop_inputs=None, repo=None, fetch=None):
    """Reinspect same-run bytes and require their external hosted attestation."""
    from app_pair_receipt import inspect,inspect_desktop_set
    directory = Path(directory)
    desktop = row.get('variant') in HOST_VARIANTS
    context = (_desktop_observation(row, directory, candidate_source, run_id, artifact,
                final_intake, selected_sources, desktop_inputs, repo, fetch) if desktop else None)
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
    modern=multipart_row(row)
    actual = (inspect_desktop_set(directory/row['binary_zip'],directory,row['corresponding_source']['archive'],
                require_clean_paths=True,desktop_context=context) if modern else
        inspect(row['id'], directory / row['binary_zip'], directory / row['source_zip'],
                     require_clean_paths=True, **({'desktop_context': context} if desktop else {})))
    if actual.get('schema') != (3 if modern else 2 if desktop else 1):
        raise ValueError('custom Desktop capsule requires its native/Burn owner, not a legacy portable row')
    if row.get('variant') in HOST_VARIANTS and row['license'] != actual['identity']['license']:
        raise ValueError('final row differs from source-owned Desktop licence')
    _native_row_matches(row,actual)
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


def hosted_predecessor(repo, app, pin, fetch=None, *, variant=None, signer_artifact=None, producer_job=None):
    """Authenticate the original job before trusting any downloaded sidecar."""
    import promote
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or app not in IDS
            or variant not in (None, *HOST_VARIANTS)
            or (variant and (app != 'comfyui' or repo != 'openabstractions/redist'))):
        raise ValueError('invalid app producer repository')
    run, jobs, artifacts = promote.inspect(repo, pin['run_id'], fetch or promote.api)
    if (run.get('id') != pin['run_id'] or run.get('head_sha') != pin['candidate_source']
            or run.get('repository', {}).get('full_name') != repo
            or run.get('head_repository', {}).get('full_name') != repo
            or run.get('path') != '.github/workflows/candidate.yml'
            or run.get('event') != 'workflow_dispatch'
            or run.get('status') not in (('completed', 'in_progress') if variant else ('completed',))):
        raise ValueError('app predecessor is not this repository manual producer source')
    if variant:
        producer_job = producer_job or 'verify'
        if producer_job not in FINAL_PRODUCERS:raise ValueError('unknown native delivery producer job')
    elif producer_job is not None:
        raise ValueError('ordinary app producer cannot select a native delivery job')
    selected_jobs = [job for job in jobs if job.get('name') == (producer_job if variant else 'app_' + app)]
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
    if variant:
        if (not isinstance(signer_artifact, dict) or set(signer_artifact) != {'id', 'name', 'sha256', 'run_attempt'}
                or type(signer_artifact['id']) is not int or signer_artifact['id'] <= 0
                or not SHA.fullmatch(str(signer_artifact['sha256']))
                or type(signer_artifact['run_attempt']) is not int or signer_artifact['run_attempt'] <= 0
                or signer_artifact['name'] != FINAL_PRODUCERS[producer_job][1] + '-' + str(signer_artifact['run_attempt'])):
            raise ValueError('custom Desktop final producer lacks exact signer input identity')
        signing_jobs = [item for item in jobs if item.get('name') == FINAL_PRODUCERS[producer_job][0]]
        signing_assets = [item for item in artifacts if item.get('id') == signer_artifact['id']]
        if (len(signing_jobs) != 1 or len(signing_assets) != 1
                or signing_jobs[0].get('status') != 'completed' or signing_jobs[0].get('conclusion') != 'success'
                or signing_jobs[0].get('run_attempt') != signer_artifact['run_attempt']
                or signing_jobs[0].get('run_id') != pin['run_id']
                or signing_jobs[0].get('head_sha') != pin['candidate_source']
                or signing_assets[0].get('name') != signer_artifact['name']
                or signing_assets[0].get('digest') != 'sha256:' + signer_artifact['sha256']
                or signing_assets[0].get('expired') is not False
                or signing_assets[0].get('workflow_run', {}).get('id') != pin['run_id']
                or signing_assets[0].get('workflow_run', {}).get('head_sha') != pin['candidate_source']):
            raise ValueError('custom Desktop signer input is not this successful source/run/artifact')
    return {'repository': repo, 'candidate_source': pin['candidate_source'], 'run_id': pin['run_id'],
            'run_attempt': attempt, 'job_id': job['id'], 'artifact_id': pin['artifact_id'],
            'artifact': artifact['name'], 'artifact_digest': artifact['digest']}


def _desktop_metadata_max_bytes(name):
    from app_pair_receipt import DESKTOP_CONTEXT_OTHER_BYTES, DESKTOP_CONTEXT_WIRE_BYTES
    return DESKTOP_CONTEXT_WIRE_BYTES if name == 'desktop-context.json' else DESKTOP_CONTEXT_OTHER_BYTES - 1


def _desktop_context_bytes(raw):
    """Bound the existing runtime-containing observation, without granting it authority."""
    from app_pair_receipt import (BACKEND_RUNTIME_MANIFEST_BYTES, DESKTOP_CONTEXT_OTHER_BYTES,
                                  DESKTOP_CONTEXT_WIRE_BYTES)
    if not 0 < len(raw) <= DESKTOP_CONTEXT_WIRE_BYTES:
        raise ValueError('custom Desktop context exceeds aggregate metadata bound')
    value=json.loads(raw,object_pairs_hook=strict_object)
    context=value.get('desktop_context') if isinstance(value,dict) else None
    if not isinstance(context,dict) or 'backend_manifest' not in context:
        if len(raw) >= DESKTOP_CONTEXT_OTHER_BYTES:
            raise ValueError('custom Desktop legacy context exceeds metadata bound')
        return value
    runtime=context['backend_manifest']
    if not isinstance(runtime,dict):
        raise ValueError('custom Desktop context lacks runtime metadata')
    # Match the existing producer's serialization convention; input whitespace
    # and key ordering remain unrestricted within the aggregate wire bound.
    encoded=lambda item:(json.dumps(item,sort_keys=True)+'\n').encode('utf-8')
    if len(encoded(runtime)) > BACKEND_RUNTIME_MANIFEST_BYTES:
        raise ValueError('custom Desktop runtime manifest exceeds metadata bound')
    remainder=dict(value,desktop_context=dict(context))
    del remainder['desktop_context']['backend_manifest']
    if len(encoded(remainder)) >= DESKTOP_CONTEXT_OTHER_BYTES:
        raise ValueError('custom Desktop remaining context exceeds metadata bound')
    return value


def _desktop_wrapper(directory):
    path=Path(directory)/'desktop-context.json'
    if (Path(directory).is_symlink() or Path(directory).is_junction() or path.is_symlink()
            or path.is_junction() or not path.is_file() or not 0 < path.stat().st_size <= _desktop_metadata_max_bytes(path.name)):
        raise ValueError('custom Desktop observation is not bounded plain metadata')
    return _desktop_context_bytes(path.read_bytes())


def _desktop_observation(row, directory, source, run_id, artifact, intake, sources, expected, repo, fetch):
    """Reuse the actual successful native verify observation at the API boundary."""
    if (not isinstance(intake, dict) or intake.get('schema') != 1 or intake.get('kind') != 'windows-artifact-intake'
            or intake.get('source') != source or intake.get('run_id') != run_id
            or not isinstance(sources, dict) or sources.get('openabstractions/adopter-comfyui') != row['source_commit']
            or not all(PUBLIC_REPOSITORY.fullmatch(str(k)) and COMMIT.fullmatch(str(v)) for k,v in sources.items())
            or not isinstance(expected, dict) or set(expected) != ({'source_policy', 'backend_input_descriptor','backend_policy'} if multipart_row(row) else {'source_policy', 'backend_input_descriptor'})
            or not isinstance(repo, str)):
        raise ValueError('custom Desktop requires current source pins and authenticated final API intake')
    api_artifact=intake.get('artifact', {})
    if (set(api_artifact) != {'id','name','sha256'} or api_artifact['name'] != artifact
            or type(api_artifact['id']) is not int or api_artifact['id'] <= 0
            or not SHA.fullmatch(str(api_artifact['sha256']))):
        raise ValueError('custom Desktop final API artifact differs')
    wrapper=_desktop_wrapper(directory)
    if (not isinstance(wrapper,dict) or set(wrapper) != {'schema','producer_job','candidate_source','run_id','run_attempt','signer_artifact','selected_sources','desktop_context'}
            or wrapper['schema'] != 1 or wrapper['producer_job'] not in FINAL_PRODUCERS
            or wrapper['candidate_source'] != source or wrapper['run_id'] != run_id
            or wrapper['run_attempt'] != intake.get('run_attempt') or wrapper['selected_sources'] != sources
            or not isinstance(wrapper['desktop_context'],dict)
            or any(wrapper['desktop_context'].get(k) != v for k,v in expected.items() if k!='backend_policy')):
        raise ValueError('custom Desktop observation differs from current source/policy/run')
    if multipart_row(row):
        from app_pair_receipt import validate_backend_resource
        resource=validate_backend_resource(wrapper['desktop_context'].get('backend'),expected=row['backend'])
        if {key:resource['provenance']['backend_policy'][key] for key in ('bytes','sha256')}!=expected['backend_policy']:
            raise ValueError('Desktop resource recipe differs from selected source policy')
    identity=hosted_predecessor(repo,'comfyui',dict(candidate_source=source,run_id=run_id,
        artifact_id=api_artifact['id'],artifact_digest='sha256:'+api_artifact['sha256']),fetch,
        variant=row['variant'],signer_artifact=wrapper['signer_artifact'],producer_job=wrapper['producer_job'])
    if identity['run_attempt'] != wrapper['run_attempt']:
        raise ValueError('custom Desktop verify observation is from another attempt')
    names={'app.json','producer.json','pair-receipt.json','desktop-context.json','desktop-build-receipt.json',*delivery_names(row)}
    files=intake.get('files')
    if (not isinstance(files,list) or len(files)!=len(names) or {r.get('name') for r in files}!=names
            or {p.name for p in directory.iterdir()}!=names):
        raise ValueError('custom Desktop final artifact roster differs')
    for pin in files:
        path=directory/pin['name']
        if (set(pin)!={'name','sha256','bytes'} or path.is_symlink() or path.is_junction() or not path.is_file()
                or type(pin['bytes']) is not int or not 0 < pin['bytes'] <= (MAX_RELEASE_ASSET_BYTES - 1 if pin['name'] in delivery_names(row) else _desktop_metadata_max_bytes(pin['name']))
                or measured(lambda:path.open('rb'))!=(pin['bytes'],pin['sha256'])):
            raise ValueError('custom Desktop final bytes differ from API intake')
    return wrapper['desktop_context']


def unpack_predecessor(blob, digest, directory, row):
    """Stream a fixed producer roster; bound metadata before JSON inspection."""
    if 'sha256:' + measured(lambda: Path(blob).open('rb'))[1] != digest:
        raise ValueError('app predecessor download differs from API digest')
    directory = Path(directory)
    if directory.exists():
        raise FileExistsError('app predecessor destination already exists')
    expected = {'app.json', 'producer.json', 'pair-receipt.json', 'inputs.json',*delivery_names(row)}
    if row.get('variant') in HOST_VARIANTS:
        expected.add('desktop-context.json')
    with zipfile.ZipFile(blob) as archive:
        members = archive.infolist()
        names = [item.filename for item in members]
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValueError('app predecessor has extra/missing/duplicate files')
        for item in members:
            limit = MAX_RELEASE_ASSET_BYTES - 1 if item.filename in delivery_names(row) else _desktop_metadata_max_bytes(item.filename)
            if (item.is_dir() or '/' in item.filename or '\\' in item.filename
                    or (item.external_attr >> 16) & 0o170000 == 0o120000
                    or not 0 <= item.file_size <= limit):
                raise ValueError('unsafe or oversized app predecessor entry')
            if item.filename == 'desktop-context.json':
                _desktop_context_bytes(archive.read(item))
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
    if pair.get('schema') != 1:
        raise ValueError('custom Desktop capsule requires its native/Burn owner, not a legacy portable row')
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
                        current_sources, source_root, catalog_sha256, repo, fetch=None, *,
                        final_intake=None, desktop_inputs=None):
    """Bind actual P to current C without rewriting P's original source/run."""
    from app_producer_inputs import compare_consumer_sources
    directory = Path(directory)
    wrapper = (_desktop_wrapper(directory)
               if row.get('variant') in HOST_VARIANTS else None)
    identity = hosted_predecessor(repo, row['id'], pin, fetch,
        **({'variant': row['variant'], 'signer_artifact': wrapper.get('signer_artifact'),
            'producer_job':wrapper.get('producer_job')} if wrapper else {}))
    verify_producer(row, directory, identity['candidate_source'], identity['run_id'], identity['artifact'],
        **({'final_intake':final_intake,'selected_sources':current_sources,'desktop_inputs':desktop_inputs,
            'repo':repo,'fetch':fetch} if wrapper else {}))
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
                    current_sources, repo, fetch=None, *, final_intake=None, desktop_inputs=None):
    """Reauthenticate P and bind the successful current app job's C receipt."""
    from app_producer_inputs import CHARTER, CHARTER_DERIVED_PATHS
    directory = Path(directory)
    wrapper = (_desktop_wrapper(directory)
               if row.get('variant') in HOST_VARIANTS else None)
    identity = hosted_predecessor(repo, row['id'], pin, fetch,
        **({'variant': row['variant'], 'signer_artifact': wrapper.get('signer_artifact'),
            'producer_job':wrapper.get('producer_job')} if wrapper else {}))
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
    verify_producer(row, directory, identity['candidate_source'], identity['run_id'], identity['artifact'],
        **({'final_intake':final_intake,'selected_sources':current_sources,'desktop_inputs':desktop_inputs,
            'repo':repo,'fetch':fetch} if wrapper else {}))


def validate_pair(row, manifest, open_file):
    """Return canonical metadata only after both producer files match exactly."""
    fields = row_fields(row)
    if not isinstance(manifest, dict) or set(manifest) != {'schema', *fields, 'binary', 'source'}:
        raise ValueError('optional app producer manifest has unexpected fields')
    modern=multipart_row(row)
    if type(manifest['schema']) is not int or manifest['schema'] != (2 if modern else 1) or any(manifest[key] != row[key] for key in fields):
        raise ValueError('optional app producer differs from reviewed roster')
    if modern:
        from app_pair_receipt import validate_archive_set
        expected={'name':row['binary_zip'],'bytes':row['binary_bytes'],'sha256':row['binary_sha256']}
        if manifest['binary']!=expected or manifest['source']!=row['corresponding_source']['archive']:
            raise ValueError('Desktop capsule/source set differs from reviewed catalog')
        size,sha=measured(lambda:open_file(expected['name']))
        if (size,sha)!=(expected['bytes'],expected['sha256']):raise ValueError('Desktop capsule bytes differ')
        source=validate_archive_set(manifest['source'],format='zip');logical=hashlib.sha256();total=0
        for part in source['parts']:
            hashed=hashlib.sha256();count=0
            with open_file(part['name']) as reader:
                while raw:=reader.read(1<<20):
                    count+=len(raw);total+=len(raw)
                    if count>part['bytes']:raise ValueError('Desktop source part exceeds declared size')
                    hashed.update(raw);logical.update(raw)
            if (count,hashed.hexdigest())!=(part['bytes'],part['sha256']):raise ValueError('Desktop source part differs')
        if (total,logical.hexdigest())!=(source['bytes'],source['sha256']):raise ValueError('Desktop logical source differs')
        return dict(schema=2,**row,binary=expected,source=source)
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
          predecessors=None, catalog_sha256=None, current_sources=None, repo=None, fetch=None,
          final_intakes=None, desktop_inputs=None):
    """Verify same-run producer outputs already downloaded to inputs/ID/."""
    admission_selection(rows)
    dist = Path(dist)
    if not set(predecessors or {}) <= {row['id'] for row in rows}:
        raise ValueError('app predecessor is absent from current catalog')
    apps = []
    checksums = []
    for row in rows:
        source = Path(inputs) / row['id']
        expected = {'app.json', 'producer.json', 'pair-receipt.json', *delivery_names(row)}
        desktop = row.get('variant') in HOST_VARIANTS
        if desktop:
            expected.update(('desktop-context.json','desktop-build-receipt.json'))
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
                            current_sources[row['id']], repo, fetch,
                            **({'final_intake':(final_intakes or {}).get(row['id']),
                                'desktop_inputs':(desktop_inputs or {}).get(row['id'])} if desktop else {}))
        else:
            verify_producer(row, source, candidate_source, run_id, output['artifact'],
                **({'final_intake':(final_intakes or {}).get(row['id']),
                    'desktop_inputs':(desktop_inputs or {}).get(row['id']),
                    'selected_sources':(current_sources or {}).get(row['id']),
                    'repo':repo,'fetch':fetch} if desktop else {}))
        manifest = json.loads((source / 'app.json').read_text(encoding='utf-8'), object_pairs_hook=strict_object)
        apps.append(validate_pair(row, manifest, lambda name: (source / name).open('rb')))
        verify_data_release(row,fetch)
        for name in delivery_names(row):
            if (dist / name).exists():
                raise ValueError('optional app asset collides with another package: ' + name)
            shutil.copyfile(source / name, dist / name)
            checksums.append(f'{measured(lambda: (dist / name).open("rb"))[1]}  {name}\n')
    Path(metadata_path).write_text(json.dumps(apps, sort_keys=True) + '\n', encoding='utf-8')
    (dist / 'SHA256SUMS.apps').write_text(''.join(checksums), encoding='utf-8')
    return apps


def panel_app_ids(selected_deliveries):
    """Select existing app-pin producers; MSI and engine inputs keep their owners."""
    if not isinstance(selected_deliveries,(list,tuple,set,frozenset)) or any(
            not isinstance(app,str) for app in selected_deliveries):
        raise ValueError('invalid selected application deliveries')
    return sorted(set(selected_deliveries) & IDS)


def panel_pin_document(source_document, produced_rows, *, expected_apps):
    """Project already authenticated stage rows into the existing compiled schema.

    The caller owns API/producer admission and supplies its exact selected app-pin
    roster. This projection grants no delivery acceptance or installation state.
    """
    document = json.loads(source_document, object_pairs_hook=strict_object)
    roster_text(source_document)
    if (not isinstance(expected_apps, (list, tuple)) or
            len(set(expected_apps)) != len(expected_apps) or
            any(app not in IDS for app in expected_apps) or not isinstance(produced_rows, list)):
        raise ValueError('invalid selected Panel app roster')
    rows, ids, schemas = [], set(), set()
    for row in produced_rows:
        if not isinstance(row, dict):raise ValueError('invalid produced Panel row')
        fields = row_fields(row)
        if (set(row) != {'schema', *fields, 'binary', 'source'} or row.get('id') not in expected_apps
                or row['id'] in ids or row.get('release_tag') != document['release_tag']):
            raise ValueError('produced Panel row differs from selected roster')
        modern = multipart_row(row)
        schema = 2 if modern else 1
        binary = dict(name=row['binary_zip'], bytes=row['binary_bytes'], sha256=row['binary_sha256'])
        source = row['corresponding_source']['archive'] if modern else dict(
            name=row['source_zip'], bytes=row['source_bytes'], sha256=row['source_sha256'])
        if (type(row['schema']) is not int or row['schema'] != schema or row['source'] != source or
                not isinstance(row['binary'],dict) or
                set(row['binary']) != ({'name','bytes','sha256'} if modern else
                    {'name','bytes','sha256','source_name','source_sha256'}) or
                (not modern and (row['binary']['source_name'] != source['name'] or
                    row['binary']['source_sha256'] != source['sha256'])) or
                any(row['binary'].get(key) != value for key, value in binary.items())):
            raise ValueError('produced Panel archive pins differ')
        rows.append({key: row[key] for key in fields if key != 'release_tag'})
        ids.add(row['id']);schemas.add(schema)
    if ids != set(expected_apps) or len(schemas) > 1:
        raise ValueError('produced Panel rows are missing or incompatible')
    document['apps'] = sorted(rows, key=lambda row: row['id'])
    if schemas:document['schema'] = next(iter(schemas))
    raw = (json.dumps(document, sort_keys=True) + '\n').encode('utf-8')
    roster_text(raw.decode('utf-8'))
    return raw


def panel_pin_input(source_document, produced_rows, *, expected_apps, producer):
    """Bind generated build data to the already authenticated stage producer."""
    if (not isinstance(producer,dict) or set(producer) != {'source','run_id','run_attempt'} or
            not re.fullmatch('[0-9a-f]{40}',str(producer['source'])) or
            any(type(producer[key]) is not int or producer[key] <= 0 for key in ('run_id','run_attempt'))):
        raise ValueError('Panel catalogue requires exact current producer identity')
    raw = panel_pin_document(source_document,produced_rows,expected_apps=expected_apps)
    def pin(value):return dict(bytes=len(value),sha256=hashlib.sha256(value).hexdigest())
    source = source_document.encode('utf-8') if isinstance(source_document,str) else source_document
    descriptor = dict(schema=1,kind='monitor-compiled-catalogue-input',producer=dict(producer),
        catalogue=pin(raw),expected_apps=sorted(expected_apps),source_catalogue=pin(source),
        produced_rows=pin((json.dumps(produced_rows,sort_keys=True)+'\n').encode('utf-8')))
    return raw,(json.dumps(descriptor,sort_keys=True)+'\n').encode('utf-8')


def validate_release(rows, apps, open_file,*,fetch=None):
    admission_selection(rows)
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
    for row in rows:verify_data_release(row,fetch)
    return {name for row in rows for name in delivery_names(row)}


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
