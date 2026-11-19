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
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
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
                 'windows-runtime-build', 'windows-runtime-sign',
                 'windows', 'windows-app-msi', 'windows-msi-sign', 'verify', 'linux',
                 'linux-verify', 'macos', 'draft', 'bundle', 'windows-bundle-sign',
                 'windows-bundle-verify'}
SETUP_ARTIFACT = 'setup-bundle-'
# GitHub reruns "all of the failed jobs and their dependent jobs" in a new
# attempt (https://docs.github.com/en/rest/actions/workflow-runs#re-run-failed-jobs-from-a-workflow-run).
# Each retained artifact keeps its successful producer job's own attempt.
# A downstream-only rerun can retain draft and signing from different attempts.
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
    if 'catalog_opencode' in setup_receipt:
        signatures['files'].append(setup_receipt['catalog_opencode']['signature'])
    return release_facts_owner().producer_record(metadata, assets, unsigned_platforms=['linux'], setup_signatures=signatures)


def windows_signing_directory():
    windows = Path(__file__).resolve().parent.parent / 'windows'
    if not windows.is_dir():
        windows = Path(__file__).resolve().parents[3] / 'installer'
    return windows


def windows_policy_bytes():
    return (windows_signing_directory() / 'certum_simplysign.json').read_bytes()


def runtime_release_policy(version):
    """Read the unchanged source pin used by the provider's final download URL."""
    if tuple(map(int, version.removeprefix('v').split('.'))) < (0, 8, 0):
        return None
    windows = windows_signing_directory()
    path = windows / 'modelhost_engine.py'
    import types
    owner = types.ModuleType('oa_runtime_release_owner'); owner.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), owner.__dict__)
    pin = windows / 'vc-runtime.json'
    if not pin.is_file():
        pin = Path(__file__).resolve().parents[3] / 'monitor/internal/setup/vc_runtime_asset.json'
    asset = owner.runtime_asset(pin)
    if asset['release_tag'] != version:
        raise ValueError('runtime asset release tag differs from the exact candidate version')
    return owner, asset


def runtime_release_asset(archive, version):
    selected = runtime_release_policy(version)
    if selected is None:
        return None
    owner, asset = selected
    pin = asset['archive']; name = pin['name']
    if archive.getinfo(name).file_size != pin['size_bytes']:
        raise ValueError('final runtime ZIP size differs from its source pin')
    with tempfile.TemporaryDirectory(prefix='oa-runtime-release-') as temporary:
        target = Path(temporary) / name
        with archive.open(name) as reader:
            target.write_bytes(reader.read(pin['size_bytes'] + 1))
        owner.runtime_asset_bytes(target, asset)
    return name


def verify_runtime_url(version, *, open_url=None):
    """Read the frozen anonymous public URL before publication is complete."""
    selected = runtime_release_policy(version)
    if selected is None:
        return
    pin = selected[1]['archive']
    with (open_url or urllib.request.urlopen)(pin['url'], timeout=30) as response:
        raw = response.read(pin['size_bytes'] + 1)
    if (len(raw), hashlib.sha256(raw).hexdigest()) != (pin['size_bytes'], pin['sha256']):
        raise ValueError('published runtime URL differs from the frozen source size/hash')
    verify_pytorch_urls(version, open_url=open_url)


def pytorch_release_assets(archive, version):
    """Admit only the retained runtime ZIP and its exact owner manifest."""
    owner = pytorch_inputs_module()
    pins = owner.release_assets(version)
    with tempfile.TemporaryDirectory(prefix='oa-pytorch-release-') as temporary:
        directory = Path(temporary)
        for name, pin in pins.items():
            if archive.getinfo(name).file_size != pin['size_bytes']:
                raise ValueError('final PyTorch runtime input size differs from its source pin')
            with archive.open(name) as reader, (directory / name).open('xb') as writer:
                shutil.copyfileobj(reader, writer, length=1024 * 1024)
        owner.verify_release_inputs(directory)
    return set(pins)


def verify_pytorch_urls(version, *, open_url=None):
    """Stream the frozen anonymous URLs without buffering the 1.7 GB ZIP."""
    for name, pin in pytorch_inputs_module().release_assets(version).items():
        size = 0; checksum = hashlib.sha256()
        with (open_url or urllib.request.urlopen)(pin['url'], timeout=30) as response:
            while size <= pin['size_bytes']:
                chunk = response.read(min(1024 * 1024, pin['size_bytes'] + 1 - size))
                if not chunk:
                    break
                checksum.update(chunk); size += len(chunk)
        if (size, checksum.hexdigest()) != (pin['size_bytes'], pin['sha256']):
            raise ValueError('published PyTorch runtime URL differs from the frozen source size/hash: ' + name)


def windows_signing_owner():
    spec = importlib.util.spec_from_file_location(
        'oa_promote_windows_signing', windows_signing_directory() / 'windows_signing.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def windows_signature_proof(receipt):
    """Use the same reviewed certificate policy as the independent Windows verifier."""
    policy_bytes = windows_policy_bytes()
    helper = windows_signing_owner()
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
        entries = data if key is None else data[key]
        if key is None and (not isinstance(entries, list) or len(entries) > 100
                            or any(not isinstance(row, dict) for row in entries)):
            raise ValueError('API list page is malformed')
        result.extend(entries)
        if len(entries) < 100:
            return result
    raise ValueError('API pagination exceeded 100 pages')


LOCAL_RELEASE_REPO = 'openabstractions/redist'
LOCAL_RELEASE_ACTOR = {'login': 'ReinisLusis', 'id': 13084295}


def local_release_actor(fetch=api):
    if (any(os.environ.get(key) for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'))
            or os.environ.get('GH_HOST', 'github.com') != 'github.com'):
        raise ValueError('local release requires the existing github.com gh login')
    actor = fetch('user')
    repository = fetch(f'repos/{LOCAL_RELEASE_REPO}')
    if (any(actor.get(key) != value for key, value in LOCAL_RELEASE_ACTOR.items())
            or repository.get('full_name') != LOCAL_RELEASE_REPO
            or repository.get('private') is not False
            or repository.get('archived') is not False
            or repository.get('disabled') is not False
            or repository.get('permissions', {}).get('push') is not True):
        raise ValueError('local release actor or repository write permission differs')
    return dict(LOCAL_RELEASE_ACTOR)


def local_release_tag(version, commit, lookup=optional_api):
    ref = f'refs/tags/{version}'
    tag = lookup(f'repos/{LOCAL_RELEASE_REPO}/git/ref/tags/{version}')
    if tag is None:
        return False
    if (tag.get('ref') != ref or tag.get('object', {}).get('type') != 'commit'
            or tag['object'].get('sha') != commit):
        raise ValueError('local release tag differs from the selected commit')
    return True


def local_release_list(version, fetch=api):
    matches = []
    for page in range(1, 101):
        rows = fetch(f'repos/{LOCAL_RELEASE_REPO}/releases?per_page=100&page={page}')
        if not isinstance(rows, list) or len(rows) > 100 or any(not isinstance(row, dict) for row in rows):
            raise ValueError('local release listing is malformed')
        matches.extend(row for row in rows if row.get('tag_name') == version)
        if len(matches) > 1:
            raise ValueError('local release listing is ambiguous')
        if len(rows) < 100:
            return matches[0] if matches else None
    raise ValueError('local release listing exceeded 100 pages')


def local_release_files(rows, retained):
    expected = {}
    for row in rows:
        name, pin = row['name'], row['artifact']
        path = Path(pin['path'])
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', name) or name in expected
                or path.name != name or not path.is_absolute() or pin not in retained
                or not re.fullmatch(r'[0-9a-f]{64}', str(pin.get('sha256')))
                or type(pin.get('bytes')) is not int or not 0 < pin['bytes'] < MAX_RELEASE_ASSET_BYTES):
            raise ValueError('local release asset pin differs')
        assert_local_release_file(path, pin)
        expected[name] = pin
    if not expected:
        raise ValueError('local release asset roster is empty')
    return expected


def assert_local_release_file(path, pin):
    import stat
    for parent in (path, *path.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('local release asset path is linked')
    if (not stat.S_ISREG(path.lstat().st_mode)
            or path.stat().st_nlink != 1
            or measured(lambda: path.open('rb')) != (pin['bytes'], pin['sha256'])):
        raise ValueError('local release asset bytes differ: ' + path.name)


def local_release_identity(basis, release_id, *, fetch=api, allow_public=False):
    version, actor = basis['version'], basis['actor']
    prefix = f'repos/{LOCAL_RELEASE_REPO}'
    if type(release_id) is not int or release_id < 1:
        raise ValueError('local release has no journaled ID')
    listed = local_release_list(version, fetch)
    if listed is None:
        raise ReadAPIError(f'{prefix}/releases/{release_id}', 'draft-not-visible')
    if listed.get('id') != release_id:
        raise ValueError('local release listing differs from its journaled draft')
    release = fetch(f'{prefix}/releases/{release_id}')
    author = release.get('author', {})
    endpoint = f'https://uploads.github.com/{prefix}/releases/{release_id}/assets'
    if (release.get('id') != release_id or release.get('tag_name') != version
            or release.get('name') != version
            or release.get('prerelease') is not False
            or (release.get('draft') is not True and not (allow_public and release.get('draft') is False))
            or release.get('body', '').replace('\r\n', '\n') != basis['body']
            or any(author.get(key) != value for key, value in actor.items())
            or release.get('upload_url') != endpoint + '{?name,label}'):
        raise ValueError('local release ID, author, body or draft state differs')
    return release


def local_release_readback(basis, release_id, *, fetch=api, read_asset=None):
    release = local_release_identity(basis, release_id, fetch=fetch)
    prefix = f'repos/{LOCAL_RELEASE_REPO}'
    assets, ids = {}, set()
    for row in pages(f'{prefix}/releases/{release_id}/assets', None, fetch):
        name, asset_id = row.get('name'), row.get('id')
        wanted = basis['assets'].get(name)
        if (wanted is None or name in assets or type(asset_id) is not int or asset_id < 1
                or asset_id in ids or row.get('state') != 'uploaded' or row.get('size') != wanted['bytes']):
            raise ValueError('local release asset roster or identity differs')
        digest = row.get('digest')
        if digest is None and read_asset is not None:
            digest = 'sha256:' + read_asset(asset_id)
        if digest != 'sha256:' + wanted['sha256']:
            raise ValueError('local release asset digest differs: ' + name)
        assets[name] = dict(id=asset_id, bytes=wanted['bytes'], sha256=wanted['sha256'])
        ids.add(asset_id)
    return release, assets, f'https://uploads.github.com/{prefix}/releases/{release_id}/assets'


def local_release_draft(basis, state, save, mutate, *, fetch=api, lookup=optional_api, read_asset=None):
    """Advance only journaled create-only writes. None requires reconciliation."""
    version, commit = basis['version'], basis['commit']
    prefix = f'repos/{LOCAL_RELEASE_REPO}'
    if local_release_actor(fetch) != basis['actor']:
        raise ValueError('local release actor changed after admission')

    def begin(kind, **identity):
        state['pending'] = dict(kind=kind, **identity)
        save()

    def acknowledge(**identity):
        state.update(identity)
        state.pop('pending', None)
        save()

    tag = local_release_tag(version, commit, lookup)
    pending = state.get('pending', {})
    if pending.get('kind') == 'tag':
        if not tag:
            return None
        acknowledge(tag=commit)
    elif 'tag' not in state:
        if tag != basis['tag_present'] or local_release_list(version, fetch) is not None:
            raise ValueError('local release tag or draft changed after admission')
        if not tag:
            begin('tag', commit=commit)
            ref = f'refs/tags/{version}'
            created = mutate(f'{prefix}/git/refs', {'ref': ref, 'sha': commit})
            if (created.get('ref') != ref or created.get('object', {}).get('type') != 'commit'
                    or created['object'].get('sha') != commit):
                raise ValueError('local release create returned a different tag')
            if not local_release_tag(version, commit, lookup):
                return None
        acknowledge(tag=commit)
    elif not tag or state['tag'] != commit:
        raise ValueError('local release journaled tag differs')

    if state.get('pending', {}).get('kind') == 'draft':
        # A visible tag/body cannot replace the unacknowledged numeric ID.
        return None
    if 'release_id' not in state:
        if local_release_list(version, fetch) is not None:
            raise ValueError('a release already exists for the selected tag')
        if not local_release_tag(version, commit, lookup):
            raise ValueError('local release tag disappeared before draft creation')
        begin('draft', tag=version)
        created = mutate(f'{prefix}/releases', dict(tag_name=version, target_commitish=commit,
                         name=version, body=basis['body'], draft=True, prerelease=False))
        release_id = created.get('id')
        if type(release_id) is not int or release_id < 1:
            return None
        acknowledge(release_id=release_id)

    def read():
        _, assets, endpoint = local_release_readback(basis, state['release_id'], fetch=fetch, read_asset=read_asset)
        return assets, endpoint

    assets, endpoint = read()
    known = state.get('assets', {})
    pending = state.get('pending', {})
    if pending:
        if pending.get('kind') != 'asset' or pending.get('name') not in basis['assets']:
            raise ValueError('local release pending write identity differs')
        name = pending['name']
        if name not in assets:
            return None
        if (set(assets) != set(known) | {name} or any(assets[key] != pin for key, pin in known.items())
                or pending.get('id', assets[name]['id']) != assets[name]['id']):
            raise ValueError('local release asset IDs changed during upload')
        acknowledge(assets=assets)
    elif assets != known:
        raise ValueError('local release has assets outside the journaled upload history')

    for name, pin in basis['assets'].items():
        if name in assets:
            continue
        if (not local_release_tag(version, commit, lookup) or read()[0] != assets):
            raise ValueError('local release changed before asset upload')
        begin('asset', name=name, sha256=pin['sha256'])
        uploaded = mutate(f'{endpoint}?name={name}', pin)
        asset_id = uploaded.get('id')
        if type(asset_id) is not int or asset_id < 1:
            return None
        state['pending']['id'] = asset_id
        save()
        observed, _ = read()
        if observed == assets:
            return None
        if (set(observed) != set(assets) | {name}
                or any(observed[key] != old for key, old in assets.items())
                or observed[name]['id'] != asset_id):
            raise ValueError('local release upload readback differs')
        assets = observed
        acknowledge(assets=assets)
    return dict(release_id=state['release_id'], assets=assets)


def publish_backend_data(row, files, source, *, fetch=api, lookup=optional_api, mutate=command, read_url=None):
    """Publish the exact DATA parts of an already verified signed app producer.

    The caller verifies the signed producer before this step; the unchanged
    app-assets stage verifies the published DATA release afterwards.
    """
    from app_pair_receipt import (validate_backend_resource, validate_corresponding_source,
                                 data_part_url, backend_data_release)

    if row.get('id') != 'comfyui' or not _app_assets.multipart_row(row):
        raise ValueError('backend DATA requires the multipart ComfyUI producer')
    backend = validate_backend_resource(row['backend'])
    offer = validate_corresponding_source(row['corresponding_source'])
    location = backend['data_release']
    expected_location = backend_data_release(backend['archive'])
    tag = expected_location['tag']
    if (location != expected_location
            or offer['data_release'] != location or not re.fullmatch(r'[0-9a-f]{40}', source)):
        raise ValueError('backend DATA differs from the source-selected release locator')
    expected = {}
    aliases = {}
    for archive in (backend['archive'], backend['corresponding_source'], offer['archive']):
        for part in archive['parts']:
            name = part['name']
            if name.casefold() in aliases and (aliases[name.casefold()] != name or expected[name] != part):
                raise ValueError('backend DATA parts alias different identities')
            aliases[name.casefold()] = name
            expected[name] = part
    if not isinstance(files, dict) or set(files) != set(expected):
        raise ValueError('backend DATA local file roster differs')
    for name, pin in expected.items():
        path = Path(files[name]).absolute()
        if path.name != name:
            raise ValueError('backend DATA local part name differs')
        assert_local_release_file(path, pin)
    identity = dict(kind='comfyui-backend-data', backend=backend, corresponding_source=offer)
    body = json.dumps(identity, sort_keys=True) + '\n'
    title = tag
    prefix = 'repos/' + LOCAL_RELEASE_REPO
    releases = [item for item in pages(prefix + '/releases', None, fetch) if item.get('tag_name') == tag]
    if len(releases) > 1:
        raise ValueError('backend DATA release identity is ambiguous')
    release = releases[0] if releases else None

    def check_tag(commit):
        current = lookup(prefix + '/git/ref/tags/' + tag)
        if (not isinstance(current, dict) or current.get('ref') != 'refs/tags/' + tag
                or current.get('object', {}).get('type') != 'commit'
                or current['object'].get('sha') != commit):
            raise ValueError('backend DATA tag differs from its original release commit')

    def read(release_id, commit):
        check_tag(commit)
        current = fetch(prefix + '/releases/' + str(release_id))
        endpoint = f'https://uploads.github.com/{prefix}/releases/{release_id}/assets'
        if (not isinstance(current, dict) or current.get('id') != release_id
                or current.get('tag_name') != tag or current.get('target_commitish') != commit
                or current.get('name') != title or current.get('prerelease') is not True
                or type(current.get('draft')) is not bool
                or current.get('body', '').replace('\r\n', '\n') != body
                or current.get('upload_url') != endpoint + '{?name,label}'):
            raise ValueError('backend DATA release differs from its original content identity')
        assets, ids = {}, set()
        for asset in pages(prefix + f'/releases/{release_id}/assets', None, fetch):
            name, asset_id = asset.get('name'), asset.get('id')
            pin = expected.get(name)
            if (pin is None or name in assets or type(asset_id) is not int or asset_id < 1 or asset_id in ids
                    or asset.get('state') != 'uploaded' or asset.get('size') != pin['bytes']
                    or asset.get('digest') != 'sha256:' + pin['sha256']
                    or asset.get('browser_download_url') != data_part_url(location, name)):
                raise ValueError('backend DATA release asset differs from the exact part roster')
            assets[name] = asset_id
            ids.add(asset_id)
        return current, assets, endpoint

    if release is None:
        if lookup(prefix + '/git/ref/tags/' + tag) is not None:
            raise ValueError('backend DATA tag already exists without its owned release')
        created = json.loads(mutate(['api', '--method', 'POST', prefix + '/git/refs',
                                     '-f', 'ref=refs/tags/' + tag, '-f', 'sha=' + source]))
        if (created.get('ref') != 'refs/tags/' + tag or created.get('object', {}).get('type') != 'commit'
                or created['object'].get('sha') != source):
            raise ValueError('backend DATA tag creation returned a different identity')
        check_tag(source)
        release = owned_input_draft(LOCAL_RELEASE_REPO, tag, source, identity, title,
                                    fetch=fetch, mutate=mutate)
    commit = release.get('target_commitish')
    release_id = release.get('id')
    if (not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit)
            or type(release_id) is not int or release_id < 1):
        raise ValueError('backend DATA release lacks its exact original commit and ID')
    current, assets, endpoint = read(release_id, commit)
    if not current['draft'] and set(assets) != set(expected):
        raise ValueError('published backend DATA release omits required parts')
    for name, pin in expected.items():
        if name in assets:
            continue
        if read(release_id, commit)[:2] != (current, assets):
            raise ValueError('backend DATA release changed before upload')
        assert_local_release_file(Path(files[name]).absolute(), pin)
        uploaded = json.loads(mutate(['api', '--method', 'POST', endpoint + '?name=' + name,
                                     '-H', 'Content-Type: application/octet-stream',
                                     '--input', str(Path(files[name]).absolute())], timeout=1200))
        observed, next_assets, _ = read(release_id, commit)
        if (set(next_assets) != set(assets) | {name}
                or any(next_assets[key] != value for key, value in assets.items())
                or next_assets.get(name) != uploaded.get('id') or observed['draft'] is not True):
            raise ValueError('backend DATA upload readback differs')
        current, assets = observed, next_assets
    if current['draft']:
        if read(release_id, commit)[:2] != (current, assets):
            raise ValueError('backend DATA release changed before publication')
        mutate(['api', '--method', 'PATCH', prefix + '/releases/' + str(release_id),
                '-F', 'draft=false', '-F', 'prerelease=true', '-f', 'make_latest=false'])
    final, final_assets, _ = read(release_id, commit)
    if final['draft'] or final_assets != assets:
        raise ValueError('backend DATA publication readback differs')
    proof = _app_assets.verify_data_release(row, fetch)
    if read_url is None:
        from urllib.request import urlopen
        read_url = lambda url: urlopen(url, timeout=120)
    for name, part in expected.items():
        with read_url(data_part_url(location, name)) as reader:
            checksum=hashlib.sha256();size=0
            while raw:=reader.read(1<<20):
                size+=len(raw)
                if size>part['bytes']:raise ValueError('published backend DATA URL exceeds its exact part size')
                checksum.update(raw)
            if (size,checksum.hexdigest())!=(part['bytes'],part['sha256']):
                raise ValueError('published backend DATA URL bytes differ: '+name)
    if _app_assets.verify_data_release(row, fetch)!=proof:
        raise ValueError('backend DATA release changed during URL readback')
    return dict(proof, parts=[dict(expected[name], url=data_part_url(location, name)) for name in sorted(expected)])


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
            or run.get('status') != 'completed' or run.get('conclusion') != 'success'
            or type(run.get('run_attempt')) is not int or run['run_attempt'] < 1):
        raise ValueError('candidate must be a successful manual candidate.yml run in this repository at the exact dispatch commit')
    names = [job.get('name') for job in jobs]
    if (any(not isinstance(name,str) or not name for name in names)
            or not REQUIRED_JOBS.issubset(names) or len(names) != len(set(names))):
        raise ValueError('candidate is missing required jobs or has ambiguous job names')
    for job in jobs:
        if job.get('head_sha') != source or job.get('status') != 'completed':
            raise ValueError('candidate job did not pass: ' + str(job.get('name')))
        if job.get('conclusion') == 'skipped' and job.get('name') not in REQUIRED_JOBS:
            continue
        if job.get('conclusion') != 'success':
            raise ValueError('candidate job did not pass: ' + str(job.get('name')))


def run_artifact(name, source, artifacts, *, run_id=None):
    """The one retained artifact of exactly this name, with a digest and the
    candidate's source as its provenance."""
    found = [a for a in artifacts if a.get('name') == name]
    if len(found) != 1 or found[0].get('expired') is not False:
        raise ValueError(name + ' is missing, ambiguous or expired; rebuild and qualify a new candidate')
    artifact = found[0]
    if type(artifact.get('id')) is not int or artifact['id'] < 1:
        raise ValueError('GitHub artifact has no positive exact ID: ' + name)
    if not isinstance(artifact.get('digest'),str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact['digest']):
        raise ValueError('GitHub artifact has no SHA-256 digest: ' + name)
    provenance = artifact.get('workflow_run')
    if (not isinstance(provenance,dict) or provenance.get('head_sha') != source
            or (run_id is not None and (type(provenance.get('id')) is not int or provenance['id'] != run_id))):
        raise ValueError('artifact provenance differs from candidate source: ' + name)
    return artifact


def producer_attempt(run, jobs, job_name):
    """Use the exact successful producer record selected by inspect's paging."""
    selected = [job for job in jobs if job.get('name') == job_name]
    if len(selected) != 1:
        raise ValueError('missing or ambiguous artifact producer job: ' + job_name)
    job = selected[0]
    attempt = job.get('run_attempt')
    if (job.get('head_sha') != run['head_sha'] or type(job.get('run_id')) is not int or job['run_id'] != run['id']
            or job.get('status') != 'completed' or job.get('conclusion') != 'success'
            or type(attempt) is not int or not 1 <= attempt <= run['run_attempt']):
        raise ValueError('artifact producer differs from exact run/source/attempt: ' + job_name)
    return attempt


def verified_artifact(repo, run_id, source, run, jobs, artifacts):
    candidate_run(repo, run_id, source, run, jobs)
    attempt = producer_attempt(run, jobs, 'draft')
    return run_artifact(f'verified-release-{attempt}', source, artifacts, run_id=run_id)


def setup_artifact(repo, run_id, source, run, jobs, artifacts):
    """The signed Setup bundle of its successful producer attempt, by exact name,
    under the same run and job checks as the verified release."""
    candidate_run(repo, run_id, source, run, jobs)
    attempt = producer_attempt(run, jobs, 'windows-bundle-sign')
    return run_artifact(f'{SETUP_ARTIFACT}{attempt}', source, artifacts, run_id=run_id)


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


def setup_catalog_files(archive, receipt, version, run):
    """Bind the Catalog MSI, external chain MSIs and private inventory."""
    def metadata(name, limit):
        if name not in archive.namelist() or archive.getinfo(name).file_size > limit:
            raise ValueError('Setup Catalog metadata is missing or too large: ' + name)
        return json.loads(archive.read(name))

    proof = receipt['catalog_opencode']
    context = metadata('app-chain-context.json', 8 << 20)
    signer = windows_signing_owner()
    owner = signer.bundle_owner()
    distribution = owner.read_chain_context(metadata(signer.APP_DISTRIBUTION_CHAIN, 1 << 20), Path('.'))
    physical = owner.read_chain_context(receipt['chain_context'], Path('.'))
    if owner.burn_chain(distribution) != physical or distribution['version'] != version[1:]:
        raise ValueError('Setup Catalog roster differs from its exact physical chain')
    expected_chain = [(role, Path(member['file']).name, member['sha256'], member['bytes'])
                      for role, _, member, _ in owner.chain_packages(physical)]
    rows = receipt['chain']
    if rows[0].get('id') == 'BeginCoreUpgrade':
        if rows[0].get('name') != 'openabstractions.exe' or rows[0].get('role') != 'upgrade-supervisor':
            raise ValueError('Setup Catalog has an unexpected upgrade supervisor')
        rows = rows[1:]
    if [(row.get('id'), row.get('name'), row.get('sha256'), row.get('bytes')) for row in rows] != expected_chain:
        raise ValueError('Setup Catalog receipt differs from its physical chain')
    if (not run or type(context.get('run_attempt')) is not int
            or not 1 <= context['run_attempt'] <= run['run_attempt']
            or context.get('source') != run['head_sha'] or context.get('run_id') != run['id']
            or context.get('version') != version[1:]
            or any(proof.get(key) != context[key] for key in ('source', 'run_id', 'run_attempt'))):
        raise ValueError('Setup Catalog source or run differs from the promoted candidate')
    apps = [app for app in distribution['apps'] if app['id'] == owner.CATALOG_ONLY_APP]
    if len(apps) != 1:
        raise ValueError('Setup Catalog requires one exact application package')
    app = apps[0]
    signer.producer_hosts(dict(distribution, apps=apps), {'opencode': context['expected_producers']['opencode']},
                          source=proof['source'], run_id=proof['run_id'], run_attempt=proof['run_attempt'])
    name = 'opencode-' + version[1:] + '.msi'
    package = proof['package']
    preflight = app['host']['preflight']
    if (package.get('name') != name or Path(app['file']).name != name or package.get('version') != version[1:]
            or package.get('upgrade_code') != '{8E0B8005-0E00-5720-9556-E5B984F15A96}'
            or not re.fullmatch(r'\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\}', str(package.get('product_code')))):
        raise ValueError('Setup Catalog MSI identity differs')
    for observed, expected in ((proof['signature'], app), (package, app), (proof['preflight'], preflight)):
        if (observed.get('name') != Path(expected['file']).name
                or any(observed.get(key) != expected[key] for key in ('sha256', 'bytes'))):
            raise ValueError('Setup Catalog signed file differs from the admitted pin')
    windows_signature_proof({'schema': 1, 'result': 'pass', 'policy_sha256': receipt['policy_sha256'],
                             'files': [proof['signature'], proof['preflight']]})
    pin = lambda row: (row['sha256'], row['bytes'])
    files = {Path(member['file']).name: pin(member)
             for _, _, member, app in owner.chain_packages(distribution) if app is not None}
    for binding in context['expected_producers'].values():
        if 'delivery' in binding:
            delivery = binding['delivery']
            for member in (delivery['binary'], *delivery['source']['parts']):
                member_name = delivery['directory'] + '/' + member['name']
                if member_name in files:
                    raise ValueError('duplicate Setup Catalog distribution member')
                files[member_name] = pin(member)
    files.update({signer.APP_DISTRIBUTION_CHAIN: None, 'app-chain-context.json': None})
    # Physical application MSIs are uncompressed Burn payloads carried beside Setup.
    external_msis = {Path(package['file']).name
                     for _, kind, package, app in owner.chain_packages(physical)
                     if app is not None and kind == 'MsiPackage'}
    return name, files, external_msis


def unpack_setup(blob, digest, destination, version, packages, *, receipt_sink=None, run=None):
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
        names = [item.filename for item in entries if not item.is_dir()]
        directories = {item.filename.rstrip('/') for item in entries if item.is_dir()}
        if len(entries) != len({item.filename.rstrip('/').casefold() for item in entries}):
            raise ValueError('duplicate Setup artifact entries')
        for item in entries:
            kind = (item.external_attr >> 16) & 0o170000
            if ('\\' in item.filename or ':' in item.filename
                    or any(part in ('', '.', '..') for part in item.filename.rstrip('/').split('/'))
                    or kind not in (0, 0o040000 if item.is_dir() else 0o100000)
                    or (item.is_dir() and item.file_size)):
                raise ValueError('Setup artifact contains an unsafe file or directory')
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
        split = 'catalog_opencode' in receipt
        if split:
            catalog, internal, external_msis = setup_catalog_files(archive, receipt, version, run)
            cores = [row for row in chain if (row.get('id'), row.get('name')) == SETUP_CORE]
            if len(cores) != 1:
                raise ValueError('the Setup receipt lacks exactly one core MSI')
            core = cores[0]
        else:
            internal = {}
            core = chain[0]
        windows_signature_proof({'schema': 1, 'result': 'pass', 'policy_sha256': receipt.get('policy_sha256'),
                                 'files': [entry.get('signature', {}) for entry in chain]})
        if any(entry['signature'].get('sha256') != entry.get('sha256')
               or entry['signature'].get('bytes') != entry.get('bytes') for entry in chain):
            raise ValueError('Setup chain signature proof differs from signed MSI pins')
        if (core.get('id'), core.get('name')) != SETUP_CORE or core.get('sha256') != packages.get(SETUP_CORE[1]):
            raise ValueError('the Setup bundle does not carry this release\'s abstraction-x64.msi')
        published = {exe: (bundle.get('sha256'), bundle.get('bytes'))}
        if split:
            if catalog in packages:
                raise ValueError('Setup Catalog MSI collides with a verified release package')
            published[catalog] = internal.pop(catalog)
        for entry in chain[1:]:
            name = entry.get('name')
            if split and name not in external_msis:
                continue
            if (not isinstance(name, str)
                    or (not split and not re.fullmatch(
                        r'[a-z0-9][a-z0-9_-]{0,63}-' + re.escape(version[1:]) + r'\.msi', name))
                    or name in published or name in packages):
                raise ValueError('Setup receipt names an unexpected application package')
            published[name] = (entry.get('sha256'), entry.get('bytes'))
            if split and internal.pop(name, None) != published[name]:
                raise ValueError('Setup external MSI differs from its admitted distribution pin')
        if set(names) != set(published) | set(internal) | {SETUP_RECEIPT, SETUP_SUMS}:
            raise ValueError('Setup artifact file set differs from its receipt')
        if directories - {parent.as_posix() for name in internal for parent in PurePosixPath(name).parents
                          if parent != PurePosixPath('.')}:
            raise ValueError('Setup artifact directory set differs from its receipt')
        checksums = {}
        for line in archive.read(SETUP_SUMS).decode('utf-8').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64}) [ *](\S+)', line)
            if not match or match[2] in checksums:
                raise ValueError('malformed or duplicate Setup checksum')
            checksums[match[2]] = match[1]
        if set(checksums) != set(published) | set(internal) | {SETUP_RECEIPT}:
            raise ValueError('Setup checksum file does not cover exactly the bundle, its packages and receipt')
        for name in checksums:
            size, checksum = measured(lambda: archive.open(name))
            if checksum != checksums[name]:
                raise ValueError('Setup checksum mismatch: ' + name)
            if name in published and published[name] != (checksum, size):
                raise ValueError('Setup receipt differs from the file: ' + name)
            if name in internal and internal[name] is not None and internal[name] != (checksum, size):
                raise ValueError('Setup internal member differs from the admitted file: ' + name)
            if size >= MAX_RELEASE_ASSET_BYTES:
                raise ValueError('release asset must be under 2 GiB: ' + name)
        for name in published:
            with archive.open(name) as source, (destination / name).open('wb') as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
    if receipt_sink is not None:
        receipt_sink.update(receipt)
    return list(published), {name: checksums[name] for name in published}


def unpack_verified(blob, digest, destination, run, version, *, producer_attempt=None):
    attempt = run['run_attempt'] if producer_attempt is None else producer_attempt
    if type(attempt) is not int or not 1 <= attempt <= run['run_attempt']:
        raise ValueError('verified release producer attempt is outside the exact run')
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
            limit = 16 << 20 if name == 'candidate.json' else 1 << 20
            if archive.getinfo(name).file_size > limit:
                raise ValueError('verified release metadata is too large: ' + name)
        metadata = json.loads(archive.read('candidate.json'))
        expected = {'schema': 1, 'source': run['head_sha'], 'version': version,
                    'run_id': run['id'], 'run_attempt': attempt}
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
            packages.add(runtime_release_asset(archive, version))
            packages.update(pytorch_release_assets(archive, version))
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
            raise ValueError("owned input draft is missing and creation is not admitted")
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
    """Create or resume one owned draft containing only the retained input roster."""
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
    if engine.SOURCE_NAME in engine.INPUT_PINS and engine.measured(directory / engine.SOURCE_NAME) != (
            engine.INPUT_PINS[engine.SOURCE_NAME]['size_bytes'], engine.INPUT_PINS[engine.SOURCE_NAME]['sha256']):
        raise ValueError('retained PyTorch source archive differs')
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


PRIOR_REPOSITORY = 'openabstractions/redist'
PRIOR_DRAFT_OWNER = 'ReinisLusis'


def require_fixed_prior_volume(path):
    if os.name != 'nt':
        return
    import ctypes
    drive_type = ctypes.WinDLL('kernel32.dll', winmode=0x800).GetDriveTypeW
    drive_type.argtypes = (ctypes.c_wchar_p,)
    drive_type.restype = ctypes.c_uint
    if drive_type(path.anchor) != 3:  # DRIVE_FIXED
        raise ValueError('installer predecessor evidence requires a fixed local Windows volume')


def stage_installer_priors(archives, evidence_root, source, draft_target, authority, *, fetch,
                           optional_fetch, mutate, get):
    """Stage reviewed archives. The owner keeps this release ID unpublished during upload."""
    if source == draft_target or any(not re.fullmatch(r'[0-9a-f]{40}', value) for value in (source, draft_target)):
        raise ValueError('predecessor staging requires distinct exact private source and redist target commits')
    if authority.get('schema') != 1 or authority.get('version') != '0.8.0' or len(archives) != 2 or len(authority['priors']) != 2:
        raise ValueError('predecessor staging requires two ordered original archives')
    windows = windows_signing_owner()
    receiver = pytorch_inputs_module()

    def local_path(value, kind):
        path = Path(value)
        if (not path.is_absolute() or '..' in path.parts or str(path).startswith(('\\\\', '//'))
                or os.name == 'nt' and not re.fullmatch(r'[A-Za-z]:', path.drive)):
            raise ValueError('installer predecessor evidence requires an absolute local path')
        require_fixed_prior_volume(path)
        return windows.file_boundary.ordinary_path(path, kind=kind)

    evidence_root = local_path(evidence_root, 'directory')

    def admit_archive(value):
        path = local_path(value, 'file')
        try:
            windows.file_boundary.relative_beneath_existing(path, evidence_root)
        except windows.file_boundary.OutsideRoot as error:
            raise ValueError('installer predecessor archive is outside the declared evidence root') from error
        return path

    paths = []
    for archive in archives:
        if (not isinstance(archive, dict) or set(archive) != {'path', 'bytes', 'sha256'}
                or type(archive['bytes']) is not int or not 0 < archive['bytes'] <= 512 << 20
                or not re.fullmatch(r'[0-9a-f]{64}', str(archive['sha256']))):
            raise ValueError('installer predecessor requires exact reviewed archive pins')
        paths.append(admit_archive(archive['path']))
    if len(set(paths)) != 2:
        raise ValueError('predecessor archives require two distinct local files')
    names = ['installer-prior-1.zip', 'installer-prior-2.zip']
    prefix = 'repos/' + PRIOR_REPOSITORY
    with tempfile.TemporaryDirectory(prefix='oa-prior-stage-', dir=evidence_root) as temporary:
        directory = local_path(temporary, 'directory')
        uploads, readback = directory / 'uploads', directory / 'readback'
        uploads.mkdir()
        readback.mkdir()
        pins = {}
        rows = dict(zip(names, authority['priors']))
        for path, name, approved in zip(paths, names, archives):
            pin = {key: approved[key] for key in ('bytes', 'sha256')}
            staged = uploads / name
            with path.open('rb') as original, staged.open('xb') as target:
                held = os.fstat(original.fileno())
                if held.st_nlink != 1 or held.st_size != pin['bytes']:
                    raise ValueError('installer predecessor archive size or link differs from reviewed input')
                remaining = held.st_size
                while remaining:
                    chunk = original.read(min(remaining, 1 << 20))
                    if not chunk:
                        raise ValueError('installer predecessor archive shrank during staging')
                    target.write(chunk)
                    remaining -= len(chunk)
                if original.read(1):
                    raise ValueError('installer predecessor archive grew during staging')
            if measured(lambda: staged.open('rb')) != (pin['bytes'], pin['sha256']):
                raise ValueError('installer predecessor archive differs from its reviewed digest')
            windows.installer_prior_members(staged, dict(rows[name], asset=pin))
            pins[name] = pin
        identity = {'purpose': 'installer-predecessor-inputs', 'draft_target': draft_target,
                    'version': authority['version'],
                    'priors': [dict(rows[name], name=name, **pins[name]) for name in names]}
        body = json.dumps(identity, sort_keys=True) + '\n'
        draft_key = hashlib.sha256(body.encode('utf-8')).hexdigest()
        tag = 'oa-installer-priors-' + draft_key
        ref = prefix + '/git/ref/tags/' + tag
        title = 'Installer predecessor inputs ' + draft_key[:12]

        def require_no_ref():
            if optional_fetch(ref) is not None:
                raise ValueError('installer predecessor staging requires an absent Git ref')

        def recheck_local():
            local_path(evidence_root, 'directory')
            for path, name in zip(paths, names):
                admit_archive(path)
                pin = pins[name]
                if path.stat().st_nlink != 1 or measured(lambda: path.open('rb')) != (pin['bytes'], pin['sha256']):
                    raise ValueError('original installer predecessor archive changed: ' + path.name)

        recheck_local()
        actor = fetch('user')
        if (not isinstance(actor, dict) or actor.get('login') != PRIOR_DRAFT_OWNER
                or type(actor.get('id')) is not int or actor['id'] < 1):
            raise ValueError('installer predecessor staging requires its authenticated draft owner')
        commit = fetch(prefix + '/commits/' + draft_target)
        if not isinstance(commit, dict) or commit.get('sha') != draft_target:
            raise ValueError('installer predecessor redist target differs')
        require_no_ref()
        release = owned_input_draft(PRIOR_REPOSITORY, tag, draft_target, identity, title,
                                    fetch=fetch, mutate=mutate)
        release_id = release['id']
        endpoint = f'https://uploads.github.com/{prefix}/releases/{release_id}/assets'

        def selected_assets(release):
            if not isinstance(release, dict):
                raise ValueError('installer predecessor draft readback is malformed')
            author = release.get('author', {})
            if (release.get('id') != release_id or release.get('draft') is not True
                    or release.get('prerelease') is not True or release.get('published_at') is not None
                    or release.get('immutable') is not False or release.get('tag_name') != tag
                    or release.get('target_commitish') != draft_target or release.get('name') != title
                    or release.get('body', '').replace('\r\n', '\n') != body
                    or not isinstance(author, dict) or author.get('login') != PRIOR_DRAFT_OWNER
                    or author.get('id') != actor['id']
                    or release.get('upload_url') != endpoint + '{?name,label}'
                    or not isinstance(release.get('assets'), list)):
                raise ValueError('installer predecessor draft identity differs')
            selected, ids = {}, set()
            for asset in release['assets']:
                if not isinstance(asset, dict):
                    raise ValueError('installer predecessor draft asset is malformed')
                name = asset.get('name')
                if (not isinstance(name, str) or name not in pins or name in selected
                        or type(asset.get('id')) is not int
                        or asset['id'] < 1 or asset['id'] in ids or asset.get('state') != 'uploaded'
                        or asset.get('size') != pins[name]['bytes']
                        or asset.get('digest') != 'sha256:' + pins[name]['sha256']):
                    raise ValueError('installer predecessor draft asset differs')
                ids.add(asset['id'])
                selected[name] = {'repository': PRIOR_REPOSITORY, 'release_id': release_id,
                                  'id': asset['id'], 'name': name, **pins[name]}
            return selected

        def current_assets():
            return selected_assets(fetch(prefix + '/releases/' + str(release_id)))

        def receive(assets):
            if not assets:
                return
            selected = {name: dict(id=asset['id'], name=name, size_bytes=asset['bytes'],
                                   sha256=asset['sha256']) for name, asset in assets.items()}
            receiver.receive_assets(readback, PRIOR_REPOSITORY, selected, fetch=fetch, download=get, created=[])
            for name, asset in assets.items():
                windows.installer_prior_members(readback / name, dict(rows[name], asset=asset))

        assets = selected_assets(release)
        if current_assets() != assets:
            raise ValueError('installer predecessor draft changed during admission')
        receive(assets)
        for name in names:
            if name in assets:
                continue
            require_no_ref()
            if current_assets() != assets:
                raise ValueError('installer predecessor draft changed before upload')
            staged = local_path(uploads / name, 'file')
            pin = pins[name]
            if staged.stat().st_nlink != 1 or measured(lambda: staged.open('rb')) != (pin['bytes'], pin['sha256']):
                raise ValueError('installer predecessor staged archive changed before upload')
            # Exact release ID and fixed host; a same-name upload cannot replace bytes.
            mutate(['api', '--method', 'POST', endpoint + '?name=' + name, '-H',
                    'Content-Type: application/zip', '--input', str(staged)], timeout=1200)
            observed = current_assets()
            if set(observed) != set(assets) | {name} or any(observed[key] != pin for key, pin in assets.items()):
                raise ValueError('installer predecessor upload readback differs')
            receive({name: observed[name]})
            assets = observed
        recheck_local()
        final = owned_input_draft(PRIOR_REPOSITORY, tag, draft_target, identity, title,
                                  fetch=fetch, mutate=mutate, allow_create=False)
        if selected_assets(final) != assets or current_assets() != assets:
            raise ValueError('installer predecessor final draft readback differs')
        require_no_ref()
        descriptor = {'schema': 1, 'source': source, 'version': authority['version'],
                      'priors': [dict(rows[name], asset=assets[name]) for name in names]}
        windows.installer_prior_descriptor(descriptor, authority=authority)
        return {'descriptor': descriptor, 'archives': [dict(path=str(path), **pins[name])
                                                       for path, name in zip(paths, names)]}


def stage_installer_priors_main(argv):
    parser = argparse.ArgumentParser(
        description='Stage the exact predecessor pair in its owned unpublished redist draft.',
        epilog='Keep this release ID unpublished throughout staging. GitHub has no conditional '
               'upload that enforces draft state for an already selected release ID.')
    parser.add_argument('--source-root', type=Path, required=True, help='clean exact private Source checkout')
    parser.add_argument('--source', required=True, help='exact private Source SHA for the local descriptor')
    parser.add_argument('--draft-target', required=True, help='existing exact redist commit for the draft')
    parser.add_argument('--evidence-root', type=Path, required=True, help='ordinary local archive directory')
    parser.add_argument('--archive', nargs=3, metavar=('PATH', 'BYTES', 'SHA256'), action='append',
                        required=True, help='reviewed original archive pin in authority order')
    parser.add_argument('--approve-draft-staging', action='store_true', required=True)
    args = parser.parse_args(argv)
    try:
        archives = [dict(path=path, bytes=int(size), sha256=sha256) for path, size, sha256 in args.archive]
    except ValueError:
        parser.error('archive size must be an integer')
    checkout = args.source_root.resolve()
    git = ['git', '-C', str(checkout)]
    top = subprocess.check_output([*git, 'rev-parse', '--show-toplevel'], text=True, timeout=30).strip()
    head = subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True, timeout=30).strip()
    dirty = subprocess.check_output([*git, 'status', '--porcelain=v1', '--untracked-files=all'],
                                    text=True, timeout=30).strip()
    if Path(top).resolve() != checkout or head != args.source or dirty:
        parser.error('predecessor staging requires the clean exact private Source checkout')
    authority = json.loads(subprocess.check_output(
        [*git, 'show', 'HEAD:installer/installer-prior-authorities.json'], timeout=30))
    github = 'https://api.github.com/'

    def mutate(argv, **kwargs):
        endpoint = argv[3] if argv[3].startswith('https://') else github + argv[3]
        return command([*argv[:3], endpoint, *argv[4:], '--hostname', 'github.com'], **kwargs)

    def get(argv, path):
        download([*argv[:-1], github + argv[-1], '--hostname', 'github.com'], path)

    result = stage_installer_priors(archives, args.evidence_root, args.source, args.draft_target, authority,
                                   fetch=lambda path: api(github + path),
                                   optional_fetch=lambda path: optional_api(github + path),
                                   mutate=mutate, get=get)
    print(json.dumps(result, sort_keys=True))
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
    if internal[:1] == ['stage-installer-priors']:
        return stage_installer_priors_main(internal[1:])
    parser = argparse.ArgumentParser(description=__doc__,
                                     epilog="Draft inputs: seed-pytorch-inputs --help or stage-installer-priors --help.")
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
        assets, metadata = unpack_verified(retained, artifact['digest'], directory, run, args.version,
            producer_attempt=producer_attempt(run, jobs, 'draft'))
        sums = directory / 'SHA256SUMS'
        lines = sums.read_bytes().decode('utf-8').splitlines()
        packages = {line[66:]: line[:64] for line in lines}
        retained_setup = directory / 'setup-artifact.zip'
        download(['api', f'repos/{args.repo}/actions/artifacts/{setup["id"]}/zip'], retained_setup)
        setup_receipt = {}
        setup_assets, setup_sums = unpack_setup(retained_setup, setup['digest'], directory, args.version, packages, receipt_sink=setup_receipt, run=run)
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
                     *[str(directory / name) for name in assets]], timeout=7200)
    print(f'Drafted {args.version} from verified run {args.run}; packages were not rebuilt.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, subprocess.TimeoutExpired) as exc:
        print('REFUSED: ' + str(exc), file=sys.stderr)
        sys.exit(1)
