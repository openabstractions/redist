"""Public synthetic draft-to-Actions transport canary; never a release admission.

prepare writes fixed public bytes. seed requires explicit staging effect approval.
intake/readback execute only in the genuine narrow-token canary workflow.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import zipfile

import promote

REPOSITORY = 'openabstractions/redist'
WORKFLOW = '.github/workflows/transport-canary.yml'
BRANCH = 'release/transport-canary-962'
CAPSULE = 'transport962-capsule.zip'
MANIFEST = 'transport962-manifest.json'
RECEIPT = 'transport962-intake.json'
TEXT = b'OpenAbstractions public staging transport canary.\nThis file contains synthetic public text only.\n'
PINS = {
    CAPSULE: {'size_bytes': 215, 'sha256': 'bb304ebe1b1f88625093d73602ae8577f4ab919f46b66e572085cb18fbf2f1e9'},
    MANIFEST: {'size_bytes': 182, 'sha256': '84b80f2fad361101f40b3e52906fba254f987a69ea220e88d743e6a4c23db82e'},
}


def engine():
    return promote.pytorch_inputs_module()


def identity(source):
    if not isinstance(source, str) or not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('canary source must be an exact public commit')
    return {'schema': 1, 'purpose': 'public-staging-transport-canary',
            'source': source, 'files': PINS}


def tag(source):
    identity(source)
    return 'oa-transport-canary-962-' + source


def prepare(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    info = zipfile.ZipInfo('README.txt', date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type, info.create_system, info.external_attr = zipfile.ZIP_STORED, 3, 0o100644 << 16
    with zipfile.ZipFile(output / CAPSULE, 'w') as archive:
        archive.writestr(info, TEXT)
    value = {'schema': 1, 'purpose': 'public-staging-transport-canary', 'files': [
        {'path': 'README.txt', 'size_bytes': len(TEXT), 'sha256': hashlib.sha256(TEXT).hexdigest()}]}
    # Retain the exact reviewed Windows-produced 182 bytes on every runner.
    (output / MANIFEST).write_bytes((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\r\n').encode())
    verify_bytes(output)


def verify_bytes(directory):
    for name, pin in PINS.items():
        path = Path(directory) / name
        if path.is_symlink() or engine().measured(path) != (pin['size_bytes'], pin['sha256']):
            raise ValueError('canary bytes differ: ' + name)
    with zipfile.ZipFile(Path(directory) / CAPSULE) as archive:
        if archive.namelist() != ['README.txt'] or archive.read('README.txt') != TEXT:
            raise ValueError('canary member roster differs')


def assets(release, source, release_id=None):
    body = json.dumps(identity(source), sort_keys=True) + '\n'
    if (not isinstance(release, dict) or type(release.get('id')) is not int or release['id'] < 1
            or release_id is not None and release['id'] != release_id
            or release.get('draft') is not True or release.get('prerelease') is not True
            or release.get('tag_name') != tag(source) or release.get('target_commitish') != source
            or release.get('body', '').replace('\r\n', '\n') != body
            or not isinstance(release.get('assets'), list)):
        raise ValueError('canary draft origin differs')
    selected, ids = {}, set()
    for item in release['assets']:
        name = item.get('name')
        if (name not in PINS or name in selected or type(item.get('id')) is not int
                or item['id'] < 1 or item['id'] in ids or item.get('state') != 'uploaded'
                or item.get('size') != PINS[name]['size_bytes']
                or item.get('digest') != 'sha256:' + PINS[name]['sha256']):
            raise ValueError('canary draft asset differs')
        ids.add(item['id'])
        selected[name] = {'id': item['id'], 'name': name, **PINS[name]}
    return selected


def seed(directory, source, *, fetch=promote.api, optional_fetch=promote.optional_api, mutate=promote.command):
    verify_bytes(directory)
    prefix = 'repos/' + REPOSITORY
    if optional_fetch(prefix + '/git/ref/tags/' + tag(source)) is not None:
        raise ValueError('canary must have no Git tag/ref')
    release = promote.owned_input_draft(REPOSITORY, tag(source), source, identity(source),
        'Public transport canary 962 ' + source[:12], fetch=fetch, mutate=mutate)
    selected = assets(release, source)
    missing = [name for name in PINS if name not in selected]
    if missing:
        mutate(['release', 'upload', tag(source), '--repo', REPOSITORY,
                *[str(Path(directory) / name) for name in missing]])
    release_id = release['id']
    release = fetch(prefix + '/releases/' + str(release_id))
    selected = assets(release, source, release_id)
    if set(selected) != set(PINS):
        raise ValueError('canary seed is incomplete')
    if optional_fetch(prefix + '/git/ref/tags/' + tag(source)) is not None:
        raise ValueError('canary Git ref appeared during seeding')
    return {'source': source, 'repository': REPOSITORY, 'release_id': release['id'], 'assets': selected}


def context(source, run_id, attempt, environment, fetch):
    identity(source)
    if any(type(x) is not int or x < 1 for x in (run_id, attempt)):
        raise ValueError('canary needs exact positive run/attempt')
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_SHA': source,
                'GITHUB_RUN_ID': str(run_id), 'GITHUB_RUN_ATTEMPT': str(attempt),
                'GITHUB_REF': 'refs/heads/' + BRANCH, 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_ACTOR': 'ReinisLusis', 'GITHUB_TRIGGERING_ACTOR': 'ReinisLusis'}
    if any(environment.get(k) != v for k, v in expected.items()):
        raise ValueError('canary requires genuine trusted Actions context')
    run = fetch(f'repos/{REPOSITORY}/actions/runs/{run_id}')
    if (run.get('id') != run_id or run.get('run_attempt') != attempt or run.get('head_sha') != source
            or run.get('path') != WORKFLOW or run.get('event') != 'workflow_dispatch'
            or run.get('head_branch') != BRANCH or run.get('repository', {}).get('full_name') != REPOSITORY
            or run.get('head_repository', {}).get('full_name') != REPOSITORY):
        raise ValueError('canary run identity differs')


def selection(source, release_id, capsule_id, manifest_id, fetch):
    if any(type(x) is not int or x < 1 for x in (release_id, capsule_id, manifest_id)):
        raise ValueError('canary requires exact positive release/asset IDs')
    selected = assets(fetch(f'repos/{REPOSITORY}/releases/{release_id}'), source, release_id)
    if (set(selected) != set(PINS) or selected[CAPSULE]['id'] != capsule_id
            or selected[MANIFEST]['id'] != manifest_id):
        raise ValueError('canary exact asset selection differs')
    return selected


def intake_receipt(source, run_id, attempt, release_id, selected):
    return {'schema': 1, 'purpose': 'public-staging-transport-canary', 'source': source,
            'repository': REPOSITORY, 'workflow': WORKFLOW, 'run_id': run_id, 'run_attempt': attempt,
            'release_id': release_id, 'assets': selected, 'verification': 'exact bytes PASS'}


def intake(output, source, release_id, capsule_id, manifest_id, run_id, attempt, *,
           fetch=promote.api, download=promote.download, environment=None):
    context(source, run_id, attempt, os.environ if environment is None else environment, fetch)
    selected = selection(source, release_id, capsule_id, manifest_id, fetch)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    created = []
    try:
        engine().receive_assets(output, REPOSITORY, selected, fetch=fetch, download=download, created=created)
        verify_bytes(output)
        receipt = intake_receipt(source, run_id, attempt, release_id, selected)
        with (output / RECEIPT).open('xb') as stream:
            created.append(output / RECEIPT)
            stream.write((json.dumps(receipt, sort_keys=True) + '\n').encode())
        return receipt
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        if not any(output.iterdir()): output.rmdir()
        raise


def readback(output, source, release_id, capsule_id, manifest_id, run_id, attempt, artifact_id, *,
             fetch=promote.api, download=promote.download, environment=None):
    context(source, run_id, attempt, os.environ if environment is None else environment, fetch)
    if type(artifact_id) is not int or artifact_id < 1: raise ValueError('invalid exact artifact ID')
    selected = selection(source, release_id, capsule_id, manifest_id, fetch)
    jobs = fetch(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')['jobs']
    passed = [job for job in jobs if job.get('name') == 'intake' and job.get('head_sha') == source
              and job.get('status') == 'completed' and job.get('conclusion') == 'success']
    if len(passed) != 1 or any(not any(step.get('name') == name and step.get('status') == 'completed'
            and step.get('conclusion') == 'success' for step in passed[0].get('steps', []))
            for name in ('intake exact public canary assets', 'upload exact canary bytes')):
        raise ValueError('enabled intake and upload did not both pass')
    artifact = fetch(f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}')
    digest = artifact.get('digest', '')
    if (artifact.get('id') != artifact_id or artifact.get('name') != f'transport962-{attempt}'
            or artifact.get('expired') is not False or type(artifact.get('size_in_bytes')) is not int
            or not 0 < artifact['size_in_bytes'] <= 65536
            or artifact.get('workflow_run', {}).get('id') != run_id
            or artifact.get('workflow_run', {}).get('head_sha') != source
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest)):
        raise ValueError('canary artifact identity differs')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    blob = output / 'artifact.zip'
    download(['api', f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip'], blob)
    if 'sha256:' + engine().measured(blob)[1] != digest:
        raise ValueError('canary artifact archive digest differs')
    with zipfile.ZipFile(blob) as archive:
        if sorted(archive.namelist()) != sorted([*PINS, RECEIPT]):
            raise ValueError('canary artifact member roster differs')
        if any(info.file_size > 16384 for info in archive.infolist()):
            raise ValueError('canary artifact member exceeds bound')
        for name in (*PINS, RECEIPT):
            data = archive.read(name)
            if name in PINS and (len(data), hashlib.sha256(data).hexdigest()) != (PINS[name]['size_bytes'], PINS[name]['sha256']):
                raise ValueError('canary artifact bytes differ')
            (output / name).write_bytes(data)
    expected = intake_receipt(source, run_id, attempt, release_id, selected)
    if (output / RECEIPT).read_bytes() != (json.dumps(expected, sort_keys=True) + '\n').encode():
        raise ValueError('canary artifact intake receipt differs')
    verify_bytes(output)
    result = {**expected, 'artifact_id': artifact_id, 'artifact_digest': digest,
              'verification': 'enabled narrow-token intake/upload/exact readback PASS'}
    (output / 'transport962-readback.json').write_text(json.dumps(result, sort_keys=True) + '\n', encoding='utf-8')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'seed', 'intake', 'readback'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source')
    for name in ('release-id', 'capsule-id', 'manifest-id', 'run-id', 'attempt', 'artifact-id'):
        parser.add_argument('--' + name, type=int)
    args = parser.parse_args(argv)
    if args.operation == 'prepare': prepare(args.output); return 0
    if args.operation == 'seed': result = seed(args.output, args.source)
    else:
        values = [args.output, args.source, args.release_id, args.capsule_id, args.manifest_id, args.run_id, args.attempt]
        result = intake(*values) if args.operation == 'intake' else readback(*values, args.artifact_id)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
