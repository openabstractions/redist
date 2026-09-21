"""Inspect a packaging candidate or draft its exact verified artifacts.

--status is read-only. Promotion requires the successful candidate's exact
redist commit, version and run ID. No compiler, installer or package builder is
invoked. Authentication uses the existing gh environment.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

REQUIRED_JOBS = {'candidate', 'windows', 'verify', 'linux', 'linux-verify', 'macos', 'draft'}


def command(args):
    result = subprocess.run(['gh', *args], capture_output=True, timeout=120)
    if result.returncode:
        raise ValueError(result.stderr.decode('utf-8', errors='replace').strip())
    return result.stdout


def api(path):
    return json.loads(command(['api', path]))


def optional_api(path):
    try:
        return api(path)
    except ValueError as exc:
        if '(HTTP 404)' in str(exc):
            return None
        raise


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


def verified_artifact(repo, run_id, source, run, jobs, artifacts):
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
        if (job.get('head_sha') != source or job.get('status') != 'completed'
                or job.get('conclusion') != 'success'):
            raise ValueError('candidate job did not pass: ' + str(job.get('name')))
    name = f'verified-release-{run["run_attempt"]}'
    found = [a for a in artifacts if a.get('name') == name]
    if len(found) != 1 or found[0].get('expired') is not False:
        raise ValueError('verified artifact is missing, ambiguous or expired; rebuild and qualify a new candidate')
    artifact = found[0]
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', '')):
        raise ValueError('GitHub artifact has no SHA-256 digest')
    if artifact.get('workflow_run', {}).get('head_sha') != source:
        raise ValueError('artifact provenance differs from candidate source')
    return artifact


def unpack_verified(blob, digest, destination, run, version):
    if 'sha256:' + hashlib.sha256(blob).hexdigest() != digest:
        raise ValueError('downloaded artifact digest differs from GitHub')
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]
        if len(names) != len(set(names)):
            raise ValueError('duplicate artifact entries')
        for item in entries:
            if (item.is_dir() or '/' in item.filename or '\\' in item.filename
                    or item.filename in ('.', '..')
                    or (item.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError('artifact entries must be ordinary root-level files')
        metadata = json.loads(archive.read('candidate.json'))
        expected = {'schema': 1, 'source': run['head_sha'], 'version': version,
                    'run_id': run['id'], 'run_attempt': run['run_attempt']}
        if any(metadata.get(k) != value for k, value in expected.items()):
            raise ValueError('artifact metadata differs from requested candidate')
        if not isinstance(metadata.get('preview'), bool) or metadata.get('macos') not in ('signed', 'unsigned', 'partial'):
            raise ValueError('candidate is missing explicit preview/signing state')
        number = version[1:]
        packages = {'abstraction-x64.msi', 'abstraction-arm64.msi',
                    f'abstraction-{number}-linux-amd64.tar.gz', f'abstraction-{number}-linux-arm64.tar.gz'}
        if metadata['macos'] == 'signed':
            packages.add(f'abstraction-{number}-macos-universal.pkg')
        if set(names) != packages | {'candidate.json', 'NOTES.md', 'SHA256SUMS'}:
            raise ValueError('artifact file set differs from declared packages')
        checksums = {}
        for line in archive.read('SHA256SUMS').decode('utf-8').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64}) [ *](\S+)', line)
            if not match or match[2] in checksums:
                raise ValueError('malformed or duplicate package checksum')
            checksums[match[2]] = match[1]
        if set(checksums) != packages:
            raise ValueError('checksum file does not cover exactly the packages')
        for name, checksum in checksums.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != checksum:
                raise ValueError('package checksum mismatch: ' + name)
        if not archive.read('NOTES.md').strip():
            raise ValueError('release notes are empty')
        for name in names:
            (destination / name).write_bytes(archive.read(name))
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
        print('Next: inspect failed logs; for a transient failure with unchanged inputs, retry failed jobs once:')
        print(f'  gh run rerun {run_id} --failed -R {repo}')
        print('A source/workflow fix needs a new candidate; preserve this failed run.')
    else:
        try:
            verified_artifact(repo, run_id, run['head_sha'], run, jobs, artifacts)
        except ValueError as exc:
            print('Promotion unavailable: ' + str(exc))
        else:
            print('Next: dispatch release.yml from this same branch commit with candidate_run=' + str(run_id)
                  + ' and the candidate version. Promotion downloads these artifacts without rebuilding.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default=os.environ.get('GH_REPO', 'openabstractions/redist'))
    parser.add_argument('--run', type=int, required=True, help='exact candidate workflow run ID')
    parser.add_argument('--status', action='store_true', help='read-only run, job, retained artifact and next-action summary')
    parser.add_argument('--version', help='vMAJOR.MINOR.PATCH of the verified packages')
    parser.add_argument('--source', help='exact redist commit running the promotion workflow')
    parser.add_argument('--resume', action='store_true', help='recover a partial promotion at the same tag/commit; verify existing draft assets and upload only missing files')
    args = parser.parse_args(argv)
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
    blob = command(['api', f'repos/{args.repo}/actions/artifacts/{artifact["id"]}/zip'])
    with tempfile.TemporaryDirectory(prefix='oa-promotion-') as tmp:
        directory = Path(tmp)
        assets, metadata = unpack_verified(blob, artifact['digest'], directory, run, args.version)
        notes = directory / 'NOTES.md'
        body = notes.read_text(encoding='utf-8') + f'\n\nVerified candidate: https://github.com/{args.repo}/actions/runs/{args.run}\n'
        notes.write_text(body, encoding='utf-8')
        # Create-only refs preserve existing tags. A failed lookup cannot authorize
        # mutation; the API refuses concurrent or existing tags atomically.
        release = None
        if args.resume:
            tag = api(f'repos/{args.repo}/git/ref/tags/{args.version}')
            if tag.get('object', {}).get('type') != 'commit' or tag['object'].get('sha') != args.source:
                raise ValueError('resume requires the existing tag to point directly to the verified commit')
            release = optional_api(f'repos/{args.repo}/releases/tags/{args.version}')
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
                data = command(['api', '-H', 'Accept: application/octet-stream',
                                f'repos/{args.repo}/releases/assets/{item["id"]}'])
                if data != (directory / item['name']).read_bytes():
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
