"""Stage the exact qualified native IPC wheels for a separate trusted upload.

This command reads one successful candidate run and downloads its retained
artifacts. It never builds a wheel or uploads to PyPI.
"""
import argparse
import hashlib
import io
from pathlib import Path
import re
import sys
import tempfile
import zipfile

import promote
try:
    import py_wheels
except ModuleNotFoundError:
    # The source copy lives under research/; the split redist has both scripts
    # together. Keep the source copy runnable for local offline checks.
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts'))
    import py_wheels


PLATFORMS = {
    'win32-x64': 'win_amd64',
    'linux-x64': 'manylinux_2_28_x86_64',
    'darwin-arm64': 'macosx_11_0_arm64',
    'darwin-x64': 'macosx_11_0_x86_64',
}


def wheel_artifacts(artifacts, jobs, source, run_id, latest_attempt):
    result = {}
    allowed = re.compile(r'^abstraction-pypi-(?:' + '|'.join(map(re.escape, PLATFORMS)) + r')-[1-9][0-9]*$')
    if any(artifact.get('name', '').startswith('abstraction-pypi-')
           and not allowed.fullmatch(artifact['name']) for artifact in artifacts):
        raise ValueError('candidate has an unknown Python wheel artifact')
    for artifact_id in PLATFORMS:
        pattern = re.compile(r'^python \(' + re.escape(artifact_id) + r'(?:,|\))')
        platform_jobs = [job for job in jobs if pattern.match(job.get('name', ''))]
        if not platform_jobs:
            raise ValueError(f'candidate has no python matrix job for {artifact_id}')
        if any(type(job.get('run_attempt')) is not int or job['run_attempt'] < 1
               for job in platform_jobs):
            raise ValueError(f'python matrix job for {artifact_id} has no valid run attempt')
        attempt = max(job['run_attempt'] for job in platform_jobs)
        current = [job for job in platform_jobs if job['run_attempt'] == attempt]
        if (attempt > latest_attempt or len(current) != 1
                or current[0].get('head_sha') != source
                or current[0].get('status') != 'completed'
                or current[0].get('conclusion') != 'success'):
            raise ValueError(f'latest python matrix job for {artifact_id} is ambiguous or did not pass')
        name = f'abstraction-pypi-{artifact_id}-{attempt}'
        found = [artifact for artifact in artifacts if artifact.get('name') == name]
        if len(found) != 1 or found[0].get('expired') is not False:
            raise ValueError(f'{name} is missing, ambiguous or expired')
        artifact = found[0]
        origin = artifact.get('workflow_run', {})
        if origin.get('head_sha') != source or origin.get('id') != run_id:
            raise ValueError(f'{name} differs from the candidate source')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', '')):
            raise ValueError(f'{name} has no SHA-256 artifact digest')
        result[artifact_id] = artifact
    return result


def unpack_wheel_artifact(blob, artifact, artifact_id, version):
    name = artifact['name']
    if hashlib.sha256(blob).hexdigest() != artifact['digest'][7:]:
        raise ValueError(f'{name} differs from its GitHub artifact digest')
    platform = PLATFORMS[artifact_id]
    wheel_name = f'abstraction_ipc-{version[1:]}-py3-none-{platform}.whl'
    checksum_name = f'SHA256SUMS.pypi.{artifact_id}'
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != 2 or set(names) != {wheel_name, checksum_name}:
            raise ValueError(f'{name} has an unexpected wheel or checksum file set')
        for entry in entries:
            if (entry.is_dir() or '/' in entry.filename or '\\' in entry.filename
                    or (entry.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError(f'{name} contains a non-file or nested path')
        wheel = archive.read(wheel_name)
        checksum = archive.read(checksum_name).decode('ascii')
    expected = hashlib.sha256(wheel).hexdigest()
    if checksum != f'{expected}  {wheel_name}\n':
        raise ValueError(f'{name} wheel checksum differs or is malformed')
    with zipfile.ZipFile(io.BytesIO(wheel)) as wheel_archive:
        metadata_name = f'abstraction_ipc-{version[1:]}.dist-info/METADATA'
        metadata = wheel_archive.read(metadata_name).decode('utf-8')
    fields = {}
    for line in metadata.splitlines():
        for key in ('Name', 'Version'):
            if line.startswith(key + ': '):
                fields.setdefault(key, []).append(line[len(key) + 2:])
    if fields != {'Name': ['abstraction-ipc'], 'Version': [version[1:]]}:
        raise ValueError(f'{name} has unexpected distribution metadata')
    return wheel_name, wheel


def stage(repo, run_id, attempt, source, version, output, inspect=promote.inspect,
          download=promote.command, all_jobs=None):
    run, jobs, artifacts = inspect(repo, run_id)
    if run.get('run_attempt') != attempt:
        raise ValueError('requested attempt differs from the candidate current attempt')
    release = promote.verified_artifact(repo, run_id, source, run, jobs, artifacts)
    # The verified installer artifact carries the run/source/version/attempt
    # metadata. Its own package checksums are checked by this existing reader.
    verified = download(['api', f'repos/{repo}/actions/artifacts/{release["id"]}/zip'])
    with tempfile.TemporaryDirectory(prefix='oa-pypi-candidate-') as tmp:
        _, metadata = promote.unpack_verified(verified, release['digest'], Path(tmp), run, version)
    if metadata['preview']:
        raise ValueError('preview candidate cannot publish Python wheels')
    if all_jobs is None:
        all_jobs = promote.pages(f'repos/{repo}/actions/runs/{run_id}/jobs?filter=all', 'jobs')
    wheel_set = wheel_artifacts(artifacts, all_jobs, source, run_id, attempt)
    staged = {}
    for artifact_id, artifact in wheel_set.items():
        blob = download(['api', f'repos/{repo}/actions/artifacts/{artifact["id"]}/zip'])
        name, wheel = unpack_wheel_artifact(blob, artifact, artifact_id, version)
        staged[name] = (wheel, PLATFORMS[artifact_id])
    if output.exists():
        raise ValueError('output directory already exists')
    output.mkdir(parents=True)
    try:
        for name, (wheel, platform) in staged.items():
            path = output / name
            path.write_bytes(wheel)
            checked_version, checked_platform, _ = py_wheels.check(path)
            if (checked_version, checked_platform) != (version[1:], platform):
                raise ValueError(f'{name} carries unexpected wheel metadata')
    except Exception:
        for path in output.iterdir():
            path.unlink()
        output.rmdir()
        raise
    return sorted(staged)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='openabstractions/redist')
    parser.add_argument('--run', type=int, required=True)
    parser.add_argument('--attempt', type=int, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo)
            or args.run < 1 or args.attempt < 1
            or not re.fullmatch(r'[0-9a-f]{40}', args.source)
            or not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', args.version)):
        parser.error('expected repository, positive run/attempt, full SHA and vMAJOR.MINOR.PATCH')
    names = stage(args.repo, args.run, args.attempt, args.source, args.version, args.output)
    for name in names:
        print(f'verified {name} sha256:{hashlib.sha256((args.output / name).read_bytes()).hexdigest()}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, UnicodeError, zipfile.BadZipFile,
            py_wheels.Refused) as exc:
        print('REFUSED: ' + str(exc), file=sys.stderr)
        sys.exit(1)
