import hashlib, json, os, pathlib, re, shutil, subprocess, zipfile
path = pathlib.Path('dist/ipc-library.json')
receipt = json.loads(path.read_text(encoding='utf-8'))
artifact = receipt.get('artifact', '')
if (receipt.get('schema') != 1 or receipt.get('run_id') != int(os.environ['GITHUB_RUN_ID'])
        or not re.fullmatch(r'abstraction-pypi-win32-x64-[1-9][0-9]*', artifact)
        or not re.fullmatch(r'abstraction_ipc-[A-Za-z0-9_.+-]+-win_amd64\.whl', receipt.get('wheel', ''))
        or receipt.get('member') != 'abstraction/ipc/_native/abstraction_ipc.dll'
        or receipt.get('library') != 'tools/abstraction_ipc.dll'):
    raise SystemExit('FAIL  dist/ipc-library.json does not name a win_amd64 wheel artifact of this run')
folder = pathlib.Path('ipc-wheel')
subprocess.run(['gh', 'run', 'download', os.environ['GITHUB_RUN_ID'], '-n', artifact,
                '-D', str(folder)], check=True)
wheel = folder / receipt['wheel']
if hashlib.sha256(wheel.read_bytes()).hexdigest() != receipt['wheel_sha256']:
    raise SystemExit('FAIL  %s is not the wheel the receipt records' % wheel.name)
sums = (folder / 'SHA256SUMS.pypi.win32-x64').read_text(encoding='utf-8').splitlines()
if [line for line in sums if line.endswith(wheel.name)] != [receipt['wheel_sums_line']] \
        or receipt['wheel_sums_line'][:64] != receipt['wheel_sha256']:
    raise SystemExit('FAIL  SHA256SUMS.pypi.win32-x64 differs from the receipt for %s' % wheel.name)
with zipfile.ZipFile(wheel) as archive:
    data = archive.read(receipt['member'])
if (hashlib.sha256(data).hexdigest(), len(data)) != (receipt['sha256'], receipt['bytes']):
    raise SystemExit('FAIL  the DLL in %s differs from the receipt' % wheel.name)
shutil.move(str(path), os.path.join(os.environ['RUNNER_TEMP'], 'ipc-library.json'))
print('ok    dist/ipc-library.json matches %s in %s: abstraction_ipc.dll sha256 %s'
      % (wheel.name, artifact, receipt['sha256']))
