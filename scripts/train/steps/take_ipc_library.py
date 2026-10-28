import hashlib, json, os, pathlib, re, sys, zipfile
folder = pathlib.Path(sys.argv[1])
wheels = sorted(folder.glob('abstraction_ipc-*-win_amd64.whl'))
if len(wheels) != 1:
    raise SystemExit('FAIL  expected one win_amd64 abstraction-ipc wheel in %s, found %d'
                     % (folder, len(wheels)))
wheel = wheels[0]
wheel_sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
sums = (folder / 'SHA256SUMS.pypi.win32-x64').read_text(encoding='utf-8').splitlines()
lines = [line for line in sums if re.fullmatch(r'[0-9a-f]{64} [ *]' + re.escape(wheel.name), line)]
if len(lines) != 1 or lines[0][:64] != wheel_sha256:
    raise SystemExit('FAIL  SHA256SUMS.pypi.win32-x64 does not list %s with its SHA-256 %s'
                     % (wheel.name, wheel_sha256))
member = 'abstraction/ipc/_native/abstraction_ipc.dll'
with zipfile.ZipFile(wheel) as archive:
    data = archive.read(member)
target = pathlib.Path('ipc-library/abstraction_ipc.dll')
target.parent.mkdir(exist_ok=True)
target.write_bytes(data)
receipt = {'schema': 1, 'run_id': int(os.environ['GITHUB_RUN_ID']), 'artifact': folder.name,
           'wheel': wheel.name, 'wheel_sha256': wheel_sha256, 'wheel_sums_line': lines[0],
           'member': member, 'library': 'tools/abstraction_ipc.dll',
           'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
pathlib.Path('dist/ipc-library.json').write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print('ok    %s, %d bytes, sha256 %s, from %s (%s)'
      % (target, len(data), receipt['sha256'], wheel.name, folder.name))
