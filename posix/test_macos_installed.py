#!/usr/bin/env python3
"""Run the existing home-domain package journey from a real Aqua session.

The release driver supplies one hash-bound request in its owned temporary
directory. This owner installs that package, checks default discovery, reinstalls
it, and invokes its verified packaged uninstaller. Existing account files and
unknown installation state cause refusal before installation.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

AUTOMATED_ACCEPTANCE = {'profile': 'automated',
    'reason': 'Owner directive 2026-10-17: manual product demonstrations are deferred from publication.'}


def automated_acceptance(request):
    if 'acceptance' not in request:
        return False
    if request['acceptance'] != AUTOMATED_ACCEPTANCE:
        raise ValueError('unknown or changed installed acceptance profile/provenance')
    return True


RECEIPTS = tuple('com.openabstractions.abstraction' + suffix for suffix in
                 ('', '.localstores', '.modelhost', '.mcpgateway'))
LABELS = ('com.openabstractions.runtime', 'com.openabstractions.panel', 'com.openabstractions.jobd')
DATA = ('.abstraction', 'Library/Application Support/abstraction',
        'Library/Application Support/openabstractions/runtime-v1', 'Library/Caches/openabstractions')
KNOWN = ('.local/share/abstraction/LICENSE', '.local/share/abstraction/dev/USING.txt',
         '.local/share/abstraction/com.openabstractions.runtime.plist', '.local/share/abstraction/FILES',
         '.local/share/abstraction/uninstall.sh', '.local/share/abstraction/com.openabstractions.panel.plist',
         '.local/bin/Abstraction Panel.app/Contents/Info.plist',
         '.local/bin/Abstraction Panel.app/Contents/Resources/AppIcon.icns',
         '.local/bin/Abstraction Panel.app/Contents/MacOS/panel',
         '.local/bin/Abstraction Panel.app/Contents/MacOS/Abstraction Panel',
         '.local/bin/Abstraction Panel.app/Contents/_CodeSignature/CodeResources',
         '.local/bin/openabstractions', '.local/share/abstraction/lifecycle.sh',
         '.local/bin/declarations/lemonade.json', '.local/bin/declarations/lmstudio.json',
         '.local/bin/declarations/ollama.json', '.local/bin/declarations/comfyui.json',
         '.local/bin/openabstractions-mcp', '.local/share/abstraction/MANIFEST',
         'Library/LaunchAgents/com.openabstractions.runtime.plist',
         'Library/LaunchAgents/com.openabstractions.panel.plist',
         'Library/LaunchAgents/com.openabstractions.jobd.plist',
         '.local/share/abstraction/com.openabstractions.jobd.plist', '.local/bin/jobd', '.local/bin/dl',
         '.local/bin/jobctl', '.local/bin/inventoryd', '.local/bin/declarations/local-stores.json', '.local/bin/modelhostd')
AGENTS = tuple('Library/LaunchAgents/' + name + '.plist' for name in LABELS[:2])


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def write(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def relative(value):
    path = PurePosixPath(value)
    if not isinstance(value, str) or not value or path.is_absolute() or '..' in path.parts or str(path) != value:
        raise ValueError('invalid home payload path')
    return value


def checked_file(row, root):
    path = Path(row['path'])
    if not path.is_absolute() or path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file():
        raise ValueError('input is outside the owned ordinary-file root')
    if not re.fullmatch('[0-9a-f]{64}', str(row.get('sha256'))) or sha(path) != row['sha256'] or path.stat().st_size != row['bytes']:
        raise ValueError('input hash/size changed: ' + path.name)
    return path


def validate(request, request_path):
    root = request_path.parent
    if (not root.is_absolute() or root.is_symlink() or root.parent != Path('/private/tmp')
            or not re.fullmatch(r'oa-release-acceptance-[A-Za-z0-9_-]+', root.name) or root.resolve() != root):
        raise ValueError('expected one owned /private/tmp/oa-release-acceptance directory')
    if request.get('schema') != 1 or request.get('kind') != 'macos':
        raise ValueError('unsupported native Mac request')
    for name in ('source_sha', 'tool_source'):
        if not re.fullmatch('[0-9a-f]{40}', str(request.get(name))):
            raise ValueError('exact source/tool commit required')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', str(request.get('version'))):
        raise ValueError('exact release version required')
    if request.get('producer_sha256') != sha(Path(__file__)):
        raise ValueError('native acceptance owner bytes changed')
    if not isinstance(request.get('uid'), int) or request['uid'] <= 0 or not re.fullmatch('[A-Za-z0-9_-]+', str(request.get('user'))):
        raise ValueError('expected a named unelevated user')
    home = Path(request['home'])
    if not home.is_absolute() or home.is_symlink() or home.resolve() != home:
        raise ValueError('expected canonical account home')
    checked_file(request['artifact'], root)
    payload = request['expected_payload']
    if not isinstance(payload, list) or not payload:
        raise ValueError('expected exact assembled payload inventory')
    paths = set()
    for row in payload:
        name = relative(row['path'])
        if (name not in KNOWN or name in paths or not re.fullmatch('[0-9a-f]{64}', str(row.get('sha256')))
                or row.get('mode') not in (0o644, 0o755) or type(row.get('optional_off')) is not bool):
            raise ValueError('unknown/duplicate or malformed payload row')
        paths.add(name)
    required = {'.local/bin/openabstractions', '.local/share/abstraction/uninstall.sh',
                '.local/share/abstraction/FILES', '.local/share/abstraction/lifecycle.sh',
                '.local/bin/Abstraction Panel.app/Contents/_CodeSignature/CodeResources'}
    if not required <= paths or any(row['optional_off'] for row in payload if row['path'] in required):
        raise ValueError('default runtime/removal/Panel seal payload is incomplete')
    probe = request['probe']
    for key in ('go', 'native_library', 'python_script'):
        checked_file(probe[key], root)
    pythonpath = Path(probe['pythonpath'])
    if not pythonpath.is_dir() or pythonpath.is_symlink() or not pythonpath.resolve().is_relative_to(root):
        raise ValueError('source Python packages must stay in the owned root')
    files = probe['python_files']
    if not isinstance(files, list) or not files or any(path.is_symlink() for path in pythonpath.rglob('*')):
        raise ValueError('Python source inventory must contain ordinary source files')
    actual = {path for path in pythonpath.rglob('*') if path.is_file()}
    expected = {checked_file(row, root) for row in files}
    required_python = {'abstraction/ipc/__init__.py', 'abstraction/config/__init__.py', 'abstraction/facade/client.py'}
    if (actual != expected or any(not path.is_relative_to(pythonpath) for path in expected)
            or not required_python <= {path.relative_to(pythonpath).as_posix() for path in expected}):
        raise ValueError('Python source inventory differs from the exact probe inputs')
    if automated_acceptance(request):
        if 'core' in probe:
            raise ValueError('automated installed request cannot carry a human core')
        return root, home
    core = probe.get('core', {})
    if (core.get('schema') != 1 or core.get('directory') != str(root)
            or core.get('source_sha') != request['source_sha'] or core.get('tool_source') != request['tool_source']):
        raise ValueError('fixed native core caller/source binding missing')
    for key in ('go', 'journey', 'helper', 'native_library'):
        checked_file(core[key], root)
    if core['native_library'] != probe['native_library'] or core['python_files'] != files or core['pythonpath'] != probe['pythonpath']:
        raise ValueError('native core SDK inputs differ from installed discovery probe')
    if core['python']['sha256'] != sha(sys.executable) or core['python']['bytes'] != Path(sys.executable).stat().st_size:
        raise ValueError('native core Python interpreter differs from current native owner')
    return root, home


class Journey:
    def __init__(self, request, root, home):
        self.request, self.root, self.home = request, root, home
        self.logs = root / 'logs'
        self.logs.mkdir(exist_ok=True)
        self.commands, self.runtime_pids = [], []

    def call(self, name, argv, *, env=None, acceptable=(0,), timeout=90, discard=False):
        path = self.logs / (str(len(self.commands)) + '-' + name + '.log')
        start, clock = now(), time.monotonic()
        process, failure = None, None
        try:
            with path.open('wb') as output:
                process = subprocess.run([str(item) for item in argv], env=env, stdout=subprocess.DEVNULL if discard else output,
                                         stderr=subprocess.STDOUT, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as error:
            failure = error
        finally:
            result = {'operation': name, 'argv': [str(item) for item in argv], 'started_at': start, 'ended_at': now(),
                      'wall_seconds': time.monotonic() - clock, 'exit_code': process.returncode if process else None,
                      'outcome': 'timed_out' if isinstance(failure, subprocess.TimeoutExpired) else 'start_failed' if failure else 'interrupted' if process is None else 'completed',
                      'failure': str(failure) if failure else None,
                      'log_path': str(path), 'log_sha256': sha(path) if path.is_file() else None}
            self.commands.append(result)
            write(self.logs / 'commands.json', {'source_sha': self.request['source_sha'], 'tool_source': self.request['tool_source'],
                                               'commands': self.commands})
        if failure:
            raise failure
        if process.returncode not in acceptable:
            raise ValueError(name + ' failed with exit ' + str(process.returncode))
        return path.read_text(encoding='utf-8', errors='replace'), process.returncode

    def session(self):
        import pwd
        account = pwd.getpwuid(os.getuid())
        if (sys.platform != 'darwin' or os.getuid() != self.request['uid'] or os.geteuid() != os.getuid()
                or account.pw_name != self.request['user'] or Path(account.pw_dir) != self.home
                or Path.home() != self.home or os.environ.get('HOME') != str(self.home)):
            raise ValueError('real intended native account/HOME required')
        console, _ = self.call('console-owner', ['/usr/bin/stat', '-f', '%Su', '/dev/console'])
        uid, _ = self.call('manageruid', ['/bin/launchctl', 'manageruid'])
        manager, _ = self.call('managername', ['/bin/launchctl', 'managername'])
        if ((not automated_acceptance(self.request) and console.strip() != account.pw_name)
                or uid.strip() != str(os.getuid()) or manager.strip() != 'Aqua'):
            raise ValueError('run from the intended user real Aqua session')
        self.call('gui-domain', ['/bin/launchctl', 'print', 'gui/' + str(os.getuid())], discard=True)

    def presence(self):
        if any(os.path.lexists(self.home / name) for name in KNOWN):
            raise ValueError('known OA installation path is present; preserve it')
        for volume in (str(self.home), '/'):
            for name in RECEIPTS:
                text, code = self.call('receipt-absence', ['/usr/sbin/pkgutil', '--volume', volume, '--pkg-info', name],
                                       acceptable=(0, 1), timeout=15)
                if not code or 'No receipt' not in text:
                    raise ValueError('OA receipt present or absence unknown')
        for name in LABELS:
            text, code = self.call('job-absence', ['/bin/launchctl', 'print', 'gui/' + str(self.request['uid']) + '/' + name],
                                  acceptable=(0, 113), timeout=15)
            if not code or 'Could not find service' not in text:
                raise ValueError('OA job present or absence unknown')

    def retained_presence(self):
        return {name: os.path.lexists(self.home / name) for name in DATA}

    def manifest(self):
        path = self.home / '.local/share/abstraction/MANIFEST'
        if path.is_symlink() or not path.is_file():
            raise ValueError('removal ledger is absent or redirected; preserve payload')
        entries = path.read_text(encoding='utf-8').splitlines()
        allowed = {str(self.home / row['path']) for row in self.request['expected_payload']} | {str(self.home / name) for name in AGENTS}
        if not entries or len(entries) != len(set(entries)) or not set(entries) <= allowed:
            raise ValueError('unknown/duplicate manifest member; preserve payload')
        return entries

    def cleanup(self):
        self.manifest()
        row = next(row for row in self.request['expected_payload'] if row['path'] == '.local/share/abstraction/uninstall.sh')
        path = self.home / row['path']
        if path.is_symlink() or not path.is_file() or sha(path) != row['sha256']:
            raise ValueError('uninstaller changed; preserve payload')
        self.call('packaged-uninstall', ['/bin/sh', path], timeout=180)

    def installed(self, phase):
        selected = set()
        for row in self.request['expected_payload']:
            path = self.home / row['path']
            if row['optional_off']:
                if os.path.lexists(path):
                    raise ValueError('default-off payload was installed')
                continue
            if path.is_symlink() or not path.is_file() or sha(path) != row['sha256']:
                raise ValueError('installed bytes differ: ' + row['path'])
            if path.stat().st_mode & 0o777 != row['mode'] or path.stat().st_uid != self.request['uid']:
                raise ValueError('installed mode/owner differs: ' + row['path'])
            selected.add(str(path))
        wanted = selected | {str(self.home / name) for name in AGENTS}
        if set(self.manifest()) != wanted:
            raise ValueError('installed removal ledger differs from default payload/jobs')
        files = (self.home / '.local/share/abstraction/FILES').read_text(encoding='utf-8').splitlines()
        if len(files) != len(set(files)) or set(files) != {row['path'] for row in self.request['expected_payload']}:
            raise ValueError('FILES differs from all carried default/optional payload')
        text, _ = self.call('installed-receipt-' + phase, ['/usr/sbin/pkgutil', '--volume', self.home, '--pkg-info', RECEIPTS[0]])
        if 'version: ' + self.request['version'] not in text.splitlines():
            raise ValueError('installed receipt version differs')
        binary = self.home / '.local/bin/openabstractions'
        self.call('runtime-start-' + phase, [binary, 'start', '--timeout', '30s'], timeout=40)
        observation, _ = self.call('runtime-job-' + phase, ['/bin/launchctl', 'print', 'gui/' + str(self.request['uid']) + '/' + LABELS[0]])
        match = re.search(r'^\s*pid = ([0-9]+)$', observation, re.MULTILINE)
        if match:
            pid = int(match[1])
            started, _ = self.call('runtime-start-' + phase, ['/bin/ps', '-p', str(pid), '-o', 'lstart='])
            self.runtime_pids.append({'pid': pid, 'started': started.strip()})
        if not match:
            raise ValueError('ready runtime job has no observable owned PID')
        self.call('runtime-status-' + phase, [binary, 'status', '--json'])
        probe = self.request['probe']
        self.call('go-xpc-' + phase, [probe['go']['path'], 'installed', 'unused', self.root / 'state', binary, probe['go']['path']])
        env = dict(os.environ, PYTHONPATH=probe['pythonpath'], PYTHONDONTWRITEBYTECODE='1')
        self.call('python-discovery-' + phase, [sys.executable, '-B', probe['python_script']['path'], probe['native_library']['path']], env=env)
        if phase == 'fresh' and not automated_acceptance(self.request):
            core = probe['core']
            specification = importlib.util.spec_from_file_location('oa_installed_native_core', core['helper']['path'])
            helper = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(helper)
            request = helper.session_request(core, self.root / 'native-request.json', binary,
                self.home / '.local/bin/Abstraction Panel.app/Contents/MacOS/panel', self.logs / 'native-core')
            self.call('native-core', [sys.executable, '-B', core['journey']['path'], '--native-request', request], env=env, timeout=390)
            self.core = json.loads((request.parent / 'core-result.json').read_text())
            helper.validate_result(self.core, core, permission=True)

    def runtime_absence(self):
        for record in self.runtime_pids:
            text, code = self.call('owned-runtime-absence', ['/bin/ps', '-p', str(record['pid']), '-o', 'lstart='], acceptable=(0, 1))
            if not code and text.strip() == record['started']:
                raise ValueError('owned runtime process remains after removal')

    def run(self):
        self.session()
        self.presence()
        before = self.retained_presence()
        attempted, removed = False, False
        error, cleanup_error = None, None
        try:
            attempted = True
            self.call('install', ['/usr/sbin/installer', '-pkg', self.request['artifact']['path'], '-target', 'CurrentUserHomeDirectory', '-verboseR'], timeout=180)
            self.installed('fresh')
            self.call('reinstall', ['/usr/sbin/installer', '-pkg', self.request['artifact']['path'], '-target', 'CurrentUserHomeDirectory', '-verboseR'], timeout=180)
            self.installed('reinstall')
            self.cleanup()
            removed = True
        except (OSError, ValueError, subprocess.SubprocessError) as caught:
            error = str(caught)
        finally:
            if attempted and not removed and (self.home / '.local/share/abstraction/MANIFEST').is_file():
                try:
                    self.cleanup()
                except (OSError, ValueError, subprocess.SubprocessError) as caught:
                    cleanup_error = str(caught)
        self.presence()
        self.runtime_absence()
        after = self.retained_presence()
        if any(present and not after[name] for name, present in before.items()):
            raise ValueError('preexisting retained data directory disappeared')
        return {'result': 'failed' if error or cleanup_error else 'pass', 'exit_code': 1 if error or cleanup_error else 0,
                'failure': error, 'cleanup_failure': cleanup_error, 'cleanup_verified': True,
                'retained_presence': {'before': before, 'after': after}, 'owned_runtime_PIDs_absent': True,
                'core': getattr(self, 'core', None), 'private_evidence': True,
                **({'acceptance': self.request['acceptance'],
                    'manual': {'status': 'deferred', 'reason': self.request['acceptance']['reason']},
                    'automated_checks': [row['operation'] for row in self.commands]}
                   if automated_acceptance(self.request) else {})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    args = parser.parse_args()
    request_path = args.request
    if not request_path.is_absolute() or request_path.is_symlink():
        parser.error('request must be an absolute ordinary file')
    request = json.loads(request_path.read_text(encoding='utf-8'))
    root, home = validate(request, request_path)
    if (root / 'native-launch.json').exists() or (root / 'native-result.json').exists():
        raise SystemExit('native attempt already has launch/result evidence; reconcile it')
    started = now()
    launch = {key: request[key] for key in ('schema', 'kind', 'source_sha', 'tool_source', 'version', 'artifact', 'producer_sha256')}
    launch.update(request_sha256=sha(request_path), process_id=os.getpid(), started_utc=started,
        process_started=subprocess.check_output(['/bin/ps', '-p', str(os.getpid()), '-o', 'lstart='], text=True).strip(),
        process_command=subprocess.check_output(['/bin/ps', '-p', str(os.getpid()), '-o', 'command='], text=True).strip())
    write(root / 'native-launch.json', launch)
    journey = Journey(request, root, home)
    try:
        outcome = journey.run()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        outcome = {'result': 'failed', 'exit_code': 1, 'failure': str(error), 'cleanup_verified': False}
    result = {key: request[key] for key in ('schema', 'kind', 'source_sha', 'tool_source', 'version', 'artifact', 'producer_sha256')}
    result.update(outcome, started_utc=started, finished_utc=now(), commands=journey.commands)
    write(root / 'native-result.json', result)
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
