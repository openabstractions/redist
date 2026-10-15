"""Inert controls for the existing native package journey's owning guards."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mac_installed_owner', Path(__file__).with_name('test_macos_installed.py'))
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


class InstalledOwnerTests(unittest.TestCase):
    def setUp(self):
        self.area = tempfile.TemporaryDirectory(prefix='oa-native-mac-guards-')
        self.addCleanup(self.area.cleanup)
        self.root = Path(self.area.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.request = {'uid': 501, 'version': '0.4.0', 'source_sha': 'a' * 40, 'tool_source': 'b' * 40,
                        'expected_payload': [], 'artifact': {'path': str(self.root / 'exact.pkg')}}
        self.journey = owner.Journey(self.request, self.root, self.home)

    def file(self, relative, data=b'exact', optional=False):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.request['expected_payload'].append({'path': relative, 'sha256': owner.sha(path), 'mode': 0o644, 'optional_off': optional})
        return path

    def ledger(self, entries):
        path = self.home / '.local/share/abstraction/MANIFEST'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(''.join(str(self.home / entry) + '\n' for entry in entries), encoding='utf-8')

    def test_existing_owner_path_refuses_before_any_system_query(self):
        self.file('.local/bin/openabstractions')
        with patch.object(self.journey, 'call', side_effect=AssertionError('query/install dispatched')):
            with self.assertRaisesRegex(ValueError, 'installation path is present'):
                self.journey.presence()

    def test_receipt_query_error_is_unknown_and_refuses(self):
        with patch.object(self.journey, 'call', return_value=('permission denied', 1)):
            with self.assertRaisesRegex(ValueError, 'absence unknown'):
                self.journey.presence()

    def test_known_no_receipt_and_no_job_answers_prove_absence(self):
        calls = []
        def answer(name, *args, **kwargs):
            calls.append(name)
            return ('No receipt found', 1) if name == 'receipt-absence' else ('Could not find service', 113)
        with patch.object(self.journey, 'call', side_effect=answer):
            self.journey.presence()
        self.assertEqual(calls.count('receipt-absence'), 8)
        self.assertEqual(calls.count('job-absence'), 3)

    def test_unknown_or_duplicate_ledger_refuses_removal(self):
        self.file('.local/share/abstraction/uninstall.sh')
        for entries in (['unrelated-owner-file'], ['.local/share/abstraction/uninstall.sh'] * 2):
            self.ledger(entries)
            with patch.object(self.journey, 'call', side_effect=AssertionError('uninstall dispatched')):
                with self.assertRaisesRegex(ValueError, 'unknown/duplicate manifest'):
                    self.journey.cleanup()

    def test_changed_uninstaller_refuses_with_payload_preserved(self):
        path = self.file('.local/share/abstraction/uninstall.sh')
        self.ledger(['.local/share/abstraction/uninstall.sh'])
        path.write_bytes(b'changed')
        with patch.object(self.journey, 'call', side_effect=AssertionError('uninstall dispatched')):
            with self.assertRaisesRegex(ValueError, 'uninstaller changed'):
                self.journey.cleanup()
        self.assertEqual(path.read_bytes(), b'changed')

    def test_background_session_refuses_before_install(self):
        import types
        account = types.SimpleNamespace(pw_name='fixture', pw_dir=str(self.home))
        self.request.update(user='fixture')
        pwd = types.SimpleNamespace(getpwuid=lambda _: account)
        with patch.dict('sys.modules', {'pwd': pwd}), patch.object(owner.sys, 'platform', 'darwin'), \
                patch.object(owner.os, 'getuid', return_value=501, create=True), \
                patch.object(owner.os, 'geteuid', return_value=501, create=True), \
                patch.object(owner.Path, 'home', return_value=self.home), patch.dict(owner.os.environ, {'HOME': str(self.home)}), \
                patch.object(self.journey, 'call', side_effect=[('fixture', 0), ('501', 0), ('Background', 0)]):
            with self.assertRaisesRegex(ValueError, 'real Aqua session'):
                self.journey.session()

    def test_failure_after_install_runs_guarded_removal_and_preserves_failed_verdict(self):
        self.file('.local/share/abstraction/MANIFEST')
        cleanup = []
        with patch.object(self.journey, 'session'), patch.object(self.journey, 'presence'), \
                patch.object(self.journey, 'retained_presence', return_value={name: False for name in owner.DATA}), \
                patch.object(self.journey, 'call'), patch.object(self.journey, 'installed', side_effect=ValueError('readiness failed')), \
                patch.object(self.journey, 'cleanup', side_effect=lambda: cleanup.append(1)), patch.object(self.journey, 'runtime_absence'):
            result = self.journey.run()
        self.assertEqual(cleanup, [1])
        self.assertEqual(result['result'], 'failed')
        self.assertTrue(result['cleanup_verified'])

    def test_live_owned_pid_remains_failure_but_reused_pid_is_not_ours(self):
        self.journey.runtime_pids = [{'pid': 123, 'started': 'exact-start'}]
        with patch.object(self.journey, 'call', return_value=('exact-start', 0)):
            with self.assertRaisesRegex(ValueError, 'runtime process remains'):
                self.journey.runtime_absence()
        with patch.object(self.journey, 'call', return_value=('different-start', 0)):
            self.journey.runtime_absence()

    def test_paths_reject_traversal_and_preserve_new_panel_seal_inventory(self):
        for path in ('/other', '../other', '.local/../other'):
            with self.assertRaises(ValueError):
                owner.relative(path)
        self.assertIn('.local/bin/Abstraction Panel.app/Contents/_CodeSignature/CodeResources', owner.KNOWN)

    def test_timeout_retains_timed_failed_command_and_never_reports_success(self):
        with patch.object(owner.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['bounded'], 1)):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.journey.call('bounded-step', ['/usr/sbin/installer', '-pkg', 'exact.pkg'], timeout=1)
        record, = self.journey.commands
        self.assertEqual(record['operation'], 'bounded-step')
        self.assertEqual(record['outcome'], 'timed_out')
        self.assertIsNone(record['exit_code'])
        self.assertGreaterEqual(record['wall_seconds'], 0)
        self.assertTrue(record['started_at'] and record['ended_at'] and record['log_sha256'])

    def test_keyboard_interrupt_retains_interrupted_command_without_completed_claim(self):
        with patch.object(owner.subprocess, 'run', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.journey.call('interrupted', ['fixed-owner'])
        record, = json.loads((self.journey.logs / 'commands.json').read_text())['commands']
        self.assertEqual(record['outcome'], 'interrupted')
        self.assertIsNone(record['exit_code'])
        self.assertGreaterEqual(record['wall_seconds'], 0)


if __name__ == '__main__':
    unittest.main()
