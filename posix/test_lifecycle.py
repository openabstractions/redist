"""Run with python3 installer/posix/test_lifecycle.py; isolated shell/manager fixtures."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "user home"
        self.share = self.home / ".local/share/abstraction"
        self.share.mkdir(parents=True)
        self.bin = self.root / "commands"
        self.bin.mkdir()
        self.env = dict(os.environ, HOME=str(self.home), PATH=str(self.bin)+":"+os.environ["PATH"], LOG=str(self.root/"calls"))
        self.command("id", 'echo 1000')
        self.command("systemctl", r'''echo "$*" >> "$LOG"
case "$*" in
*show-environment*) [ "${FAIL:-}" != manager ];;
*--property=LoadState*) echo loaded;;
*--property=ActiveState*) echo "${ACTIVE:-inactive}";;
*--property=MainPID*) echo 0;;
*--property=Result*) echo "${RESULT:-success}";;
*stop*) [ "${FAIL:-}" != stop ];;
*is-active*) [ "${FAIL:-}" != active ];;
*) exit 0;;
esac''')
        self.command("launchctl", r'''echo "$*" >> "$LOG"
case "$1" in
manageruid) echo "${MANAGER_UID:-1000}"; [ "${FAIL:-}" != manager_query ];;
managername) echo "${MANAGER_NAME:-Aqua}";;
list)
    [ "${FAIL:-}" != verify ] || exit 5
    if [ "${FAIL:-}" = after ] && [ -f "$LOG.stopped" ]; then exit 5; fi
    [ "${FAIL:-}" != format ] || { echo unexpected; exit 0; }
    printf 'PID\tStatus\tLabel\n'
    if [ "${UNRELATED:-}" = yes ]; then printf '%s\n' '- 0 unrelated label with spaces'; fi
    if [ "${ABSENT:-}" != yes ] && { [ ! -f "$LOG.stopped" ] || [ "${ACTIVE:-}" = active ]; }; then
        printf '%s\n' '- 0 com.openabstractions.jobd'
    fi;;
bootout) [ "${FAIL:-}" != stop ] || exit 5; touch "$LOG.stopped";;
bootstrap) [ "${FAIL:-}" != bootstrap ];;
print) case "$2" in */com.openabstractions.jobd) [ "${ACTIVE:-}" = active ];; *) [ "${FAIL:-}" != verify ];; esac;;
*) exit 0;;
esac''')
        self.command("pkgutil", 'exit 0')
        self.payload = self.home / ".local/bin/jobd"
        self.payload.parent.mkdir(parents=True)
        self.payload.write_text("payload")
        (self.share/"MANIFEST").write_text(str(self.payload)+"\ntimer yes\n")
        self.data = self.home / ".abstraction/jobs"
        self.data.parent.mkdir()
        self.data.write_text("accepted work")

    def command(self, name, body):
        path = self.bin/name
        path.write_text("#!/bin/sh\n"+body+"\n")
        path.chmod(0o755)

    def uninstall(self, platform, **env):
        shutil.copyfile(HERE/platform/"uninstall.sh", self.share/"uninstall.sh")
        shutil.copyfile(HERE/"linux/lifecycle.sh", self.share/"lifecycle.sh")
        return subprocess.run(["sh", str(self.share/"uninstall.sh")], env=dict(self.env, **env), text=True, capture_output=True, timeout=5)

    def test_linux_stops_trigger_before_workers_and_preserves_data(self):
        result = self.uninstall("linux")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root/"calls").read_text()
        self.assertLess(calls.index("stop abstraction-jobd.timer"), calls.index("stop abstraction-jobd.service"))
        self.assertLess(calls.index("stop abstraction-jobd.service"), calls.index("stop abstraction-runtime.service"))
        self.assertFalse(self.payload.exists())
        self.assertEqual(self.data.read_text(), "accepted work")

    def test_linux_failed_stop_or_unavailable_manager_retains_payload(self):
        for failure in ["stop", "manager"]:
            with self.subTest(failure=failure):
                (self.root/"calls.stopped").unlink(missing_ok=True)
                self.payload.parent.mkdir(parents=True, exist_ok=True)
                self.payload.write_text("payload")
                (self.share/"MANIFEST").write_text(str(self.payload)+"\ntimer yes\n")
                result = self.uninstall("linux", FAIL=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.payload.exists())
                self.assertTrue((self.share/"MANIFEST").exists())

    def test_linux_unverified_active_state_retains_payload(self):
        result = self.uninstall("linux", ACTIVE="active")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.payload.exists())

    def test_linux_forced_result_is_reported(self):
        result = self.uninstall("linux", RESULT="timeout")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("graceful completion not established", result.stderr)

    def test_macos_failed_bootout_or_remaining_registration_retains_payload(self):
        for env in [{"FAIL": "stop"}, {"ACTIVE": "active"}, {"FAIL": "verify"}, {"FAIL": "format"}, {"FAIL": "manager_query"}, {"FAIL": "after"}, {"MANAGER_NAME": "Background"}, {"MANAGER_UID": "0"}]:
            with self.subTest(env=env):
                (self.root/"calls.stopped").unlink(missing_ok=True)
                self.payload.parent.mkdir(parents=True, exist_ok=True)
                self.payload.write_text("payload")
                (self.share/"MANIFEST").write_text(str(self.payload)+"\ntimer yes\n")
                result = self.uninstall("macos", **env)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.payload.exists())

    def test_macos_verified_bootout_preserves_data(self):
        result = self.uninstall("macos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.payload.exists())
        self.assertTrue(self.data.exists())
        self.assertIn("graceful exit is not independently established", result.stdout)

    def test_macos_already_absent_agent_can_be_removed_without_bootout(self):
        result = self.uninstall("macos", ABSENT="yes", FAIL="stop", UNRELATED="yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.payload.exists())
        self.assertNotIn("bootout", (self.root/"calls").read_text())
        self.assertTrue(self.data.exists())

    def test_macos_empty_enumeration_after_failed_registration_allows_removal(self):
        result = self.uninstall("macos", ABSENT="yes", FAIL="stop")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.payload.exists())
        self.assertTrue(self.data.exists())
        self.assertNotIn("bootout", (self.root/"calls").read_text())

    def test_linux_install_registers_runtime_and_checks_readiness(self):
        package = self.root/"package"
        payload = package/"payload"
        for rel, source in [(".local/share/abstraction/lifecycle.sh", "linux/lifecycle.sh"),
                            (".config/systemd/user/abstraction-runtime.service", "linux/abstraction-runtime.service")]:
            destination = payload/rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE/source, destination)
        executable = payload/".local/bin/openabstractions"
        executable.parent.mkdir(parents=True)
        executable.write_text('#!/bin/sh\necho "cli $*" >> "$LOG"\n')
        shutil.copyfile(HERE/"linux/install.sh", package/"install.sh")
        result = subprocess.run(["sh", str(package/"install.sh")], env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root/"calls").read_text()
        self.assertIn("enable --now abstraction-jobd.timer abstraction-runtime.service", calls)
        self.assertIn("cli status --timeout 1s", calls)
        self.assertTrue(self.data.exists())

    def test_macos_bootstrap_failure_is_installation_failure(self):
        self.command("stat", "echo 1000")
        self.command("chown", "exit 0")
        plist = self.home/"Library/LaunchAgents/com.openabstractions.jobd.plist"
        plist.parent.mkdir(parents=True)
        shutil.copyfile(HERE/"macos/com.openabstractions.jobd.plist", plist)
        (self.share/"FILES").write_text(".local/bin/jobd\n")
        result = subprocess.run(["sh", str(HERE/"macos/postinstall")], env=dict(self.env, FAIL="bootstrap", ACTIVE="active"), text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.payload.exists())

    def test_macos_owns_installed_ancestors_without_touching_siblings(self):
        self.command("stat", "echo 1000")
        self.command("chown", 'printf "chown:%s\\n" "$*" >> "$LOG"')
        self.command("chmod", 'printf "chmod:%s\\n" "$*" >> "$LOG"')
        plist = self.home/"Library/LaunchAgents/com.openabstractions.jobd.plist"
        plist.parent.mkdir(parents=True)
        shutil.copyfile(HERE/"macos/com.openabstractions.jobd.plist", plist)
        other = self.payload.parent/"other-tool"
        other.write_text("unrelated")
        (self.share/"FILES").write_text(".local/bin/jobd\nLibrary/LaunchAgents/com.openabstractions.jobd.plist\n")
        result = subprocess.run(["sh", str(HERE/"macos/postinstall")], env=dict(self.env, ACTIVE="active"), text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root/"calls").read_text().splitlines()
        for directory in [self.share, self.share.parent, self.home/".local", self.payload.parent, plist.parent, self.home/"Library"]:
            self.assertIn("chown:1000:1000 " + str(directory), calls)
            self.assertIn("chmod:u+rwx " + str(directory), calls)
        self.assertNotIn("chown:1000:1000 " + str(self.home), calls)
        self.assertFalse(any(str(other) in line or "chown:-R" in line for line in calls))
        self.assertEqual(other.read_text(), "unrelated")

    def test_macos_refuses_symlink_ancestor_before_ownership_change(self):
        self.command("stat", "echo 1000")
        self.command("chown", 'echo "chown $*" >> "$LOG"')
        plist = self.home/"Library/LaunchAgents/com.openabstractions.jobd.plist"
        plist.parent.mkdir(parents=True)
        shutil.copyfile(HERE/"macos/com.openabstractions.jobd.plist", plist)
        outside = self.root/"outside"
        outside.mkdir()
        (outside/"file").write_text("untouched")
        (self.home/"escape").symlink_to(outside, target_is_directory=True)
        (self.share/"FILES").write_text("escape/file\n")
        result = subprocess.run(["sh", str(HERE/"macos/postinstall")], env=self.env, text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe payload directory", result.stderr)
        self.assertFalse((self.root/"calls").exists())
        self.assertEqual((outside/"file").read_text(), "untouched")

    def test_native_units_own_shutdown_and_keep_job_admission_opt_in(self):
        runtime = (HERE/"linux/abstraction-runtime.service").read_text()
        self.assertIn('ExecStart="%h/.local/bin/openabstractions" serve runtime\n', runtime)
        self.assertNotIn("--jobs-", runtime)
        for unit in [runtime, (HERE/"linux/abstraction-jobd.service").read_text()]:
            self.assertIn("KillMode=control-group", unit)
            self.assertIn("TimeoutStopSec=10s", unit)
        import plistlib
        plist = plistlib.loads((HERE/"macos/com.openabstractions.jobd.plist").read_bytes())
        self.assertEqual(plist["ExitTimeOut"], 10)
        self.assertFalse(plist["AbandonProcessGroup"])

if __name__ == "__main__":
    unittest.main()
