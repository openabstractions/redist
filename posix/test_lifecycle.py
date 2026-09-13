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
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "user & <home>|back\\slash"
        self.share = self.home / ".local/share/abstraction"
        self.share.mkdir(parents=True)
        self.bin = self.root / "commands"
        self.bin.mkdir()
        self.env = dict(os.environ, HOME=str(self.home), PATH=str(self.bin)+":"+os.environ["PATH"], LOG=str(self.root/"calls"))
        self.command("id", 'echo 1000')
        # Manager commands are mocked on both native hosts; Python bounds tests.
        # macOS has no bundled GNU timeout. Real Linux timeout is exercised by
        # test_systemd.sh separately.
        self.command("timeout", 'shift; shift; exec "$@"')
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
        self.mac_helper = (HERE/"macos/lifecycle.sh").read_text().replace('/bin/launchctl', '"'+str(self.bin/"launchctl")+'"')
        (self.share/"lifecycle.sh").write_text(self.mac_helper)

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
        if platform == "linux":
            shutil.copyfile(HERE/"linux/lifecycle.sh", self.share/"lifecycle.sh")
        else:
            (self.share/"lifecycle.sh").write_text(self.mac_helper)
        return subprocess.run(["sh", str(self.share/"uninstall.sh")], env=dict(self.env, **env), text=True, capture_output=True, timeout=5)

    def linux_package(self, name, retired=True):
        package = self.root / name
        payload = package / "payload"
        for rel, text in [(".local/bin/jobd", name),
                          (".local/bin/openabstractions", "#!/bin/sh\nexit 0\n")]:
            target = payload / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
            target.chmod(0o755)
        if retired:
            (payload / ".local/bin/jobctl").write_text("original retired payload")
        for filename in ("lifecycle.sh", "uninstall.sh"):
            target = payload / ".local/share/abstraction" / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE / "linux" / filename, target)
        shutil.copyfile(HERE / "linux/install.sh", package / "install.sh")
        return package

    def install_linux(self, package):
        return subprocess.run(["sh", str(package / "install.sh")], env=self.env,
                              text=True, capture_output=True, timeout=8)

    def test_linux_upgrade_retired_payload_is_removed_but_user_change_survives(self):
        for modified in (False, True):
            with self.subTest(modified=modified):
                first = self.install_linux(self.linux_package("first" + str(modified)))
                self.assertEqual(first.returncode, 0, first.stderr)
                retired = self.home / ".local/bin/jobctl"
                second = self.install_linux(self.linux_package("second" + str(modified), retired=False))
                self.assertEqual(second.returncode, 0, second.stderr)
                if modified:
                    retired.write_text("user changed retired tool")
                result = self.uninstall("linux")
                self.assertEqual(result.returncode, 0, result.stderr)
                if modified:
                    self.assertEqual(retired.read_text(), "user changed retired tool")
                    self.assertIn("preserv", result.stderr)
                else:
                    self.assertFalse(retired.exists())
                self.assertEqual(self.data.read_text(), "accepted work")
                self.share.mkdir(parents=True, exist_ok=True)

    def test_linux_unhashed_legacy_retirement_preserves_file(self):
        retired = self.home / ".local/bin/jobctl"
        retired.write_text("old file with no baseline")
        with (self.share / "MANIFEST").open("a") as ledger:
            ledger.write(str(retired) + "\n")
        result = self.install_linux(self.linux_package("legacy-retirement", retired=False))
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.uninstall("linux")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(retired.read_text(), "old file with no baseline")
        self.assertIn("no original hash", result.stderr)

    def test_linux_unsafe_manifest_entries_refuse_whole_operation(self):
        outside = self.root / "outside"
        outside.mkdir()
        victim = outside / "victim"
        victim.write_text("user bytes")
        link = self.share / "redirect"
        link.symlink_to(outside, target_is_directory=True)
        for bad in (str(link / "victim"), str(self.share / ".." / "victim"),
                    "retired badhash " + str(self.payload),
                    "sha256 " + "a" * 64 + " " + str(victim)):
            with self.subTest(bad=bad):
                manifest = self.share / "MANIFEST"
                manifest.write_text(str(self.payload) + "\n" + bad + "\ntimer yes\n")
                before = manifest.read_bytes()
                result = self.uninstall("linux")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.payload.read_text(), "payload")
                self.assertEqual(victim.read_text(), "user bytes")
                self.assertEqual(manifest.read_bytes(), before)

    def test_linux_copy_failure_preserves_predecessor_ledger_and_payload(self):
        previous = (self.share / "MANIFEST").read_bytes()
        package = self.linux_package("copy-failure")
        self.command("cp", 'for last do :; done; case "$last" in *jobctl) exit 7;; esac; exec /bin/cp "$@"')
        result = self.install_linux(package)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.share / "MANIFEST").read_bytes(), previous)
        self.assertEqual(self.payload.read_text(), "payload")
        self.assertEqual(self.data.read_text(), "accepted work")

    def test_linux_checksum_failure_preserves_predecessor(self):
        previous = (self.share / "MANIFEST").read_bytes()
        package = self.linux_package("checksum-failure")
        for body in ('printf "%064d  -\\n" 0; exit 7', 'echo malformed; exit 0'):
            with self.subTest(body=body):
                self.command("sha256sum", body)
                result = self.install_linux(package)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.share / "MANIFEST").read_bytes(), previous)
                self.assertEqual(self.payload.read_text(), "payload")
                self.assertFalse((self.home / ".local/bin/jobctl").exists())
                self.assertEqual(self.data.read_text(), "accepted work")

    def test_linux_replacement_failure_rolls_back_files_and_ledger(self):
        previous = (self.share / "MANIFEST").read_bytes()
        package = self.linux_package("replacement-failure")
        self.command("mv", 'for last do :; done; case "$last" in "$HOME/.local/bin/openabstractions") exit 7;; esac; exec /bin/mv "$@"')
        result = self.install_linux(package)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.share / "MANIFEST").read_bytes(), previous)
        self.assertEqual(self.payload.read_text(), "payload")
        self.assertFalse((self.home / ".local/bin/jobctl").exists())

    def test_linux_manifest_escape_refuses_before_any_removal_or_replacement(self):
        outside = self.root / "outside-data"
        outside.write_text("unrelated")
        manifest = self.share / "MANIFEST"
        manifest.write_text(str(self.payload) + "\n" + str(outside) + "\ntimer yes\n")
        previous = manifest.read_bytes()
        result = self.uninstall("linux")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outside.read_text(), "unrelated")
        self.assertEqual(self.payload.read_text(), "payload")
        self.assertEqual(manifest.read_bytes(), previous)
        result = self.install_linux(self.linux_package("escaped-ledger"))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(manifest.read_bytes(), previous)
        self.assertEqual(self.payload.read_text(), "payload")

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
        executable.chmod(0o755)
        shutil.copyfile(HERE/"linux/install.sh", package/"install.sh")
        result = subprocess.run(["sh", str(package/"install.sh")], env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root/"calls").read_text()
        self.assertIn("enable --now abstraction-jobd.timer abstraction-runtime.service", calls)
        self.assertIn("cli status --timeout 1s", calls)
        self.assertLess(calls.index("stop abstraction-runtime.service"), calls.index("cli storage check"))
        self.assertLess(calls.index("cli storage check"), calls.index("enable --now"))
        self.assertTrue(self.data.exists())

    def test_linux_upgrade_preflight_failure_preserves_payload_and_manifest(self):
        package = self.root / "rejected-package"
        candidate = package / "payload/.local/bin/openabstractions"
        candidate.parent.mkdir(parents=True)
        candidate.write_text('#!/bin/sh\necho "candidate $*" >> "$LOG"\nexit 1\n')
        candidate.chmod(0o755)
        helper = package / "payload/.local/share/abstraction/lifecycle.sh"
        helper.parent.mkdir(parents=True)
        shutil.copyfile(HERE / "linux/lifecycle.sh", helper)
        installed = self.home / ".local/bin/openabstractions"
        installed.write_text("previous runtime")
        manifest = self.share / "MANIFEST"
        before_manifest = manifest.read_bytes()
        shutil.copyfile(HERE / "linux/install.sh", package / "install.sh")
        stopped = subprocess.run(["sh", str(package / "install.sh")],
                                 env=dict(self.env, FAIL="stop"), text=True,
                                 capture_output=True, timeout=5)
        self.assertNotEqual(stopped.returncode, 0)
        self.assertNotIn("candidate", (self.root / "calls").read_text())
        self.assertEqual(installed.read_text(), "previous runtime")
        self.assertEqual(manifest.read_bytes(), before_manifest)
        (self.root / "calls").unlink()
        result = subprocess.run(["sh", str(package / "install.sh")],
                                env=self.env, text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed payload retained", result.stderr)
        self.assertEqual(installed.read_text(), "previous runtime")
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual(self.data.read_text(), "accepted work")
        calls = (self.root / "calls").read_text()
        self.assertLess(calls.index("stop abstraction-runtime.service"), calls.index("candidate storage check"))
        self.assertNotIn("enable --now", calls)

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
        import plistlib
        parsed = plistlib.loads(plist.read_bytes())
        self.assertEqual(parsed["ProgramArguments"], [str(self.home/".local/bin/openabstractions"), "serve", "runtime"])
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
        self.assertEqual(plist["ProgramArguments"], ["@BIN@/openabstractions", "serve", "runtime"])
        self.assertTrue(plist["KeepAlive"])
        self.assertNotIn("StartInterval", plist)

    def test_macos_manager_watchdog_bounds_only_its_child(self):
        self.command("launchctl", 'trap "" TERM; exec sleep 5')
        helper = self.mac_helper.replace("sleep 20", "sleep 0.05").replace("sleep 2", "sleep 0.05")
        (self.share/"lifecycle.sh").write_text(helper)
        result = subprocess.run(["sh", "-c", '. "$HOME/.local/share/abstraction/lifecycle.sh"; manager list'], env=self.env, text=True, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("timed out", result.stderr)
        self.assertTrue(self.payload.exists())

if __name__ == "__main__":
    unittest.main()
