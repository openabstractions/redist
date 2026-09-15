"""Run with python3 installer/posix/test_lifecycle.py; isolated shell/manager fixtures."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
# Bounds one fixture script run. A cold WSL instance ran a warm 0.2 s uninstall
# past 5 s. The manager watchdog sleeps 20 s, so a leaked watchdog holding the
# captured pipes still fails this bound.
SCRIPT_TIMEOUT = 15

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
        # TMPDIR is a fixture directory, so no script under test reads or
        # removes lock files in the host's real temporary directory.
        (self.root/"fixture-tmp").mkdir()
        self.env = dict(os.environ, HOME=str(self.home), PATH=str(self.bin)+":"+os.environ["PATH"], LOG=str(self.root/"calls"),
                        TMPDIR=str(self.root/"fixture-tmp"), USER="fixture-user")
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
        # A receipt lives on one volume, recorded in $LOG.receipt. pkgutil with
        # no --volume looks at /, the way the real tool does, and a home-domain
        # receipt is invisible there.
        self.command("pkgutil", r'''vol=/
if [ "$1" = --volume ]; then vol=$2; shift 2; fi
here=absent; [ -f "$LOG.receipt" ] && [ "$(cat "$LOG.receipt")" = "$vol" ] && here=present
payload=absent; [ -e "$PAYLOAD" ] && payload=present
uninstaller=absent; [ -e "$HOME/.local/share/abstraction/uninstall.sh" ] && uninstaller=present
echo "pkgutil $1 volume=$vol receipt=$here payload=$payload uninstaller=$uninstaller" >> "$LOG"
case "$1" in
--pkg-info)
    [ "${FAIL:-}" != receipt_query ] || { echo "pkgutil: internal error" >&2; exit 3; }
    [ "$here" = present ] && { echo "volume: $vol"; exit 0; };;
--forget)
    [ "${FAIL:-}" != forget ] || { echo "pkgutil: forget refused" >&2; exit 7; }
    [ "$here" = present ] && { rm -f "$LOG.receipt"; echo "Forgot package '$2' on '$vol'."; exit 0; };;
*) echo "unexpected pkgutil $*" >&2; exit 64;;
esac
echo "No receipt for '$2' found at '$vol'." >&2
exit 1''')
        (self.root/"calls.receipt").write_text(str(self.home))
        self.mac_helper = (HERE/"macos/lifecycle.sh").read_text().replace('/bin/launchctl', '"'+str(self.bin/"launchctl")+'"')
        (self.share/"lifecycle.sh").write_text(self.mac_helper)

        self.payload = self.home / ".local/bin/jobd"
        self.env["PAYLOAD"] = str(self.payload)
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
        return subprocess.run(["sh", str(self.share/"uninstall.sh")], env=dict(self.env, **env), text=True, capture_output=True, timeout=SCRIPT_TIMEOUT)

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

    def assert_notice(self, text):
        for line in ("retained user data", "~/.abstraction", "~/Library/Application Support/abstraction",
                     "~/Library/Application Support/openabstractions/runtime-v1", "~/Library/Caches/openabstractions"):
            self.assertIn(line, text)

    def test_macos_home_receipt_is_forgotten_before_payload_and_uninstaller_goes_last(self):
        result = self.uninstall("macos")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root/"calls").read_text().splitlines()
        forget = [c for c in calls if c.startswith("pkgutil --forget")]
        self.assertEqual(forget, ["pkgutil --forget volume=%s receipt=present payload=present uninstaller=present" % self.home])
        self.assertLess(calls.index("bootout gui/1000/com.openabstractions.jobd"), calls.index(forget[0]))
        self.assertFalse((self.root/"calls.receipt").exists())
        for gone in (self.payload, self.share/"MANIFEST", self.share/"uninstall.sh", self.share/"lifecycle.sh", self.share):
            self.assertFalse(gone.exists(), gone)
        self.assertEqual(self.data.read_text(), "accepted work")
        self.assertIn("package receipt forgotten on " + str(self.home), result.stdout)
        self.assert_notice(result.stdout)

    def test_macos_system_domain_receipt_falls_back_to_root_volume(self):
        (self.root/"calls.receipt").write_text("/")
        result = self.uninstall("macos")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root/"calls").read_text()
        self.assertIn("pkgutil --forget volume=/ receipt=present payload=present", calls)
        self.assertNotIn("pkgutil --forget volume=" + str(self.home), calls)
        self.assertFalse((self.root/"calls.receipt").exists())

    def test_macos_absent_receipt_allows_a_rerun_to_finish(self):
        (self.root/"calls.receipt").unlink()
        result = self.uninstall("macos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no package receipt present", result.stdout)
        self.assertNotIn("pkgutil --forget", (self.root/"calls").read_text())
        self.assertFalse(self.payload.exists())
        self.assertFalse((self.share/"MANIFEST").exists())

    def test_macos_receipt_failure_retains_payload_and_prints_recovery_and_notice(self):
        for failure in ("forget", "receipt_query"):
            with self.subTest(failure=failure):
                result = self.uninstall("macos", FAIL=failure)
                self.assertNotEqual(result.returncode, 0)
                for kept in (self.payload, self.share/"MANIFEST", self.share/"uninstall.sh", self.share/"lifecycle.sh"):
                    self.assertTrue(kept.exists(), kept)
                self.assertTrue((self.root/"calls.receipt").exists())
                self.assertIn("recovery", result.stderr)
                self.assertIn("/bin/sh '%s'" % (self.share/"uninstall.sh"), result.stderr)
                if failure == "forget":
                    self.assertIn("pkgutil --volume '%s' --forget com.openabstractions.abstraction" % self.home, result.stderr)
                self.assert_notice(result.stderr)
        # The printed recovery is runnable: the uninstaller is still in place.
        result = subprocess.run(["/bin/sh", str(self.share/"uninstall.sh")], env=self.env, text=True, capture_output=True, timeout=SCRIPT_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.payload.exists())
        self.assertFalse((self.root/"calls.receipt").exists())

    def test_macos_every_refusal_prints_recovery_and_notice(self):
        for env in [{"FAIL": "stop"}, {"MANAGER_NAME": "Background"}, {"ACTIVE": "active"}]:
            with self.subTest(env=env):
                (self.root/"calls.stopped").unlink(missing_ok=True)
                result = self.uninstall("macos", **env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("recovery", result.stderr)
                self.assertIn("/bin/sh '%s'" % (self.share/"uninstall.sh"), result.stderr)
                self.assert_notice(result.stderr)
        (self.share/"MANIFEST").unlink()
        result = self.uninstall("macos")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pkgutil --volume '%s' --forget com.openabstractions.abstraction" % self.home, result.stderr)
        self.assert_notice(result.stderr)

    def test_macos_file_removal_failure_keeps_uninstaller_for_retry(self):
        stuck = self.home/".local/bin/stuck"
        stuck.write_text("x")
        with (self.share/"MANIFEST").open("a") as ledger:
            ledger.write(str(stuck) + "\n" + str(self.share/"uninstall.sh") + "\n" + str(self.share/"lifecycle.sh") + "\n")
        self.command("rm", 'for last do :; done; case "$last" in */stuck) exit 1;; esac; exec /bin/rm "$@"')
        result = self.uninstall("macos")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.payload.exists())
        self.assertTrue((self.share/"uninstall.sh").exists())
        self.assertTrue((self.share/"MANIFEST").exists())
        self.assertIn("could not remove " + str(stuck), result.stderr)
        self.assert_notice(result.stderr)
        (self.bin/"rm").unlink()
        result = subprocess.run(["/bin/sh", str(self.share/"uninstall.sh")], env=self.env, text=True, capture_output=True, timeout=SCRIPT_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(stuck.exists())
        self.assertFalse(self.share.exists())

    def test_macos_removes_runtime_locks_whose_sockets_are_gone(self):
        tmp = self.root/"tmpdir"
        tmp.mkdir()
        gone = tmp/"openabstractions-runtime-tester.sock.lock"
        live_sock = tmp/"openabstractions-config-tester.sock"
        live_lock = tmp/"openabstractions-config-tester.sock.lock"
        other_user = tmp/"openabstractions-runtime-someone.sock.lock"
        unrelated = tmp/"unrelated.sock.lock"
        for f in (gone, live_sock, live_lock, other_user, unrelated):
            f.write_text("")
        result = self.uninstall("macos", TMPDIR=str(tmp) + "/", USER="tester")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(gone.exists())
        for kept in (live_sock, live_lock, other_user, unrelated):
            self.assertTrue(kept.exists(), kept)
        self.assertIn(str(live_sock) + " and its .lock", result.stdout)
        self.assert_notice(result.stdout)

    def test_macos_negative_control_pre_fix_uninstaller_fails_the_receipt_stub(self):
        shutil.copyfile(HERE/"test_fixture_macos_uninstall_114eb78e.sh", self.share/"uninstall.sh")
        (self.share/"lifecycle.sh").write_text(self.mac_helper)
        # The installed MANIFEST lists the uninstaller itself, as on the Mac.
        with (self.share/"MANIFEST").open("a") as ledger:
            ledger.write(str(self.share/"uninstall.sh") + "\n")
        result = subprocess.run(["sh", str(self.share/"uninstall.sh")], env=self.env, text=True, capture_output=True, timeout=SCRIPT_TIMEOUT)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No receipt for 'com.openabstractions.abstraction' found at '/'", result.stderr)
        self.assertTrue((self.root/"calls.receipt").exists())
        self.assertTrue((self.share/"MANIFEST").exists())
        self.assertFalse((self.share/"uninstall.sh").exists())
        self.assertNotIn("retained user data", result.stdout + result.stderr)

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
                                 capture_output=True, timeout=SCRIPT_TIMEOUT)
        self.assertNotEqual(stopped.returncode, 0)
        self.assertNotIn("candidate", (self.root / "calls").read_text())
        self.assertEqual(installed.read_text(), "previous runtime")
        self.assertEqual(manifest.read_bytes(), before_manifest)
        (self.root / "calls").unlink()
        result = subprocess.run(["sh", str(package / "install.sh")],
                                env=self.env, text=True, capture_output=True, timeout=SCRIPT_TIMEOUT)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed payload retained", result.stderr)
        self.assertEqual(installed.read_text(), "previous runtime")
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual(self.data.read_text(), "accepted work")
        calls = (self.root / "calls").read_text()
        self.assertLess(calls.index("stop abstraction-runtime.service"), calls.index("candidate storage check"))
        self.assertNotIn("enable --now", calls)

    def template(self):
        shutil.copyfile(HERE/"macos/com.openabstractions.jobd.plist", self.share/"com.openabstractions.jobd.plist")
        return self.home/"Library/LaunchAgents/com.openabstractions.jobd.plist"

    def test_macos_bootstrap_failure_is_installation_failure(self):
        self.command("stat", "echo 1000")
        self.command("chown", "exit 0")
        self.template()
        (self.share/"FILES").write_text(".local/bin/jobd\n")
        result = subprocess.run(["sh", str(HERE/"macos/postinstall")], env=dict(self.env, FAIL="bootstrap", ACTIVE="active"), text=True, capture_output=True, timeout=SCRIPT_TIMEOUT)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.payload.exists())

    def test_macos_owns_installed_ancestors_without_touching_siblings(self):
        self.command("stat", "echo 1000")
        self.command("chown", 'printf "chown:%s\\n" "$*" >> "$LOG"')
        self.command("chmod", 'printf "chmod:%s\\n" "$*" >> "$LOG"; exec /bin/chmod "$@"')
        # Every rename is logged with what the source held, so a placeholder
        # reaching ~/Library/LaunchAgents under any name would be visible.
        self.command("mv", r'''for last do :; done
for a do case "$a" in -*) ;; *) src=$a; break;; esac; done
printf "mv:%s -> %s bin=%s\n" "$src" "$last" "$(grep -c '@BIN@' "$src")" >> "$LOG"
exec /bin/mv "$@"''')
        plist = self.template()
        other = self.payload.parent/"other-tool"
        other.write_text("unrelated")
        (self.share/"FILES").write_text(".local/bin/jobd\n.local/share/abstraction/com.openabstractions.jobd.plist\n")
        result = subprocess.run(["sh", str(HERE/"macos/postinstall")], env=dict(self.env, ACTIVE="active"), text=True, capture_output=True, timeout=SCRIPT_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr)
        import plistlib
        parsed = plistlib.loads(plist.read_bytes())
        self.assertEqual(parsed["ProgramArguments"], [str(self.home/".local/bin/openabstractions"), "serve", "runtime"])
        self.assertEqual(sorted(p.name for p in plist.parent.iterdir()), [plist.name])
        self.assertEqual(sorted(p.name for p in self.share.iterdir() if p.name.startswith(".com.")), [])
        self.assertIn(str(plist), (self.share/"MANIFEST").read_text().splitlines())
        calls = (self.root/"calls").read_text().splitlines()
        renames = [c for c in calls if c.startswith("mv:") and str(plist.parent) in c]
        self.assertEqual(len(renames), 1, calls)
        self.assertTrue(renames[0].startswith("mv:" + str(self.share) + "/.com.openabstractions.jobd.plist."), renames[0])
        self.assertTrue(renames[0].endswith(" -> %s bin=0" % plist), renames[0])
        self.assertLess(next(i for i, c in enumerate(calls) if c.startswith("mv:") and str(plist) in c),
                        calls.index("bootstrap gui/1000 " + str(plist)))
        for directory in [self.share, self.share.parent, self.home/".local", self.payload.parent, plist.parent, self.home/"Library"]:
            self.assertIn("chown:1000:1000 " + str(directory), calls)
            self.assertIn("chmod:u+rwx " + str(directory), calls)
        self.assertNotIn("chown:1000:1000 " + str(self.home), calls)
        self.assertFalse(any(str(other) in line or "chown:-R" in line for line in calls))
        self.assertEqual(other.read_text(), "unrelated")

    def test_macos_refuses_symlink_ancestor_before_ownership_change(self):
        self.command("stat", "echo 1000")
        self.command("chown", 'echo "chown $*" >> "$LOG"')
        self.template()
        outside = self.root/"outside"
        outside.mkdir()
        (outside/"file").write_text("untouched")
        (self.home/"escape").symlink_to(outside, target_is_directory=True)
        (self.share/"FILES").write_text("escape/file\n")
        result = subprocess.run(["sh", str(HERE/"macos/postinstall")], env=self.env, text=True, capture_output=True, timeout=SCRIPT_TIMEOUT)
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
        # The payload carries only a template; postinstall places the plist.
        payload = (HERE/"payload.tsv").read_text()
        self.assertNotIn("Library/LaunchAgents", payload)
        self.assertIn(".local/share/abstraction/com.openabstractions.jobd.plist\tauthored\tposix\t\tmacos/com.openabstractions.jobd.plist", payload)

    def test_macos_manager_watchdog_bounds_only_its_child(self):
        self.command("launchctl", 'trap "" TERM; exec sleep 5')
        helper = self.mac_helper.replace("ticks=200", "ticks=1").replace("ticks=20", "ticks=1")
        self.assertEqual(helper.count("ticks=1\n"), 2)
        (self.share/"lifecycle.sh").write_text(helper)
        result = subprocess.run(["sh", "-c", '. "$HOME/.local/share/abstraction/lifecycle.sh"; manager list'], env=self.env, text=True, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("timed out", result.stderr)
        self.assertTrue(self.payload.exists())

if __name__ == "__main__":
    unittest.main()
