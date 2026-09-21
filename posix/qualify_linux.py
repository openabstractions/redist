"""Qualify the Linux per-user package against a real systemd user manager.

Run as root on a disposable Linux host with systemd as PID 1 (for example WSL
Ubuntu with systemd enabled):

  python3 installer/posix/qualify_linux.py --run \\
      --archive abstraction-<version>-linux-amd64.tar.gz \\
      --ipc-prefix <installed shared abstraction_ipc prefix> \\
      --python <directory holding installed identity, facade, logging and config packages> \\
      --evidence evidence.json [--account NAME] [--source-revision REV]

The fixture creates one temporary nonadmin account, a temporary linger record
and that account's user manager. It installs the archive with its own
install.sh and runs installation, identity, recovery, reinstall and removal
cases as that account. Identity cases use the shared native selection through
the installed Python client, including a seccomp policy that denies clone3 and
must yield PROOF_UNAVAILABLE. Cleanup always stops the user manager and removes
the linger record, account and home, then verifies their absence. Root's own
user manager must hold no abstraction units before and after. The exit status
is zero only when every case passed and cleanup completed.
"""
import argparse
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

UNITS = ("abstraction-runtime.service",)
PROGRAMS = ("openabstractions",)

PROBE = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
from abstraction.ipc import Library, FrameError, ServerExpectation
NAMES = ["OK", "TIMEOUT", "DISCONNECTED", "IO_ERROR", "INVALID_ARGUMENT", "NO_MEMORY",
         "INTERNAL_ERROR", "CANCELLED", "UNTRUSTED", "PROOF_UNAVAILABLE"]
mode = sys.argv[2]
out = {"mode": mode}
def frame_status(error):
    return NAMES[error.status] if 0 <= error.status < len(NAMES) else str(error.status)
try:
    library = Library()
    if mode == "select":
        selected = library.select_runtime(timeout=5)
        out.update(status="OK", principal_kind=selected.principal_kind,
                   principal=selected.principal, program=selected.program)
    elif mode == "trusted":
        from abstraction.facade.client import Machine
        import abstraction.config as config
        import abstraction.logging as logging
        machine = Machine(library=library, timeout=5)
        snapshot = machine.resolve_config(scope="local").read(config.RunOverrides())
        machine.resolve_log(scope="local").write(logging.Record(
            schema=1, time="2026-09-15T12:00:00.000000Z", level=2,
            msg="linux qualification", attrs={"fixture": "qualify_linux"}))
        out.update(status="OK", config_stamp=snapshot.stamp, endpoint=library.runtime_endpoint())
    elif mode == "wrong-program":
        from abstraction.facade.client import Machine
        selected = library.select_runtime(timeout=5)
        wrong = ServerExpectation(selected.principal_kind, selected.principal, selected.program + ".wrong")
        Machine(library=library, server=wrong, timeout=5).resolve_config(scope="local")
        out.update(status="OK")
    else:
        out.update(status="EXCEPTION", detail="unknown probe mode")
except FrameError as error:
    out.update(status=frame_status(error), detail=str(error))
except Exception as error:
    # A resolve refusal chains the transport failure as __cause__.
    if isinstance(error.__cause__, FrameError):
        out.update(status=frame_status(error.__cause__), resolution=getattr(error, "status", None),
                   detail=f"{error}: {error.__cause__}")
    else:
        out.update(status="EXCEPTION", detail=f"{type(error).__name__}: {error}")
print(json.dumps(out))
'''


class Failure(Exception):
    pass


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tail(result, limit=1200):
    return (result.stdout + result.stderr).strip()[-limit:]


def pidfd_supported():
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.syscall(434, os.getpid(), 0)  # pidfd_open
    if fd < 0:
        return f"errno {ctypes.get_errno()}"
    os.close(fd)
    return "available"


class Qualification:
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.uid = self.gid = None
        self.home = None
        self.evidence = {"cases": [], "cleanup": {}}

    # -- process helpers -------------------------------------------------
    def root(self, argv, timeout=60, check=True, env=None):
        result = subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                                timeout=timeout, env=env, stdin=subprocess.DEVNULL)
        if check and result.returncode:
            raise Failure(f"{' '.join(map(str, argv[:3]))} exited {result.returncode}: {tail(result, 500)}")
        return result

    def user_env(self):
        return {"HOME": self.home, "USER": self.account, "LOGNAME": self.account, "LANG": "C.UTF-8",
                "PATH": f"{self.home}/.local/bin:/usr/local/bin:/usr/bin:/bin",
                "XDG_RUNTIME_DIR": f"/run/user/{self.uid}",
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{self.uid}/bus"}

    def user(self, argv, timeout=60, check=True, extra=None):
        env = dict(self.user_env(), **(extra or {}))
        command = ["runuser", "-u", self.account, "--", "env", "-i"] + [f"{k}={v}" for k, v in env.items()]
        result = subprocess.run(command + [str(a) for a in argv], capture_output=True, text=True,
                                timeout=timeout, cwd="/", stdin=subprocess.DEVNULL)
        if check and result.returncode:
            raise Failure(f"{' '.join(map(str, argv[:3]))} exited {result.returncode}: {tail(result, 500)}")
        return result

    def root_env(self):
        return dict(os.environ, HOME="/root", XDG_RUNTIME_DIR="/run/user/0",
                    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/0/bus")

    def record(self, case, ok, **detail):
        self.evidence["cases"].append({"case": case, "pass": bool(ok), **detail})
        print(("PASS " if ok else "FAIL ") + case + " " + json.dumps(detail, sort_keys=True, default=str), flush=True)
        if not ok:
            raise Failure(case)

    def show(self, unit, *properties):
        result = self.user(["systemctl", "--user", "show", unit, "--property=" + ",".join(properties)], timeout=30)
        return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)

    def wait(self, predicate, seconds, interval=0.2):
        end = time.monotonic() + seconds
        while True:
            value = predicate()
            if value or time.monotonic() >= end:
                return value
            time.sleep(interval)

    def probe_command(self, mode):
        return ["/usr/bin/python3", "-I", self.probe_path, self.args.python, mode]

    def parse_probe(self, result):
        lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
        if not lines:
            return {"status": "NO_OUTPUT", "rc": result.returncode, "detail": tail(result, 500)}
        return json.loads(lines[-1])

    def probe(self, mode):
        return self.parse_probe(self.user(self.probe_command(mode), timeout=60, check=False,
                                          extra={"ABSTRACTION_IPC_PREFIX": self.args.ipc_prefix, "PYTHONDONTWRITEBYTECODE": "1"}))

    def probe_transient(self, mode, deny_clone3):
        argv = ["systemd-run", "--user", "--wait", "--pipe", "--quiet", "--collect",
                f"--unit=oa-qualification-probe-{uuid.uuid4().hex[:12]}",
                f"--setenv=ABSTRACTION_IPC_PREFIX={self.args.ipc_prefix}", "--setenv=PYTHONDONTWRITEBYTECODE=1"]
        if deny_clone3:
            argv += ["--property=SystemCallFilter=~clone3", "--property=SystemCallErrorNumber=ENOSYS"]
        return self.parse_probe(self.user(argv + self.probe_command(mode), timeout=90, check=False))

    def probe_root(self, mode):
        return self.parse_probe(self.root(self.probe_command(mode), timeout=60, check=False,
                                          env=dict(self.root_env(), ABSTRACTION_IPC_PREFIX=self.args.ipc_prefix, PYTHONDONTWRITEBYTECODE="1")))

    def status(self, program="openabstractions"):
        result = self.user([program, "status", "--json", "--timeout", "10s"], timeout=40, check=False)
        try:
            report = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return False, {"rc": result.returncode, "detail": tail(result, 500)}
        contracts = {item["contract"]: item.get("status") for item in report.get("capabilities", [])}
        ok = result.returncode == 0 and contracts and all(v == "resolved" for v in contracts.values())
        return ok, {"rc": result.returncode, "bootstrap": report.get("bootstrap"), "contracts": contracts,
                    "error": report.get("error")}

    def root_abstraction_units(self):
        env = self.root_env()
        if not Path("/run/user/0/bus").exists():
            return {"manager": "absent"}
        files = self.root(["systemctl", "--user", "list-unit-files", "abstraction*", "--no-legend"], env=env, check=False)
        units = self.root(["systemctl", "--user", "list-units", "abstraction*", "--all", "--no-legend"], env=env, check=False)
        return {"manager": "running", "unit_files": files.stdout.split(), "units": units.stdout.split()}

    # -- account ---------------------------------------------------------
    def create_account(self):
        import pwd  # POSIX-only; help remains available on every platform
        try:
            pwd.getpwnam(self.account)
            raise Failure(f"account {self.account} already exists; choose another --account")
        except KeyError:
            pass
        if Path("/var/lib/systemd/linger", self.account).exists():
            raise Failure(f"linger record for {self.account} already exists")
        self.root(["useradd", "--create-home", "--user-group", "--shell", "/bin/bash", self.account])
        entry = pwd.getpwnam(self.account)
        self.uid, self.gid, self.home = entry.pw_uid, entry.pw_gid, entry.pw_dir
        self.evidence["account"] = {"name": self.account, "uid": self.uid, "home": self.home}
        self.root(["loginctl", "enable-linger", self.account])
        self.root(["systemctl", "start", f"user@{self.uid}.service"], timeout=90)
        state = self.wait(lambda: self.user(["systemctl", "--user", "is-system-running"], timeout=20, check=False).stdout.strip()
                          in ("running", "degraded") and self.user(["systemctl", "--user", "is-system-running"], timeout=20, check=False).stdout.strip(), 30, 0.5)
        self.record("precondition: temporary account's user manager is ready", bool(state), uid=self.uid, state=state)

    def cleanup(self, root_before):
        c = self.evidence["cleanup"]
        if self.uid is None:
            c["account_created"] = False
            c["complete"] = self.account is None or not self.account_exists()
            return
        c["account_created"] = True
        self.root(["loginctl", "disable-linger", self.account], check=False)
        stop = self.root(["systemctl", "stop", f"user@{self.uid}.service"], timeout=90, check=False)
        c["user_manager_stop_rc"] = stop.returncode
        self.root(["loginctl", "terminate-user", self.account], timeout=30, check=False)
        remaining = self.wait(lambda: self.root(["pgrep", "-u", str(self.uid)], check=False).returncode != 0, 20)
        c["processes_exited_without_kill"] = bool(remaining)
        if not remaining:
            self.root(["pkill", "-KILL", "-u", str(self.uid)], check=False)
            c["forced_process_kill"] = self.wait(lambda: self.root(["pgrep", "-u", str(self.uid)], check=False).returncode != 0, 10)
        userdel = self.root(["userdel", "--remove", self.account], timeout=60, check=False)
        c["userdel_rc"] = userdel.returncode
        c["account_absent"] = not self.account_exists()
        c["home_absent"] = not Path(self.home).exists()
        c["linger_absent"] = not Path("/var/lib/systemd/linger", self.account).exists()
        c["runtime_dir_absent"] = bool(self.wait(lambda: not Path(f"/run/user/{self.uid}").exists(), 15))
        manager = self.root(["systemctl", "show", f"user@{self.uid}.service", "--property=ActiveState", "--value"], check=False)
        c["user_manager_state"] = manager.stdout.strip()
        root_after = self.root_abstraction_units()
        c["root_manager_units_unchanged"] = root_after == root_before
        c["root_manager_after"] = root_after
        c["complete"] = all([c["account_absent"], c["home_absent"], c["linger_absent"], c["runtime_dir_absent"],
                             c["user_manager_state"] in ("inactive", "failed", ""), c["root_manager_units_unchanged"]])
        print("CLEANUP " + json.dumps(c, sort_keys=True), flush=True)

    def account_exists(self):
        import pwd
        try:
            pwd.getpwnam(self.account)
            return True
        except KeyError:
            return False

    # -- cases -----------------------------------------------------------
    def runtime(self):
        return self.show("abstraction-runtime.service", "LoadState", "ActiveState", "MainPID", "NRestarts")

    def ready_status(self, seconds):
        outcome = {}

        def attempt():
            ok, detail = self.status()
            outcome.update(detail)
            return ok
        return bool(self.wait(attempt, seconds, 0.5)), outcome

    def cases(self, archive):
        home = Path(self.home)
        work = home / "qualification"
        self.user(["mkdir", "-p", work / "extract"])
        staged = work / archive.name
        shutil.copyfile(archive, staged)
        os.chown(staged, self.uid, self.gid)
        self.probe_path = str(work / "probe.py")
        Path(self.probe_path).write_text(PROBE, encoding="utf-8")
        os.chown(self.probe_path, self.uid, self.gid)
        self.user(["tar", "-xzf", staged, "-C", work / "extract"], timeout=120)
        packages = [p for p in (work / "extract").iterdir() if p.is_dir()]
        if len(packages) != 1:
            raise Failure(f"expected one package directory, found {[p.name for p in packages]}")
        installer = packages[0] / "install.sh"
        program = str(home / ".local/bin/openabstractions")

        # Installation
        result = self.user([installer], timeout=240, check=False)
        self.record("install: package install.sh completes as the nonadmin account", result.returncode == 0,
                    rc=result.returncode, output=tail(result, 800))
        ok, detail = self.ready_status(20)
        self.record("install: every default runtime contract resolves", ok, **detail)
        unit = self.show("abstraction-runtime.service", "LoadState", "ActiveState", "MainPID", "NRestarts", "Type",
                         "Restart", "RestartUSec", "TimeoutStopUSec", "KillMode", "FragmentPath")
        self.record("install: runtime user unit is loaded and active", unit.get("LoadState") == "loaded"
                    and unit.get("ActiveState") == "active" and unit.get("MainPID", "0") != "0", **unit)
        pid = unit["MainPID"]
        image = os.readlink(f"/proc/{pid}/exe")
        self.record("install: runtime process image is the installed executable",
                    image == os.path.realpath(program), main_pid=pid, image=image,
                    installed_sha256={name: sha256(home / ".local/bin" / name) for name in PROGRAMS})
        started = self.user(["openabstractions", "start", "--timeout", "10s"], timeout=40, check=False)
        self.record("install: start is idempotent for a running runtime",
                    started.returncode == 0 and self.runtime()["MainPID"] == pid,
                    rc=started.returncode, main_pid_after=self.runtime()["MainPID"])

        # A download through the runtime, with no store named.
        served = work / "served"
        served.mkdir()
        payload = uuid.uuid4().hex.encode()
        (served / "thing.bin").write_bytes(payload)
        out = work / "downloaded"
        self.user(["mkdir", "-p", out])
        origin = subprocess.Popen([sys.executable, "-u", "-m", "http.server", "0", "--bind", "127.0.0.1", "--directory", str(served)],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            port = int(origin.stdout.readline().split("port ")[1].split(" ")[0])
            fetched = self.user(["openabstractions", "download", f"http://127.0.0.1:{port}/thing.bin",
                                 "--out", out, "--json", "--timeout", "60s"], timeout=90, check=False)
        finally:
            origin.kill()
            origin.wait(10)
        report = json.loads(fetched.stdout) if fetched.returncode == 0 else {}
        operation = (report.get("receipt") or {}).get("operation_id", "-")
        self.record("download: the runtime fetches it and the command delivers the bytes",
                    fetched.returncode == 0 and (report.get("snapshot") or {}).get("state") == "complete"
                    and (out / "thing.bin").is_file() and (out / "thing.bin").read_bytes() == payload,
                    rc=fetched.returncode, output=tail(fetched, 800))
        shown = self.user(["openabstractions", "jobs", "show", operation, "--json"], timeout=30, check=False)
        observed = json.loads(shown.stdout) if shown.returncode == 0 else {}
        self.record("download: jobs show observes the same operation as complete",
                    shown.returncode == 0 and ((observed.get("snapshot") or {}).get("receipt") or {}).get("operation_id") == operation
                    and (observed.get("snapshot") or {}).get("state") == "complete", rc=shown.returncode, output=tail(shown, 600))

        # Identity
        selected = self.probe("select")
        self.record("identity: native selection returns the loaded unit's principal and program",
                    selected.get("status") == "OK" and selected.get("principal_kind") == 2
                    and selected.get("principal") == str(self.uid) and selected.get("program") == os.path.realpath(program),
                    **selected)
        trusted = self.probe("trusted")
        self.record("identity: default Python client resolves and calls through installation-selected trust",
                    trusted.get("status") == "OK", **trusted)
        wrong = self.probe("wrong-program")
        self.record("identity: a wrong program expectation is refused as UNTRUSTED", wrong.get("status") == "UNTRUSTED", **wrong)
        control = self.probe_transient("select", deny_clone3=False)
        self.record("identity: transient user unit without syscall policy selects normally",
                    control.get("status") == "OK" and control.get("program") == os.path.realpath(program), **control)
        denied = self.probe_transient("select", deny_clone3=True)
        self.record("identity: seccomp policy denying clone3 yields PROOF_UNAVAILABLE",
                    denied.get("status") == "PROOF_UNAVAILABLE", **denied)
        other = self.probe_root("select")
        self.record("identity: an account whose manager has no loaded runtime unit is refused as UNTRUSTED",
                    other.get("status") == "UNTRUSTED", **other)

        # Recovery
        before = self.runtime()
        if os.readlink(f"/proc/{before['MainPID']}/exe") != os.path.realpath(program):
            raise Failure("runtime image changed before crash injection")
        self.user(["systemctl", "--user", "kill", "--kill-whom=main", "--signal=KILL", "abstraction-runtime.service"], timeout=30)
        restarted = self.wait(lambda: (lambda s: s.get("ActiveState") == "active" and s.get("MainPID") not in ("0", before["MainPID"])
                                       and int(s.get("NRestarts", "0")) == int(before["NRestarts"]) + 1 and s)(self.runtime()), 40, 0.5)
        self.record("recovery: SIGKILL of the main process restarts the runtime once", bool(restarted),
                    before=before, after=restarted or self.runtime())
        ok, detail = self.ready_status(30)
        self.record("recovery: every default contract resolves again after restart", ok, **detail)
        reselected = self.probe("select")
        new_image = os.readlink(f"/proc/{restarted['MainPID']}/exe")
        self.record("recovery: selection and replacement image still match the installed executable",
                    reselected.get("status") == "OK" and reselected.get("program") == os.path.realpath(program)
                    and new_image == os.path.realpath(program), selection=reselected, image=new_image)

        # Reinstall over a live predecessor
        sentinel = home / ".local/share/openabstractions/qualification-sentinel"
        token = uuid.uuid4().hex
        self.user(["mkdir", "-p", sentinel.parent])
        self.user(["sh", "-c", 'printf %s "$1" > "$2"', "sh", token, sentinel])
        live = self.runtime()
        result = self.user([installer], timeout=240, check=False)
        after = self.runtime()
        self.record("reinstall: install.sh over the live predecessor replaces and restarts the runtime",
                    result.returncode == 0 and after.get("ActiveState") == "active"
                    and after.get("MainPID") not in ("0", live["MainPID"]),
                    rc=result.returncode, before=live, after=after, output=tail(result, 600))
        ok, detail = self.ready_status(20)
        self.record("reinstall: every default contract resolves after reinstall", ok, **detail)
        trusted = self.probe("trusted")
        self.record("reinstall: installation-selected trust still resolves and calls", trusted.get("status") == "OK", **trusted)

        # Removal
        result = self.user([home / ".local/share/abstraction/uninstall.sh"], timeout=240, check=False)
        states = {u: self.show(u, "LoadState", "ActiveState") for u in UNITS}
        self.record("removal: uninstall.sh completes and every unit is stopped and unregistered",
                    result.returncode == 0 and all(s.get("LoadState") == "not-found" and s.get("ActiveState") == "inactive"
                                                   for s in states.values()),
                    rc=result.returncode, units=states, output=tail(result, 900))
        leftovers = [str(p) for p in [home / ".local/bin" / n for n in PROGRAMS]
                     + [home / ".config/systemd/user" / u for u in UNITS]
                     + [home / ".local/share/abstraction/MANIFEST", home / ".local/share/abstraction/uninstall.sh"] if p.exists()]
        self.record("removal: installed programs, unit files and removal ledger are absent", not leftovers, leftovers=leftovers)
        retained = {"sentinel_intact": sentinel.is_file() and sentinel.read_text() == token,
                    "runtime_state_dir": (home / ".local/share/openabstractions/runtime-v1").exists(),
                    "cache_dir": (home / ".cache/openabstractions").exists()}
        self.record("removal: user data outside the manifest is retained", retained["sentinel_intact"], **retained)
        removed = self.probe("select")
        self.record("removal: selection refuses as UNTRUSTED once the runtime unit is not loaded",
                    removed.get("status") == "UNTRUSTED", **removed)
        # The installed program is gone; the candidate's own executable from the
        # extracted package observes the removed runtime.
        candidate = packages[0] / "payload/.local/bin/openabstractions"
        ok, detail = self.status(candidate)
        reported = bool(detail.get("contracts")) and all(v != "resolved" for v in detail["contracts"].values())
        bootstrap = (detail.get("bootstrap") or {}).get("state")
        self.record("removal: candidate status reports every contract unavailable and the runtime not running",
                    not ok and detail.get("rc", 0) not in (0, 126, 127) and reported and bootstrap != "running",
                    **detail)

    def run(self):
        archive = Path(self.args.archive).resolve()
        self.evidence["candidate"] = {"archive": archive.name, "bytes": archive.stat().st_size, "sha256": sha256(archive),
                                      "source_revision": self.args.source_revision}
        version = self.root(["systemctl", "--version"]).stdout.splitlines()[0]
        self.evidence["platform"] = {"kernel": os.uname().release, "systemd": version, "python": sys.version.split()[0],
                                     "pidfd_open": pidfd_supported(), "pid1": Path("/proc/1/comm").read_text().strip()}
        root_before = self.root_abstraction_units()
        self.evidence["root_manager_before"] = root_before
        passed = False
        try:
            clean = root_before.get("manager") == "absent" or (not root_before["unit_files"] and not root_before["units"])
            self.record("precondition: root user manager holds no abstraction units", clean, **root_before)
            self.create_account()
            self.cases(archive)
            passed = True
        except Failure as error:
            self.evidence["failure"] = str(error)
            print("STOPPED " + str(error), flush=True)
        finally:
            try:
                self.cleanup(root_before)
            finally:
                self.evidence["passed"] = passed and self.evidence["cleanup"].get("complete", False)
                Path(self.args.evidence).write_text(json.dumps(self.evidence, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        print(("PASS" if self.evidence["passed"] else "FAIL") + " Linux package qualification; evidence " + self.args.evidence, flush=True)
        return 0 if self.evidence["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true", help="create the temporary account and run every case")
    parser.add_argument("--archive", help="Linux package tarball under test")
    parser.add_argument("--ipc-prefix", help="installed shared abstraction_ipc prefix (lib/libabstraction_ipc.so)")
    parser.add_argument("--python", help="directory with installed abstraction identity, facade, logging and config packages")
    parser.add_argument("--evidence", help="JSON evidence output path")
    parser.add_argument("--account", default="oaqual" + uuid.uuid4().hex[:8], help="temporary account name (must not exist)")
    parser.add_argument("--source-revision", default="unrecorded", help="source revision the archive was built from")
    args = parser.parse_args()
    if not args.run:
        parser.print_help()
        return 0
    missing = [flag for flag, value in (("--archive", args.archive), ("--ipc-prefix", args.ipc_prefix),
                                        ("--python", args.python), ("--evidence", args.evidence)) if not value]
    if missing:
        parser.error("--run requires " + ", ".join(missing))
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        parser.error("run as root on Linux; the fixture creates and removes a temporary account")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        parser.error("systemd must be PID 1")
    for path in (args.archive, Path(args.ipc_prefix) / "lib/libabstraction_ipc.so", Path(args.python) / "abstraction/ipc"):
        if not Path(path).exists():
            parser.error(f"missing {path}")
    return Qualification(args).run()


if __name__ == "__main__":
    sys.exit(main())
