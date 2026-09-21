# Windows package layout

The Windows redistributable installs the shared OA runtime, the
`openabstractions` operator command and the Abstraction Panel. Per-user install
is the default and starts a runtime for that user. A machine-scope installation
registers the same per-user runtime host for interactive accounts.

Release availability, signatures and qualification belong to the selected
redist release. This page describes the source candidate's two MSI layouts,
`abstraction-x64.msi` and `abstraction-arm64.msi`, and their four selectable
features:

| feature | default | what it is |
|---|---|---|
| Background supervisor | on, cannot be unticked | `openabstractions` and its windowless link `openabstractionsw`, and whatever starts the runtime host: a per-user service for everyone, a Startup shortcut for just you |
| Examples and the panel | on | three examples that run `openabstractions status`, `download` and `jobs` against this install, plus Abstraction Panel |
| Add to PATH | on, a tick of its own | `tools\` on `PATH`; untick it and the programs are still installed |
| Developer files | off | `USING.txt` with the Go module paths and client package names, and the optional curl adapter header when a build carries it |

`openabstractions` is the one command. `openabstractions download` submits a
download to the installed runtime and copies the result out;
`openabstractions jobs list|show|wait|cancel|result` observes and controls the
work it submitted; `openabstractions status` reports readiness. None of them
names a store: they resolve the runtime's services the way an application does.
`jobd`, `jobdw`, `dl`, `jobctl` and the Python file-store packages leave the
package in 0.2.0 ([docs/REMOVED.md](https://github.com/openabstractions/abstractions/blob/main/docs/REMOVED.md)).

## What lands where

    OpenAbstractions\
      tools\      openabstractions.exe, openabstractionsw.exe, the panel — the one folder on PATH
      examples\   three folders, each one runnable .cmd
      dev\        USING.txt, and the curl adapter header when packed

`payload.tsv`'s `path` column is that layout: `validate.py` fails a package that
installs a file anywhere else, fails an executable in a folder no `PATH` entry
names, and fails a `PATH` entry that is anything but the resolved `tools\`
directory itself — so the programs cannot move out from under `PATH`.

## Two scopes, and which one is the baseline

The package is **dual-purpose**: `Scope="perUserOrMachine"`, and the person
chooses.

| chosen | goes to | `PATH` | markers | what runs the runtime host | needs |
|---|---|---|---|---|---|
| **Just me** (the default) | `%LOCALAPPDATA%\Programs\OpenAbstractions` | the user's `PATH` | `HKCU` | immediate activation, a Startup shortcut for subsequent sign-ins, and on-demand activation by `openabstractions start` or an SDK | nothing |
| Everyone | `%ProgramFiles%\OpenAbstractions` | the machine `PATH` | `HKLM` | a per-user service: your own session, no password stored, restarted when it dies | administrator |

Per-user is the default and stays installable with no rights at all, because
`METHOD.md` §14 lets a layer require *a helper process the library can start
itself, user-scope* and lets it require *a system service needing admin* only
as an upgrade. Asked for all users from a token without the rights, Windows
refuses by name — error 1925, *you do not have sufficient privileges to
complete this installation for all users of the machine* — and installs
nothing.

## How the runtime host starts

`openabstractions serve host` owns the Windows runtime's lifetime in both
scopes. It starts
`openabstractions.exe serve runtime --supervised` in a kill-on-close job
object, restarts it after 2 s, 10 s and 30 s, and exits with failure on the
fourth consecutive failure. It exits cleanly when a runtime already answers the
user's endpoint, so every activation below is idempotent.
`openabstractionsw.exe` is the same program linked with no console, and it is
the image every automatic start runs.

**Installed for everyone: a per-user service.** A template registered with
`SERVICE_USER_OWN_PROCESS`, which the operating system clones into every
interactive session as `<name>_<luid>`, running as that person with no password
stored and restarted when it dies (3 s, 10 s, 30 s). Its image is
`openabstractionsw.exe serve host --service`. Registering the template needs an
administrator once; a deferred custom action runs `openabstractions host
register` during a fresh install, and `host unregister` deletes the template and
every instance on removal. A custom action is used because `ServiceInstall`
cannot express the type. The installing session is served on demand by
`openabstractions start` or an SDK; the SCM instance takes over at the next
sign-in.

**Installed just for you:** installation runs `openabstractionsw.exe start
--require-unelevated` after finalization. `start` refuses an elevated token,
launches `openabstractionsw.exe serve host` detached and waits for readiness. A
Startup shortcut runs `openabstractionsw.exe serve host` at subsequent sign-ins.
The host holds a hidden session window, so Restart Manager and sign-out end it
gracefully, and it calls `RegisterApplicationRestart`. A host that exits is
started again by the next `openabstractions start`, SDK activation or sign-in.
The Go and C++ facades and the Go logging SDK activate an installed runtime
whose endpoint is absent, once within the call's budget.

**Upgrades stop nothing.** Restart Manager stays on
(`MSIRESTARTMANAGERCONTROL=0`, `MSIRMSHUTDOWN=0`) and ends the running host at
`InstallValidate`, before any custom action. The early script, flushed by an
`InstallExecute` before any file is replaced, holds the upgrade exclusion
(`service begin-upgrade`), registers its release at commit (`service
end-upgrade`) and registers the rollback activation (`service start --related`
per-user, `service start --machine` for everyone). While the exclusion is held,
`start`, `serve host` and SDK activation of the folders being replaced exit 3.
The rollback activation releases the record and runs the previous version's own
activation: `jobdw.exe start --runtime` for 0.1.6 and 0.1.7,
`openabstractionsw.exe start` from 0.1.8, and `sc start` of stopped per-session
instances for everyone. Restart Manager restarts a host that registered for
restart when the transaction ends; that and `StartUserRuntime` meet at one
endpoint and one of them exits. Every installer command appends its failure to
`upgrade-v1\installer-actions.txt` beside its scope's exclusion record, because
Windows Installer discards custom action output.

`RemoveExistingProducts` runs after `InstallFinalize`: the predecessor is removed
once this version is committed, so a failure at any earlier point leaves the
previous version installed, registered and restartable. The predecessor's own
uninstall then runs in its own transaction, which removes its `jobd.exe`,
`dl.exe` and `jobctl.exe`; a shipped 0.1.5 or 0.1.6 also deletes the shared
service on its way out. Nothing deferred can run after `InstallFinalize`, so a
machine upgrade registers the host from `RegisterSupervisorAfterRemoval`, an
immediate checked action scheduled after the removal, and the in-transaction
`RegisterSupervisor`/`RollbackSupervisor` pair is limited to installs with no
predecessor. Per-user activation follows that action.

Downloads a predecessor's `dl` or `jobd` left unfinished in the legacy job store
(`%USERPROFILE%\.abstraction` by default) are abandoned at upgrade. Their
records and partial files stay where they are; nothing reads or finishes them,
and removal leaves them as user data.

The runtime supervises configured capability processes. Use
`openabstractions status --json` to inspect capability readiness. Installed
registration, a running process and successful identity verification each have
separate evidence. Host diagnostics, including the token's elevation, are in
`%LOCALAPPDATA%\openabstractions\host\host.log`.

There is **no scheduled task.** A five-minute `jobd once` sweep was a second
writer over a store the supervisor already owned, and a console window every
five minutes for ever — `FOOTPRINT.md`'s 2026-09-06 rows record that exact
experience being removed from a different program of ours.

## Install

    msiexec /i abstraction-x64.msi

    msiexec /i abstraction-x64.msi /qn ADDLOCAL=Service,Tools,Path,Developer

`APPLICATIONFOLDER=` overrides the install folder. `ALLUSERS=1` asks for the
machine scope.

The `openabstractions` console command also runs individual capabilities in
the foreground: `openabstractions serve logging`, `openabstractions serve
config` and `openabstractions serve router-v1`. The installed runtime supervises
its configured capabilities without them.

## Build it

WiX needs no .NET SDK. Unzip the two NuGet packages and run the tool:

    curl -Lo wix.zip https://api.nuget.org/v3-flatcontainer/wix/5.0.2/wix.5.0.2.nupkg
    curl -Lo ui.zip  https://api.nuget.org/v3-flatcontainer/wixtoolset.ui.wixext/5.0.2/wixtoolset.ui.wixext.5.0.2.nupkg
    unzip -q wix.zip -d wix && unzip -q ui.zip -d ui

    py -3 installer/build.py --arch x64 --version 0.2.0 \
      --wix wix/tools/net6.0/any/wix.exe \
      --ext ui/wixext5/WixToolset.UI.wixext.dll --out dist \
      --src charter=<abstractions> --src panel=<abstractions>

With only a .NET runtime installed, run the same `wix.dll` through
`dotnet exec --roll-forward Major wix/tools/net6.0/any/wix.dll`, wrapped in a
one-line `.cmd` given to `--wix`.

`build.py` stages every `payload.tsv` row, writes `license.rtf` through
`mklicense.py`, runs `validate.py` and calls `wix build`. A source not named
with `--src` is left out, and it refuses to build a package missing a file
`abstraction.wxs` cannot gate away — which is how the UNRESOLVED rows leave the
package without anyone editing anything.

`--bin DIR` takes the programs from `DIR` instead of building them. That is the
release route: a package assembled out of published module versions, with no
repository checked out, which is what `openabstractions/redist` does and what a
stranger can reproduce.

**What comes out is unsigned**, and Windows will name the publisher unknown.
Signing is a separate, manually approved step, outside this build and outside
the release workflow, and it signs the programs inside each MSI as well as each
MSI — see `signpath.artifact-configuration.xml`.

## Check it

    py -3 installer/validate.py [package.msi ...] [--wix <wix>]

It parses `abstraction.wxs`, cross-checks it against `payload.tsv` and
`sources.tsv`, refuses a file that is in one and not the other or that two
features install, refuses a file that lands anywhere but its `payload.tsv`
path, refuses an executable no `PATH` entry reaches, refuses a signing target
that is not a PE file, refuses a source pinned to anything but a 40-hex commit,
and prints the signing targets.
`installer/signpath.artifact-configuration.xml` is checked against that list, so
adding a program without adding it to the signing configuration is a red build.

Given a built package it reads it back with `wix msi decompile` and refuses one
carrying a file `abstraction.wxs` does not install, or missing one it does and
cannot gate away.

The installed per-user fixture, `test_user_runtime.ps1 -CheckTools`, downloads
a file from a loopback origin through the installed runtime with no store
named, reads it back with `jobs show`, `jobs list` and `jobs result --out
<file>`, and requires an equal submission to return the original operation.

## What may break

- **The optional curl adapter header has no verified public commit.** Its
  declared home is `abstraction-download-over-curl`, but the public repository
  had no refs when checked on 2026-09-12. Its row remains `UNRESOLVED` and gated
  by `$(var.Cpp)`. Panel has a public module and a `tools.tsv` row; it is included
  when its prebuilt executable or source is supplied.
- **Large results move through 64 KiB exchanges.** `openabstractions download`
  and `jobs result` copy a result through the runtime's `ReadResult`; an 8 GiB
  file is about 131,000 exchanges. Typed result references are designed
  (VISION.md 2026-09-15) and not built.
- **Machine-scope evidence depends on the release run.** The workflow checks
  registration, configuration and recovery policy; a running per-user service
  instance also requires a suitable session. Read the run result and any
  explicit preview limitation; source tables alone do not prove installation.
- **Per-user verification uses a fresh non-administrator account.** The release
  workflow checks immediate readiness, removal, an upgrade from the predecessor
  release the caller names with `-PredecessorVersion`, and same-version reinstall
  in that account. The release run records their actual outcomes.
- **`sources.tsv` is behind the published tags.** Both pins resolve, neither is a
  tag any more.
- **The stop-free upgrade sequence needs an installed test.** WiX linking and
  MSI table inspection (`test_upgrade_sequence.py --wix`) verify that the
  exclusion executes before the new files, that no action stops a process and
  that the predecessor goes after the commit. Isolated tests cover the host's
  restart registration, a real `RmShutdown` of an inert host and its child, and
  the rollback activation mapping. Whether Restart Manager restarts a registered
  host after a real upgrade, the rollback activation of an installed 0.1.7, and
  the Startup shortcut's component after a late removal are measured only by an
  installed upgrade.
- **The machine-scope post-removal registration is unmeasured.**
  `RegisterSupervisorAfterRemoval` runs in the immediate sequence, so it reaches
  the SCM with the token that started msiexec. A machine upgrade driven from an
  elevated session has it; whether an upgrade started from Explorer's
  "for everyone" path does has not been measured. Its failure is checked, not
  ignored: the upgrade reports the error and re-running the installer registers
  the supervisor through `RegisterSupervisor`.
- **A quiet removal exits 0 while a reboot is still needed.** `msiexec /x
  /qn /norestart` sets `REBOOT=ReallySuppress`. When Restart Manager finds a
  critical application holding the product's files, Windows Installer moves the
  files aside, schedules their deletion for the next reboot (Info 1903) and
  logs "Removal success or error status: 0". Hosted run 34906434707 did this
  and left the runtime running. No package mechanism reports that state:
  `MsiRMFilesInUse` is shown only at full UI, `REBOOTPROMPT` only suppresses
  prompts, and `ReplacedInUseFiles` is set when an installation overwrites a
  file in use and was absent from that removal's log. The removal log records
  it. `test_removal_log.py` reads it, and the per-user fixture fails its removal
  verdict with the log's cause before its process deadline.
- **The paths in `signpath.artifact-configuration.xml` are how we think SignPath
  addresses a file inside an MSI, and nobody has submitted one.** The element
  vocabulary is as written from memory of the schema. `validate.py` keeps that
  file and `payload.tsv` in step; it cannot check what SignPath will accept.
