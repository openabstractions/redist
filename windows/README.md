# Windows package layout

The Windows redistributable installs the shared OA runtime, the
`openabstractions` operator command and the Abstraction Panel. Per-user install
is the default and starts a runtime for that user. A machine-scope installation
registers the same per-user runtime host for interactive accounts.

Release availability, signatures and qualification belong to the selected
redist release. This page describes the source candidate's two MSI layouts,
`abstraction-x64.msi` and `abstraction-arm64.msi`. Qualification evidence, the
build steps and the validation checks for this package are in
[QUALIFICATION.md](QUALIFICATION.md).

## What you get

    OpenAbstractions\
      tools\      openabstractions.exe, openabstractionsw.exe, the panel — the one folder on PATH
                  inventoryd.exe and openabstractions-mcp.exe, when their features are ticked
        declarations\  the four default host declarations, and local-stores.json with the feature
      examples\   three folders, each one runnable .cmd
      dev\        USING.txt, and the curl adapter header when packed

`tools\declarations\` holds the declaration files the installation places
beside the runtime executable: Lemonade, LM Studio, Ollama and ComfyUI at
their documented local ports, as `abstraction.facade/registry@1` declarations
of role `host`. The runtime reads them at start and lists them as declared by
the installation. An operator who removes one has that removal recorded in
the runtime's own state, so this package writing the file again on a repair
or an upgrade does not bring the host back. `installer/posix/declarations/`
ships the same four files into `~/.local/bin/declarations`, and a serve test
holds both copies to the router's `Installed()`.

`payload.tsv`'s `path` column is that layout: `validate.py` fails a package that
installs a file anywhere else, fails an executable in a folder no `PATH` entry
names, and fails a `PATH` entry that is anything but the resolved `tools\`
directory itself — so the programs cannot move out from under `PATH`.

## Scope

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

`openabstractions serve host` owns the Windows runtime's lifetime in both
scopes. It starts `openabstractions.exe serve runtime --supervised` in a
kill-on-close job object, restarts it after 2 s, 10 s and 30 s, and exits with
failure on the fourth consecutive failure. It exits cleanly when a runtime
already answers the user's endpoint, so every activation below is idempotent.
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

**Just for you, the Panel also gets a Startup shortcut**, running
`Abstraction Panel.exe --tray`: a notification-area icon that polls for
pending questions and opens the Panel to them (monitor/README.md,
"Notifications"). Installed for everyone, this is left off for every
account; enable it for your own sign-in by adding a shortcut to
`Abstraction Panel.exe --tray` to your Startup folder (Win+R,
`shell:startup`).

Host diagnostics, including the token's elevation, are in
`%LOCALAPPDATA%\openabstractions\host\host.log`. Use `openabstractions status
--json` to inspect capability readiness; installed registration, a running
process and successful identity verification each have separate evidence.

There is **no scheduled task;** the background supervisor above is the only
automatic starter of the runtime host.

## Features

| feature | `ADDLOCAL` name | default | what it is |
|---|---|---|---|
| Background supervisor | `Service` | on, cannot be unticked | `openabstractions` and its windowless link `openabstractionsw`, and whatever starts the runtime host: a per-user service for everyone, a Startup shortcut for just you |
| Examples and the panel | `Tools` | on | three examples that run `openabstractions status`, `download` and `jobs` against this install, plus Abstraction Panel |
| Add to PATH | `Path` | on, a tick of its own | `tools\` on `PATH`; untick it and the programs are still installed |
| Local model stores | `LocalStores` | on | `inventoryd`, the `abstraction.storage/inventory-source@1` provider, and the declaration file that declares it |
| Model host | `ModelHost` | off | `modelhostd`, the provider that loads one model file with a llama.cpp you already have and holds it under a lease, and the declaration file that declares it |
| MCP gateway | `McpGateway` | off | `openabstractions-mcp`, the local stdio MCP server |
| Developer files | `Developer` | off | `USING.txt` with the Go module paths and client package names, and the optional curl adapter header when a build carries it |
| NAS downloads | `NasDownload` | held, hidden | a reserved name that installs nothing; see below |

A provider is a separate process the runtime launches or attaches to, and it
versions with the runtime it serves. Each one is a feature of this package
rather than an installer of its own (`VISION.md` 2026-09-22). The feature
places the program in `tools\` and its declaration file in
`tools\declarations\`; the runtime reads that directory at start and lists
what it finds as declared by the installation. Removing the feature removes
both, so no declaration outlives the program it named. An operator who
withdraws one has that withdrawal recorded in the runtime's own state, and
reinstalling the feature does not bring the provider back.

A declaration file names its program the way the Panel is named: a file name,
resolved beside the installed runtime. The install folder is chosen when the
package is installed and cannot be written into a file the package carries.
`validate.py` fails a declaration whose program is not a file the same feature
installs beside the runtime.

**Local model stores**, on by default. `inventoryd` reads Ollama, Hugging
Face, LM Studio, ComfyUI, FastFlowLM and Jan, and reports what each one holds
and which program's own index says it uses each thing. It reads listings,
sizes and index files; it hashes nothing and writes in no store. Reading is
the line the rights model draws and it is the line this default follows. The
declaration accepts those six stores by name; the runtime serves a described
store only when an `abstraction.storage/inventory.provide` rule for it exists
as well.

**Model host**, off by default. `modelhostd` loads one model file this
machine already holds with a `llama-server` this machine already has, serves
it through the runtime like any other provider, and holds its residency under
a lease of `abstraction.resource/leases@1`, so the card can be asked back. It
ships no engine and no model and downloads neither: the engine is a path
given to `openabstractions models host`, and a machine with no llama.cpp
refuses every call `no_engine`. Its declaration is written by that command
rather than by this package, because the objects and the engine path are the
person's choice; the feature installs the program and nothing else runs until
a model is hosted. The runtime writes the program one rule,
`abstraction.resource/hold` on `card:0`, when the declaration lands; deny it
and the host holds nothing.

**MCP gateway**, off by default. `openabstractions-mcp` is a local stdio MCP
server an assistant starts by its absolute path; the runtime never starts it,
and it ships no declaration. Installing it grants it nothing. Its rights are
the Panel's kind — rules an operator writes for one exact executable path —
and `mcp-gateway/README.md` names them: `abstraction.facade/application.read`
on each `app:<name>` it should see, `abstraction.router/inventory.read` on
`abstraction.router/inventory`, `abstraction.inference/complete` on each
`host:<name>` it may use, and `abstraction.job/acceptance.submit` on
`abstraction.job/acceptance@1` for durable work. Do not copy the runtime's own
broad installation grants onto it.

**NAS downloads** is a held name that installs nothing on this machine; the
runtime only writes a job record into a share a `jobd` elsewhere watches. Its
feature stays at level 0 and hidden until that delegator becomes a program.

## Commands

`openabstractions` is the one command. `openabstractions download` submits a
download to the installed runtime and copies the result out;
`openabstractions jobs list|show|wait|cancel|result` observes and controls the
work it submitted; `openabstractions status` reports readiness. None of them
names a store: they resolve the runtime's services the way an application does.
`jobd`, `jobdw`, `dl`, `jobctl` and the Python file-store packages leave the
package in 0.2.0 ([docs/REMOVED.md](https://github.com/openabstractions/abstractions/blob/main/docs/REMOVED.md)).

    msiexec /i abstraction-x64.msi

    msiexec /i abstraction-x64.msi /qn ADDLOCAL=Service,Tools,Path,LocalStores

    msiexec /i abstraction-x64.msi /qn ADDLOCAL=ALL REMOVE=Developer

Add a feature to an installation that does not have it:

    msiexec /i abstraction-x64.msi /qn ADDLOCAL=McpGateway

or Apps and features → Abstraction → Modify → Change, which reopens the same
feature list. Nothing here is advertised and nothing is permanent, so a
feature left out today is added later without reinstalling the product, and
`REMOVE=LocalStores` takes a feature away with its declaration file.

`APPLICATIONFOLDER=` overrides the install folder. `ALLUSERS=1` asks for the
machine scope.

The `openabstractions` console command also runs individual capabilities in
the foreground: `openabstractions serve logging`, `openabstractions serve
config` and `openabstractions serve router-v1`. The installed runtime supervises
its configured capabilities without them.

## Uninstall

Remove the product from **Settings → Apps** (search **Abstraction**), or run:

    msiexec /x abstraction-x64.msi

Add `/qn` for a silent removal. A quiet removal can report success while a
reboot is still pending; [QUALIFICATION.md](QUALIFICATION.md) records the
observed case and how the removal log shows it.

## Upgrade

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
`openabstractionsw.exe start` from 0.2.0, and `sc start` of stopped per-session
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
