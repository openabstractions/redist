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
                  inventoryd.exe, modelhostd.exe, lemonaded.exe and openabstractions-mcp.exe, when their features are ticked
        declarations\  the four default host declarations, and local-stores.json and lemonade-image.json with their features
        engines\       reduced llama.cpp b10825 Windows x64 bundle, derivation receipt and license notices with ModelHost
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

`openabstractions serve supervisor` owns the Windows runtime's lifetime in both
scopes. It starts `openabstractions.exe serve runtime --supervised` in a
kill-on-close job object, restarts it after 2 s, 10 s and 30 s, and exits with
failure on the fourth consecutive failure. It exits cleanly when a runtime
already answers the user's endpoint, so every activation below is idempotent.
`openabstractionsw.exe` is the same program linked with no console, and it is
the image every automatic start runs. `serve host` is the old name of the
command, accepted for one release so that a Startup shortcut or service template
written by an earlier version keeps working.

**Installed for everyone: a per-user service.** A template registered with
`SERVICE_USER_OWN_PROCESS`, which the operating system clones into every
interactive session as `<name>_<luid>`, running as that person with no password
stored and restarted when it dies (3 s, 10 s, 30 s). Its image is
`openabstractionsw.exe serve supervisor --service`. Registering the template needs an
administrator once; a deferred custom action runs `openabstractions host
register` during a fresh install, and `host unregister` deletes the template and
every instance on removal. A custom action is used because `ServiceInstall`
cannot express the type. The installing session is served on demand by
`openabstractions start` or an SDK; the SCM instance takes over at the next
sign-in.

**Installed just for you:** installation runs `openabstractionsw.exe start
--require-unelevated` after finalization. `start` refuses an elevated token,
launches `openabstractionsw.exe serve supervisor` detached and waits for readiness. A
Startup shortcut runs `openabstractionsw.exe serve supervisor` at subsequent sign-ins.
The host holds a hidden session window, so Restart Manager and sign-out end it
gracefully, and it calls `RegisterApplicationRestart`. A host that exits is
started again by the next `openabstractions start`, SDK activation or sign-in.
The Go and C++ facades and the Go logging SDK activate an installed runtime
whose endpoint is absent, once within the call's budget.

**Just for you, the Panel also gets a Startup shortcut**, running
`Abstraction Panel.exe --background`: the native Asks presenter that polls for
pending questions in the unlocked session ([Panel window behavior](../monitor/README.md#windows)).
Installed for everyone, this is left off for every
account; enable it for your own sign-in by adding a shortcut to
`Abstraction Panel.exe --background` to your Startup folder (Win+R,
`shell:startup`). Existing `--tray` shortcuts select the same background mode.
Open Abstraction Panel or OpenAbstractions Setup from Start when needed.
The runtime host owns service work; this session process presents Asks dialogs.

Host diagnostics, including the token's elevation, are in
`%LOCALAPPDATA%\openabstractions\host\host.log`. Use `openabstractions status
--json` to inspect capability readiness; installed registration, a running
process and successful identity verification each have separate evidence.

There is **no scheduled task;** the background supervisor above is the only
automatic starter of the runtime host.

**TEMPORARY EXCEPTION: sandbox root entries (installed for everyone).** The
official OpenCode CLI resolves its folder by reading the attributes of every
ancestor from the drive root down, which an OA sandbox cannot do on `C:\` and
`C:\Users`. A machine install therefore runs `openabstractions host
sandbox-roots grant` as LocalSystem after the files are in place: one
non-inherited entry on the system drive's root and one on the profiles
folder, `SYNCHRONIZE` and `FILE_READ_ATTRIBUTES` on the folder itself and
nothing it holds, for the capability every OA sandbox carries
(`S-1-15-3-1024-2690631898-…`, derived from `openabstractions.sandbox`; facade
FAC-P3, provider kit KIT-S7). The command writes with
`SetKernelObjectSecurity`, which changes that folder alone; icacls and
`SetSecurityInfo` would re-propagate inheritance through the whole drive.
`host sandbox-roots revoke` runs on a real removal, and on the rollback of a
fresh install, and removes exactly that entry by SID, rights and flags; a
successor's upgrade keeps it. `host sandbox-roots show` reports both folders
without an administrator. A failure is logged to
`%ProgramData%\abstraction\upgrade-v1\installer-actions.txt` and stops
nothing. A per-user install writes neither entry; the sandboxed start then
names both folders and the official CLI stops at `lstat 'C:\'`. The account's
own folders above a granted path are granted per session and removed at its
exit. All of this goes, together with the capability, once OpenCode's
native-realpath fix is released and pinned (TODO.md "Temporary exception:
sandbox root attributes").

**The protected-operation helper (installed for everyone only).** A machine
install also places `tools\openabstractions-system.exe`, the one program OA
raises a Windows administrator prompt for, after the person's yes in OA's own
prompt (facade FAC-H1..FAC-H4). Its only operation reads one bounded page of
the Windows Security log (logging LOG-N1). It sits under `Program Files`, where
only administrators can change it, and the runtime and the Panel refuse to use
a copy anywhere else. A per-user install leaves it out, and the Security log
then stays refused with a sentence naming the machine-wide installation.

## Features

| feature | `ADDLOCAL` name | default | what it is |
|---|---|---|---|
| Background supervisor | `Service` | on, cannot be unticked | `openabstractions` and its windowless link `openabstractionsw`, and whatever starts the runtime host: a per-user service for everyone, a Startup shortcut for just you |
| Examples and the panel | `Tools` | on | three examples that run `openabstractions status`, `download` and `jobs` against this install, plus Abstraction Panel |
| Add to PATH | `Path` | on, a tick of its own | `tools\` on `PATH`; untick it and the programs are still installed |
| Local model stores | `LocalStores` | on | `inventoryd`, the `abstraction.storage/inventory-source@1` provider, and the declaration file that declares it |
| Model host | `ModelHost` | on | `modelhostd` and, on Windows x64, OA's 24-file llama.cpp b10825 Vulkan bundle for Setup to stage after approval; Windows ARM64 has the provider but no reviewed bundled engine |
| Local image generation | `LemonadeImage` | off, x64 only | `lemonaded`, the provider that serves image generation, transcription and speech through the Lemonade app Setup installs, and its declaration `lemonade-image.json` |
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

**Model host**, on by default in this Windows package. On x64, the MSI carries
`tools\engines\llama-b10825-oa-win-vulkan-x64.zip`, a deterministic bundle
derived from the reviewed publisher archive. It holds only the 24 files that
`modelhostd` permits in the staged engine directory, including the LLVM notice;
the publisher's RPC server and command-line tools are absent. The derivation
receipt and publisher MIT license sit beside it. Setup checks the bundle
against the provider's separate exact size and SHA-256 pin, then stages the
engine after the person approves the chat setup. A manually selected original
publisher ZIP remains an explicit recovery source under its own archive pin.
The MSI does not start or install the engine, and it carries no model. On
Windows ARM64 the ModelHost feature still installs `modelhostd`, but there is
no reviewed ARM64 engine archive or default chat engine to stage. Calls made
before an engine is staged refuse with `engine:none`. `modelhostd` serves
chat and embeddings from a model file this machine holds on that pinned build,
and video on the pinned stable-diffusion.cpp `sd-server`. It serves them
through the runtime like any other provider and holds each residency under a
lease of `abstraction.resource/leases@1`, which lets the card be asked back. Its
PyTorch video and image engine runs on a PyTorch environment the person
supplies and is moving to its own provider module
([contract](https://github.com/openabstractions/abstraction-provider-modelhost/blob/main/CONTRACT.md)).
Its declaration is written by `openabstractions models host` rather than by
this package, because the hosted object and staged engine path are selected
at setup time; nothing runs until a model is hosted. When the declaration
lands, the runtime writes the program two
rules: `abstraction.resource/hold` on `card:0` and on `awake`. Deny the card
rule and the host holds nothing. The provider-held wake is 0.4.0's stated
provisional exception, which a wake lease held for the requesting
application replaces after research (VISION 2026-10-02).

**Local image generation**, off by default and in x64 builds only.
`lemonaded` serves image generation, transcription and speech through the
pinned Lemonade app, and the feature places its declaration
`lemonade-image.json` beside it. Installing the feature starts no engine and
downloads no model: Setup in the Panel installs the Lemonade app and
downloads the reviewed backends and models after the person agrees, then
configures the provider with `lemonaded`'s own verbs.
The runtime starts the provider on the first request that needs it.

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

## OpenAbstractions Setup

`OpenAbstractions-Setup-<version>.exe` is a WiX Burn bundle that installs this
package and, as one optional step, the showcase applications' own per-user
MSIs (VISION 2026-10-06). `apps/build_app.py` builds an application MSI from
the release's application ZIP and `adopters/<app>/application-manifest.json`;
it installs to `%LOCALAPPDATA%\OpenAbstractions\apps\<id>` and starts the
Panel the core package records, where the person confirms the registration.
It reads that Panel only from the registry, never from the command line.
Without OpenAbstractions it refuses and names the release page,
https://github.com/openabstractions/redist/releases/latest; it downloads
nothing.
`apps/build_bundle.py` builds the bundle from a chain file that pins every
package by SHA-256 and size. The chain is the core MSI first and then the
applications, each behind a checkbox on the standard bootstrapper theme's
Options page. After the build it reads the bundle's own manifest and checks
the chain order and each package's size and SHA-512 against the pinned files.
These build helpers produce unsigned development fixtures. The hosted release
workflow signs each MSI before this helper pins the chain, then signs the Burn
engine and outer Setup through `windows_signing.py`. Required final verification
and promotion bind the exact signed bytes and public certificate policy.

    py -3.12 apps/build_bundle.py --chain chain.json --bal-ext WixToolset.BootstrapperApplications.wixext.dll --out out

The bundle installs this package per-machine, with one administrator prompt,
like a redistributable, and the runtime serves every account (owner,
2026-10-06). Its core chain uses `ForcePerMachine` to pass `ALLUSERS=1` to the
dual-purpose MSI. The application MSIs stay per-user, and each
prefers the Panel a machine-wide installation records over a per-user one.
Run on its own, this package still defaults to Just me.

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

The model host and the Lemonade image provider make the engine folders they
install read-only for the account (inference CONTRACT.md INF-F3), and removal
leaves those folders as user data. Before either program goes, a removal of
its feature runs `modelhostd engine unlock` or `lemonaded engine unlock` as
the removing user, which gives that account's engine folders back so they can
be deleted. Other accounts' folders stay read-only; each account can run the
same command before the removal. A successor's upgrade runs neither, and a
failure never stops the removal. An elevated removal of a per-user install
skips both commands and leaves the engine folders locked; run
`modelhostd engine unlock` and `lemonaded engine unlock` unelevated before it.
A removal rolled back after the unlock leaves the engine folders writable, and
the provider's next launch refuses them with its reinstall message.

A machine removal runs `openabstractions host sandbox-roots revoke` before the
files go, which takes the two sandbox root entries back (a temporary
exception; see [Scope](#scope)). Run `icacls C:\` before and after to see it.

A sandboxed session takes its own grants back at exit. A session that crashed
and was never opened again leaves its manifest in the account's runtime state
(`apps\<app>\sandbox.json`). Before the program goes, a real removal runs
`openabstractions service remove-sandboxes` as the removing account. That
command removes each leftover sandbox using its manifest's recorded access
lists: the file grants, the attribute entries on the account's own folders
and the profile. A sandbox a session still runs in is left for that session
to remove. Other accounts' leftovers stay until each account runs the same
command. The command refuses an elevated token. A manifest is data in the
account's own folder, and a forged folder entry would make the revoke
re-propagate through a tree of the forger's choosing with administrator
rights. An elevated removal, a machine install's included, therefore leaves
the leftovers; run `openabstractions service remove-sandboxes` unelevated
before it.

## Upgrade

**Upgrades stop nothing.** Restart Manager stays on
(`MSIRESTARTMANAGERCONTROL=0`, `MSIRMSHUTDOWN=0`) and ends the running host at
`InstallValidate`, before any custom action. The early script, flushed by an
`InstallExecute` before any file is replaced, holds the upgrade exclusion
(`service begin-upgrade`), registers its release at commit (`service
end-upgrade`) and registers the rollback activation (`service start --related`
per-user, `service start --machine` for everyone). While the exclusion is held,
`start`, `serve supervisor` and SDK activation of the folders being replaced exit 3.
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

## Returning to 0.3.x

The 0.4.0 runtime writes its permissions to
`%LOCALAPPDATA%\openabstractions\runtime-v1\rights\decisions.json` as
`rights-decisions@7`, which holds the "Defaults for all apps" switches. A
0.3.x runtime reads only `rights-decisions@2`. It keeps running with that file
and answers every permission check `unavailable`: no app is allowed anything
and the Panel cannot change a rule. Removing 0.4.0 leaves the file in place,
and a 0.3.x installed afterwards meets it.

Installing 0.4.0 or later again restores every rule and answer the file holds.
To stay on 0.3.x, rename the `rights` folder beside the file, for example to
`rights-0.4`, while no runtime is installed: after removing 0.4.0 and before
installing 0.3.x, or after removing 0.3.x again. The next 0.3.x start writes
its installation rules into a new `rights` folder. The rules and answers
recorded under 0.4.0 stay in the renamed folder. Renaming it back while no
runtime is installed, then installing 0.4.0, returns them and discards what
was set under 0.3.x.

Credentials need the same step. A state first created by 0.4.0 keeps its
secrets in DPAPI-sealed files under `credentials\items`, bound by the file
`credentials-windows-backend` beside the `credentials` folder. A 0.3.x runtime
reads secrets only from Windows Credential Manager, so it would report every
credential registered under 0.4.0 as `lost`. Move the `credentials` folder and
the `credentials-windows-backend` file aside together with `rights`, for
example to `credentials-0.4` and `credentials-windows-backend-0.4`, at the
same time and with no runtime installed. Moving all three back before
installing 0.4.0 again returns the credentials.

Questions need it too. The 0.4.0 runtime keeps apps' questions and the record
of every answer in `asks\application.json` as `asks-application@9`; 0.3.x
reads only `asks-application@1`, and an earlier 0.4.0 build only up to
`@8`. Such a runtime refuses the whole file and starts without its question
service: no app can ask, no question is shown and none can be answered, while
everything else runs. Move the `asks` folder aside with the others, for
example to `asks-0.4`, with no runtime installed; the older runtime starts a
new one. Moving it back before installing this version again returns the
pending questions and the answer record.
