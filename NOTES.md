The Open Abstractions redistributable packages programs built from published
module versions. The build appends this release's asset and signing state at
the end of these notes; those facts apply to this release only.

## Changes in this release

- **Inference covers chat, embeddings, transcription, speech, image generation
  and live voice.** The runtime selects an eligible configured host, applies
  rights and named credentials, and records attributed outcomes. Durable video
  generation and image batches use the job service for observation,
  reconciliation, cancellation and retained results.
- **Named credentials stay with the runtime service.** Operators can add,
  inspect, rotate and revoke credentials through the command line or Panel.
  The service applies an authorized credential inside the consuming service
  without returning its stored bytes to the application.
- **Applications can publish their presence and supported interfaces.** The
  permission-filtered directory lists registered applications and live
  instances. A separately authorized activation request can start a registered
  application and wait for its fresh announcement.
  On Linux, announcement and activation require a usable kernel audit-session
  ID matching the runtime. Our WSL test environment had an unset session ID
  and correctly refused these protected calls.
- **Typed client source surfaces cover Go, C++17, Python, Rust and JavaScript.**
  Go, C++ and Python facade clients use their default native IPC paths. Rust
  and JavaScript use their separate native connector packages. Each source SDK
  is available at the corresponding repository revision used for this release;
  its package version, registry availability and release status remain
  independent of the redistributable.
- **`jobd`, `dl` and `jobctl` are removed, with the job-store provider inside
  `jobd` and its `supervisor.json` heartbeat.** `openabstractions download`
  submits a download to the installed runtime and copies the result out;
  `openabstractions jobs list|show|wait|cancel|result` observes and controls
  the work `openabstractions` submitted. Downloads still in flight through the
  old job store at upgrade are abandoned: their records and partial files stay
  where they are, and nothing finishes them. The Linux `abstraction-jobd`
  sweep timer is stopped and disabled by the upgrade. On macOS the LaunchAgent
  label is now `com.openabstractions.runtime`; the upgrade boots out
  `com.openabstractions.jobd` and removes its plist. The Python file-store
  packages are no longer carried in the developer files. What existed is
  recorded in the project's `docs/REMOVED.md`.
- **`openabstractions` runs the Windows runtime.** `openabstractions serve host`
  starts the runtime, restarts it after a failure, and is started at sign-in by
  the Startup shortcut (*Just me*) or the per-user service (*Everyone*).
  `openabstractionsw` is the same program without a console window and replaces
  `jobdw`. The installer stops no process itself: Windows ends the running host
  before replacing files, and the host registers to be started again.
- **A failed Windows upgrade leaves the previous version running.** Rolling back
  starts the previous version's runtime again from its own folder, so it no
  longer waits for the next sign-in.
- **Windows upgrades keep one owner.** While an upgrade replaces an
  installation, its runtime cannot start again from the Startup shortcut, the
  service manager, `openabstractions start` or an application. The
  installation activates normally once the upgrade finishes.
- **A failed Windows upgrade leaves the previous version installed.** The
  previous version is removed only after the new one is fully installed, so an
  upgrade that fails keeps the earlier installation registered in Apps and
  features with its programs and your data.
- **Per-user upgrades find an installation in another folder.** An upgrade
  covers the previous version where it was installed, including a folder chosen
  at install time.
- **An elevated per-user install is refused before anything is copied.** See
  [Installing from an elevated session](#installing-from-an-elevated-session).
- **The panel shows what the installed runtime owns.** `Abstraction Panel`
  reads runtime readiness, accepted work, questions, rights and user
  configuration through the runtime's services. Its `--legacy-local` mode and
  the delegation, downloads and may-reach screens that read the job store
  directly are removed. With no runtime it reports the absence.
- **Rights rules can expire and record their origin.** The runtime's rights
  service accepts registered action names, rule expiry and rule provenance.
- **`services.json` is no longer read or reserved.** A store written by an
  earlier release may still hold one; a download may now use that name.
- **Every program is built with Go 1.26.8.**
- **Downgrading after a retry or lost result is refused.** See
  [Downgrading to an earlier release](#downgrading-to-an-earlier-release).

This release packages the runtime and tools. It bundles no Python wheels, Rust
crates or npm packages, and does not promise that those packages are published
to a registry. Language SDK source is available from the corresponding
repository revisions and keeps its own package versions and release status. The
architecture roadmap continues beyond this release. The known macOS
caller-identity limitation still applies to verified service readiness.

## Updating application code

The regenerated SDK source introduces named choices for closed options. In Go, use
constants such as `facade.ScopeLocal`; use an enum's `String()` method when a
wire word is needed. A Go `string(value)` conversion produces a Unicode character from a numeric
enum value. Existing JSON wire words stay unchanged.

Extensible catalogues retain unknown words. Inference request guarantees have
named constants and a dedicated type; an unsupported guarantee receives the
service's typed refusal before provider work begins. Match the client package
versions to the release's published module pins.

## What is in it

| program | what it does | platforms |
|---|---|---|
| `Abstraction Panel` | runtime readiness, accepted work, questions, rights and user configuration | Windows |
| `openabstractions` | hosts the installed runtime, submits and observes downloads through it (`download`, `jobs`), and reports readiness (`status`) | Windows, Linux, macOS |
| `openabstractionsw` | the same program built without a console window, which Windows starts at sign-in | Windows |

There are three Windows executables and one Linux/macOS program. `openabstractions`
and `openabstractionsw` are two builds of the same source. [`tools.tsv`](tools.tsv) at this release's
commit names the exact module versions and packages the workflow builds.
Resolving a module through the Go proxy proves it is fetchable; the proxy may
retain versions after a tag is deleted.

Every program on every platform is built with Go 1.26.8, with
`GOTOOLCHAIN=local` so no other toolchain is fetched. Each build job keeps
its `go version` output as a `go-version-<platform>` workflow artifact.

`openabstractions jobs list` shows the work `openabstractions` submitted in
your account. Work an application submitted through its own connection belongs
to that application and is observed there.

## Installing

**Windows.** Choose the x64 or arm64 MSI for your machine and compare it with
`SHA256SUMS`. The default *Just me* scope installs under
`%LOCALAPPDATA%\Programs\OpenAbstractions` without administrator rights.
*Everyone* installs under `%ProgramFiles%\OpenAbstractions` and requires
elevation. Programs live in `tools\`; runnable examples live in `examples\`.

**Add to PATH is optional.** Select it to use the commands from a new terminal;
leave it unchecked to invoke them by full path. A *Just me* install starts the
runtime immediately and registers a windowless Startup shortcut for subsequent
sign-ins; the runtime host restarts a runtime that fails, and the next
`openabstractions start` or application that needs it starts a host that exited.
The elevated scope registers the Windows per-user service, which starts the
user's runtime host at sign-in and restarts it after a crash. Uninstall through
Windows' installed-apps settings or `msiexec /x <package.msi>`.

**Linux.** Unpack the tarball for your architecture and run its `install.sh`.
It installs `openabstractions` under `~/.local/bin` and the uninstaller and manifest
under `~/.local/share/abstraction`. It does not edit shell profiles; follow its
PATH guidance if needed. The background runtime needs a systemd user manager;
the installer reports when it is unavailable.

**macOS.** When attached to the release, the universal `.pkg` carries both
x86_64 and arm64 programs and installs for the current user. Consult the
appended asset/signing state before downloading: a successful build alone does
not mean a package was signed, notarised or attached.

## Checking what you downloaded

In the folder containing the assets and checksum file:

    sha256sum -c SHA256SUMS

In PowerShell, a single-file comparison can use:

    (Get-FileHash abstraction-x64.msi -Algorithm SHA256).Hash.ToLower()
    Select-String abstraction-x64.msi SHA256SUMS

Checksums establish agreement with the published checksum file, not independent
proof of origin. Signing, notarisation, attached assets and platform verification
must be read as per-release facts. The **Signatures** section appended below
states the signing outcome; consult the linked release build for its install
and uninstall checks. Building an architecture does not prove installation on
that architecture. Do not infer a Windows install result from Linux verification,
or an installed macOS service from a signed package.

## Installing from an elevated session

A Windows install for your account (*Just me*) started from an elevated
administrator prompt, or from a deployment tool running elevated, stops before
any file is copied. Running the MSI with no install scope selects *Just me*, so
it is refused the same way. The runtime does not start with administrator
rights, and the message names both remedies: run the installer without
administrator rights to install for your account, or pass `ALLUSERS=1` to
install for everyone. Release 0.1.6 copied the files first and then failed
with Error 1722 / 1603.

## Downgrading to an earlier release

Job providers from release 0.1.6 and earlier cannot open a job store after
this release has retried a job attempt or recorded a lost result in it.
Downgrading to such a release then fails the storage preflight with
`unsupported owner field "Features"`. A store that never retried an attempt or
lost a result stays compatible with the earlier release.

Once this release has run, release 0.1.7 cannot open the job store: its
preflight refuses it with `unsupported storage feature journal-labels@1`,
because this release records job labels. A failed upgrade is unaffected,
because the new runtime never runs and 0.1.7 keeps working. Reinstalling 0.1.7
after this release has run leaves accepted work unavailable until this release
is installed again.

## Limitations

- `openabstractions download` and `jobs result` move a result through the
  runtime in 64 KiB exchanges; a large model takes many exchanges.
- Removal preserves user data. Resume across upgrades depends on the job and provider;
  retained-data checks alone do not establish transfer recovery.
- CI runner checks do not establish behavior on every user's machine.

## Source

Programs are built from public modules; packaging does not build them from a
private source tree.

- [abstraction-download](https://github.com/openabstractions/abstraction-download)
- [abstraction-job](https://github.com/openabstractions/abstraction-job)
- [abstractions: service host and panel](https://github.com/openabstractions/abstractions)
