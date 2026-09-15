The Open Abstractions redistributable packages programs built from published
module versions. The build appends this release's asset and signing state at
the end of these notes; those facts apply to this release only.

## Changes in this release

- **Windows upgrades keep one owner.** While an upgrade replaces an
  installation, its supervisor and runtime cannot start again from the Startup
  shortcut, the service manager, `jobd start` or `openabstractions start`. The
  installation activates normally once the upgrade finishes.
- **A failed Windows upgrade restores what it stopped.** Rollback restarts the
  supervisors the upgrade stopped, for your account or for everyone, and nothing
  it did not stop.
- **Per-user upgrades find an installation in another folder.** An upgrade stops
  the previous version where it was installed, including a folder chosen at
  install time.
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

`dl`, `jobctl`, the job-store provider inside `jobd` and its `supervisor.json`
heartbeat still ship in this release. They are planned for removal in 0.1.8,
when service-based download and job commands replace them.

This release packages the runtime and tools. Language SDKs keep their own release
versions. The architecture roadmap continues beyond this release. The known
macOS caller-identity limitation still applies to verified service readiness.

## What is in it

| program | what it does | platforms |
|---|---|---|
| `jobd` | supervises downloads and the installed capability runtime | Windows, Linux, macOS |
| `jobdw` | the same supervisor built without a console window | Windows |
| `dl` | fetches URLs resumably and verifies a supplied digest | Windows, Linux, macOS |
| `jobctl` | operates directly on the job store for scripts and debugging | Windows, Linux, macOS |
| `Abstraction Panel` | runtime readiness, accepted work, questions, rights and user configuration | Windows |
| `openabstractions` | hosts capability services through its `serve` command | Windows, Linux, macOS |

There are six Windows executables and four Linux/macOS programs. `jobd` and `jobdw`
are two builds of the same source. [`tools.tsv`](tools.tsv) at this release's
commit names the exact module versions and packages the workflow builds.
`jobd` and `jobdw` in this release are built from service-jobd v0.3.6.
Resolving a module through the Go proxy proves it is fetchable; the proxy may
retain versions after a tag is deleted.

Every program on every platform is built with Go 1.26.8, with
`GOTOOLCHAIN=local` so no other toolchain is fetched. Each build job keeps
its `go version` output as a `go-version-<platform>` workflow artifact.

`jobctl` is a low-level tool, not the download browser: use `dl list` for your
own downloads. Its store override `JOB_STORE` takes precedence over
`ABSTRACTION_STORE`, so it can address a different store from `dl` and `jobd`.
The workflow's cross-tool check writes a download with `dl` and reads it with
`jobd` and `jobctl`; that scenario is not a complete compatibility proof.

## Installing

**Windows.** Choose the x64 or arm64 MSI for your machine and compare it with
`SHA256SUMS`. The default *Just me* scope installs under
`%LOCALAPPDATA%\Programs\OpenAbstractions` without administrator rights.
*Everyone* installs under `%ProgramFiles%\OpenAbstractions` and requires
elevation. Programs live in `tools\`; runnable examples live in `examples\`.

**Add to PATH is optional.** Select it to use the commands from a new terminal;
leave it unchecked to invoke them by full path. Current source installers start
the per-user runtime immediately and register a windowless Startup shortcut for
subsequent sign-ins. Startup registration alone cannot replace a crashed supervisor.
The elevated scope registers the Windows service arrangement, which starts the
user's supervisor at sign-in and restarts it after a crash. Uninstall through
Windows' installed-apps settings or `msiexec /x <package.msi>`.

**Linux.** Unpack the tarball for your architecture and run its `install.sh`.
It installs four programs under `~/.local/bin` and the uninstaller and manifest
under `~/.local/share/abstraction`. It does not edit shell profiles; follow its
PATH guidance if needed. Background scheduling needs a systemd user manager;
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

## Limitations

- `JOB_STORE` can point `jobctl` at a different store, as described above.
- Cross-tool compatibility checks cover particular scenarios, not every operation.
- Removal preserves user data. Resume across upgrades depends on the job and provider;
  retained-data checks alone do not establish transfer recovery.
- CI runner checks do not establish behavior on every user's machine.

## Source

Programs are built from public modules; packaging does not build them from a
private source tree.

- [service-jobd](https://github.com/openabstractions/service-jobd)
- [abstraction-download](https://github.com/openabstractions/abstraction-download)
- [abstraction-job](https://github.com/openabstractions/abstraction-job)
- [abstractions: service host and panel](https://github.com/openabstractions/abstractions)
