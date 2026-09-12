The Open Abstractions redistributable packages programs built from published
module versions. The build appends this release's asset and signing state at
the end of these notes; those facts apply to this release only.

## What is in it

| program | what it does | platforms |
|---|---|---|
| `jobd` | supervises downloads after the requesting application closes | Windows, Linux, macOS |
| `jobdw` | the same supervisor built without a console window | Windows |
| `dl` | fetches URLs resumably and verifies a supplied digest | Windows, Linux, macOS |
| `jobctl` | operates directly on the job store for scripts and debugging | Windows, Linux, macOS |
| `Abstraction Panel` | graphical view of local activity | Windows |
| `openabstractions` | hosts capability services through its `serve` command | Windows, Linux, macOS |

There are six Windows executables and four Linux/macOS programs. `jobd` and `jobdw`
are two builds of the same source. [`tools.tsv`](tools.tsv) at this release's
commit names the exact module versions and packages the workflow builds.
Resolving a module through the Go proxy proves it is fetchable; the proxy may
retain versions after a tag is deleted.

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
leave it unchecked to invoke them by full path. The per-user supervisor starts
through a Startup shortcut and is not automatically replaced after a crash.
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

## Limitations

- `JOB_STORE` can point `jobctl` at a different store, as described above.
- Cross-tool compatibility checks cover particular scenarios, not every operation.
- A partly fetched download does not resume across a reinstall.
- CI runner checks do not establish behavior on every user's machine.

## Source

Programs are built from public modules; packaging does not build them from a
private source tree.

- [service-jobd](https://github.com/openabstractions/service-jobd)
- [abstraction-download](https://github.com/openabstractions/abstraction-download)
- [abstraction-job](https://github.com/openabstractions/abstraction-job)
- [abstractions: service host and panel](https://github.com/openabstractions/abstractions)
