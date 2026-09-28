Open Abstractions 0.3.0 packages the shared runtime and tools built from
published module versions. The appended build record lists the attached assets,
signing state, package verification and tested architectures.

## Release 0.3.0

- **Provider admission is tied to declared identity.** The facade registry now
  records declaration roles and service contract identities. Admission rules
  and credential policy are reconciled before provider work; credential
  redirects are refused rather than forwarding stored secrets to another host.
- **Resource access and rights carry clearer scope.** The release adds the
  versioned resource table and lease contracts, physical-path subjects, and
  expiry/provenance for rights rules. Resource-consuming child processes keep
  the owning identity and rights boundary.
- **Inference requests expose more precise guarantees.** The inference API adds
  provider admission, named refusal words and native embeddings. Realtime
  upgrades check rights before changing transport. Unsupported guarantees are
  refused before provider work begins.
- **Routing exposes more model and context information.** Model identity has a
  dedicated module. Router families describe their components, source and
  context length, and accepted-work records expose the resource they hold.
- **Local model integrations are available as optional build targets.**
  `inventoryd` reports local model stores; `modelhostd` serves a model file
  already on the machine. Storage owns the lending schema used by model
  providers. `openabstractions-mcp` is also an optional stdio gateway.
- **The Panel has a macOS application build.** It presents runtime-owned status
  and service controls. Candidate build targets include the Windows executable
  and macOS `Abstraction Panel.app`; Linux has no graphical Panel package.

The hosted build workflow pins Go 1.26.8 with `GOTOOLCHAIN=local` and records
`go version` for each platform job. The final package record will identify the
toolchain actually used for attached binaries.

The focused source-level macOS XPC proof passed resolver, configuration and
Rights calls. It is source evidence, not installed-package or signing evidence.
The Linux source-stage WSL environment lacked a matching audit-session ID, so
application announcement and activation correctly refused there.

The redistributable packages native programs only. Python wheels, Rust crates
and npm packages have separate source versions and publication status.

## Updating application code

Use named constants for closed options and an enum's `String()` method when a
Go wire word is needed. A Go `string(value)` conversion produces a Unicode
character from the numeric enum value. Existing JSON wire words stay
unchanged. Extensible catalogues retain unknown words. Inference guarantees
have named constants; unsupported guarantees receive a typed refusal before
provider work begins. Match client package versions to the release's module
pins.

## Candidate build targets

[`tools.tsv`](tools.tsv) names the module versions and packages consumed by the
build workflow. These are workflow build targets, not a promise that every optional
program appears in a final asset; installer feature selection can omit optional
components.

| Program | Role | Build targets |
|---|---|---|
| `openabstractions` | Runtime host and CLI | Windows, Linux, macOS |
| `openabstractionsw` | Windowless Windows runtime host | Windows |
| `Abstraction Panel` | Runtime status and control UI | Windows, macOS |
| `inventoryd` | Local model-store inventory provider | Windows, Linux, macOS |
| `modelhostd` | Local model-file provider | Windows, Linux, macOS |
| `openabstractions-mcp` | stdio MCP gateway | Windows, Linux, macOS |

The POSIX installer includes local-store inventory by default. Model host and
MCP gateway are optional selections. Windows selections follow MSI feature
configuration. The appended release record names the exact packages and
features delivered in each asset.

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
