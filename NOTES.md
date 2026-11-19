OpenAbstractions 0.8.0 includes the shared runtime, the Panel and tools built
from pinned module versions. Release assets and installation steps are listed below.

## Release 0.8.0

Changes since 0.4.0.

- **Add apps from the Panel.** On Windows, the Panel's Apps Catalog installs or
  repairs OpenCode and installs the OpenAbstractions integration for ComfyUI.
  ComfyUI itself comes from its official source.
- **Message between agents.** Claude and OpenCode chats can exchange messages and
  reconnect to their existing inboxes after OpenAbstractions restarts.
- **Let agents use applications.** Through application MCP, agents can discover
  which actions an app supports, see their inputs and open supported actions.
- **See what each model supports.** The model list shows model capabilities. Chat
  can request a reasoning level or budget and accept an image when the selected
  model supports it.
- **Work on a ComfyUI canvas with an agent.** Open a workflow through
  OpenAbstractions. When an agent asks to edit, choose **Allow once**, **Always
  allow** or **Not now**. A saved approval covers canvas edits by the enrolled
  agent in the approved ComfyUI app.
- **Manage storage.** The Panel's Device page shows storage by type, available
  free space, the largest reported items and verified duplicates, and lets you
  browse committed items. **Remove** offers removal for eligible items. In
  Activity, **Restore** retrieves eligible removed items from the download archive.
- **Upgrade in one pass.** During an interactive Windows upgrade, Setup's
  **Finish** step can update approved OpenCode and ComfyUI integrations when a
  verified newer package is available. If OpenCode is running, close it and choose
  **Retry**, or choose **Later** to finish from OpenAbstractions. Setup can complete
  an upgrade without restarting Windows when supported apps are using
  OpenAbstractions.

**Known limits.** Agent messaging took about 1-2 seconds under load in observed
runs. **Remove** cannot delete files that require Administrator access. An OpenCode
update took about 65 seconds in an observed run. On Windows, OpenAbstractions
starts when an app needs it; if it stops unexpectedly, it starts again on the next
request, and Windows does not restart it automatically. On Windows PCs where Smart
App Control is on, Windows can block the bundled llama.cpp engine, and local chat
through that engine does not start. Smart App Control can also block the official
OpenCode installer, and the Apps Catalog then cannot install OpenCode.

The redistributable carries native programs and the Windows app packages listed
below. Python wheels, Rust crates and npm packages have separate
source versions and publication status.

## Updating application code

Use named constants for closed options and an enum's `String()` method when a
Go wire word is needed. A Go `string(value)` conversion produces a Unicode
character from the numeric enum value. Existing JSON wire words stay
unchanged. Extensible catalogues retain unknown words. Inference guarantees
have named constants; unsupported guarantees receive a typed refusal before
provider work begins. Match client package versions to the release's module
pins.

## Candidate build targets

[`tools.tsv`](https://github.com/openabstractions/redist/blob/v0.8.0/tools.tsv) names the module versions and packages consumed by the
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
configuration.

## Installing

**Windows.** Compare `OpenAbstractions-Setup-0.8.0.exe` with `SHA256SUMS`, then
run it. Setup installs the runtime and the Panel. The Panel's Apps Catalog
installs OpenCode through its official installer and adds the OpenAbstractions
integration to an existing ComfyUI. Install ComfyUI from its official source
first. `opencode-0.8.0.msi` and `comfyui-0.8.0.msi` are the integration packages
the Catalog uses; they are also attached to the release.

OpenAbstractions downloads the `pytorch-*-inputs.zip` and `pytorch-*-source.zip`
files, their manifest and the `vc-runtime-*.zip` when needed. These support files
need no manual installation.

The direct core installers are `abstraction-0.8.0-x64.msi` and
`abstraction-0.8.0-arm64.msi`. For an MSI, the default *Just me* scope installs under
`%LOCALAPPDATA%\Programs\OpenAbstractions` without administrator rights.
*Everyone* installs under `%ProgramFiles%\OpenAbstractions` and requires
elevation. Programs live in `tools\`; runnable examples live in `examples\`.

**Add to PATH is optional.** Select it to use the commands from a new terminal;
leave it unchecked to invoke them by full path. A *Just me* install starts the
runtime immediately. Subsequent Windows sign-in registration follows confirmed
Applications and their conditional login policy. The runtime host restarts a
runtime that fails, and the next
`openabstractions start` or application that needs it starts a host that exited.
An elevated install registers a Windows per-user service. In 0.8.0, ordinary
user requests start the runtime host detached; Windows does not restart that
host automatically after a crash. The next request starts it again. Uninstall through
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

    sha256sum -c --ignore-missing SHA256SUMS

In PowerShell, a single-file comparison can use:

    (Get-FileHash OpenAbstractions-Setup-0.8.0.exe -Algorithm SHA256).Hash.ToLower()
    Select-String OpenAbstractions-Setup-0.8.0.exe SHA256SUMS

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
