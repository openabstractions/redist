# redist

The Open Abstractions redistributable packages programs built from published
module versions: the `openabstractions` service host and command.
Windows also includes `openabstractionsw`, the windowless runtime host, and
Abstraction Panel.

See [Releases](https://github.com/openabstractions/redist/releases) for available
downloads and their release-specific verification. Draft builds are not releases.
Each release lists its included capabilities, platform verification and signing state.

## Available now: 0.2.0

[Download 0.2.0](https://github.com/openabstractions/redist/releases/tag/v0.2.0) for Windows, Linux and macOS.
Use one runtime to keep accepted work running, call AI providers with named
credentials, manage application permissions, and find or activate registered
applications. Windows includes the Panel for inspecting and managing the runtime.
The SDK sources cover Go, C++17, Python, Rust and JavaScript; package versions
and registry availability are documented separately by each capability.

Windows x64 installation, upgrades, rollback and crash recovery passed.
Linux amd64 installation and runtime-backed downloading passed. The macOS
package is signed and notarised; protected service calls retain the documented
caller-identity limitation. Windows and Linux packages are unsigned.
[Release verification and limits](https://github.com/openabstractions/abstractions/blob/main/docs/results/release-0.2.0.md).

## Installing

The Windows MSI defaults to *Just me*, under
`%LOCALAPPDATA%\Programs\OpenAbstractions`. *Everyone* installs under
`%ProgramFiles%\OpenAbstractions` and requires elevation. **Add to PATH** is
optional; programs remain available by full path when it is unchecked.

Linux tarballs install for the current user through `install.sh`. The macOS
universal `.pkg`, when attached, also installs for the current user.
[Release notes](NOTES.md) explain the contents and installation choices.
Each release's appended notes name its actual assets and signing state;
consult that release's build for platform verification. Availability, signatures
and installation results are not promises made by this general README.

Compare downloads against the release's `SHA256SUMS`:

    sha256sum -c SHA256SUMS

**Check the release-specific signing notes.** Windows MSI and Linux tarball
assets are unsigned in the current workflow; macOS assets are attached only
after its signing and notarization gates. A checksum is not a signature.

The 0.2.0 CLI provides:

    openabstractions status --json
    openabstractions probe --json
    openabstractions applications list

`status` reports service readiness. `probe` performs bounded reads and prints
typed outcomes. `applications list` shows the caller's permission-filtered local
application directory. The 0.2.0 installers register the shared runtime,
which supervises configured capabilities.
Windows per-user installation starts it immediately and registers a windowless
Startup launcher. Check `openabstractions status --json` for readiness. Consult
the selected release notes for the behavior qualified in that release.

Developers can also run individual hosts in the foreground with
`openabstractions serve logging`, `serve config` and `serve router-v1`. These
commands do not install or register a service.

## Without an installer

[`tools.tsv`](tools.tsv) names each published module version and package.
Build the package at that version with `go install <package>@<version>`.
The windowless Windows executables additionally need the build flags specified by
the release workflow; plain `go install` does not reproduce their subsystem.

## What this repository is

One packaging repository for Windows, Linux and macOS. `tools.tsv` is the
version list consumed by the workflow; `windows/` and `posix/` hold packaging.
Programs' source stays in their own public modules. The workflow resolves the
pinned modules and drafts a release; publishing remains a separate decision.
Go's proxy may retain a version after its repository tag is deleted, so fetching
an artifact alone does not prove that the tag still exists.

`tools.tsv` may name only versions that are tags on their repositories. The
release workflow resolves every one before it builds anything, so a module we
broke stops the release by name instead of shipping. That is the point of the
repository: the package consumes our published artifacts exactly as a stranger
does.

It resolves them through `proxy.golang.org`, and the proxy serves a version it
has cached for good — including one whose tag was deleted. So that check cannot
see a deleted tag; `git ls-remote --tags` on the repository is what does.

## Preparing a release

Run `candidate.yml` from the reviewed `release/X.Y.Z` branch with
`version=vX.Y.Z`. It builds from the published versions in `tools.tsv`, records
the selected module graph and tag commits, and runs packaging, installer,
reproducibility and signing checks. Its `verified-release-N` artifact contains
the checked packages, checksums, release notes and exact source/run metadata.
Artifacts are retained for 30 days. No release tag is created at this stage.

Inspect the failed step if a job fails. Retry failed jobs on that run;
successful build artifacts remain available. A source change requires a new
candidate. Preserve the run URL when handing work to another maintainer.

After the candidate passes, fast-forward `main` to its exact commit through
the publication tool. Run `release.yml` from that same release branch with the
same `version` and its `candidate_run` ID. Promotion verifies the run, artifact
digest and every package checksum, then creates the version tag and a draft
release from those bytes. It invokes no builds or installation tests.
Review the draft and publish it as a separate action.

An explicit candidate `preview=true` records the existing machine-scope
evidence exception. Compilation and installer checks remain required.
If promotion stops after creating the tag or draft, inspect that run and use
`resume=true` with the same candidate. Recovery accepts only the exact tag,
notes and asset bytes already verified. Existing assets are never replaced.

## What is not here

- **No source for the programs.** They are built from the modules above.
- **Uniform platform evidence.** The workflow builds Linux tarballs and macOS
  packages, but each release reports which checks ran and which assets ship.
For NAS delivery, see [docker-jobd](https://github.com/openabstractions/docker-jobd).
