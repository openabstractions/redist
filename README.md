# redist

The Open Abstractions redistributable packages programs built from published
module versions: the `openabstractions` service host and command.
Windows also includes `openabstractionsw`, the windowless runtime host, and
Abstraction Panel.

See [Releases](https://github.com/openabstractions/redist/releases) for available
downloads and their release-specific verification. Draft builds are not releases.
Each release lists its included capabilities, platform verification and signing state.

## For people installing

### Available now: 0.2.0

The charter README carries the current pitch and platform coverage for
0.2.0. [Download 0.2.0](https://github.com/openabstractions/redist/releases/tag/v0.2.0)
directly, or read
[the charter's "Available now" section](https://github.com/openabstractions/abstractions#available-now-020)
for what it includes and its verification state.

### Planned 0.3.0 downloads (unpublished)

The prepared 0.3.0 source passed its recorded Windows, Linux and macOS
qualification stage. Installed-package acceptance and artifact promotion are
in progress; no 0.3.0 downloads are available yet. The release adds provider
admission and credential protections, clearer resource and rights contracts,
expanded inference APIs, `inventoryd`, `modelhostd`, an optional MCP gateway,
and the Windows Panel. Windows and Linux packages are unsigned; ARM64 packages
are cross-built. The macOS universal package is conditional on its signing and
notarization gates. See [candidate notes](NOTES.md) for package contents and
verification scope.

### Installing

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

## For developers using `go install`

### Without an installer

[`tools.tsv`](tools.tsv) names each published module version and package.
Build the package at that version with `go install <package>@<version>`.
The windowless Windows executables additionally need the build flags specified by
the release workflow; plain `go install` does not reproduce their subsystem.

### What this repository is

One packaging repository for Windows, Linux and macOS. `tools.tsv` is the
version list consumed by the workflow; `windows/` and `posix/` hold packaging.
Programs' source stays in their own public modules. The candidate workflow
resolves pinned modules and retains verified packages. A separate promotion
workflow creates the release draft from those packages.

`tools.tsv` may name only versions that are tags on their repositories, so a
module we broke stops the release by name instead of shipping; the workflow
checks that with `git ls-remote --tags` rather than `proxy.golang.org`, which
can still serve a version whose tag was later deleted.

### Platform evidence and language packages

Each release reports which platform checks ran and which assets ship.
For NAS delivery, see [docker-jobd](https://github.com/openabstractions/docker-jobd).

The candidate also retains Python wheels and JavaScript package archives as
separate artifacts. `pypi.tsv` pins the source of the native `abstraction-ipc`
wheels, and `npm.tsv` pins JavaScript package sources. Installer promotion
consumes the `verified-release-N` artifact. Package-index publication needs its
own configured publisher and authorization; running a candidate does not upload
packages to PyPI or npm.

### Publishing the qualified Python wheels

The `publish.yml` workflow is a manual PyPI trusted publisher for the native
`abstraction-ipc` wheels. Dispatch the reviewed publisher workflow with the
candidate's `vMAJOR.MINOR.PATCH` version, run ID, exact redist source SHA and
current run attempt. The run must have succeeded without preview. The verifier checks the
candidate's source, version and attempt metadata in `verified-release-N`, then
selects the latest successful Python matrix job for each of Windows x64, Linux
x64, macOS arm64 and macOS x64. A retry may retain a successful wheel from an
earlier attempt of the same run. Each selected artifact must match its job's
attempt and the candidate source. The verifier checks GitHub artifact digests,
per-wheel SHA256SUMS, the exact wheel filenames and native wheel contents before
staging four wheels. It builds nothing.

Current candidates give each Python matrix job a stable `python (<platform-id>)`
name. For an older candidate, the verifier accepts a matching default
`python (<platform-id>, ...)` name when GitHub's run-jobs response proves it;
unrecognized names or absent attempt numbers refuse. A failed upload can be
retried without rerunning verification: the upload job downloads the exact
artifact ID emitted by the successful verification job.

The publisher workflow can be introduced after a candidate completed. Its
dispatch ref may therefore be a later reviewed redist commit; the explicit
candidate source input is checked against the candidate run and its artifacts.

The upload job waits at the `pypi` environment gate and uses GitHub OIDC through
PyPI Trusted Publishing. Before dispatch, the owner must verify that the
`abstraction-ipc` PyPI publisher is configured for the `openabstractions/redist`
repository, `.github/workflows/publish.yml` and `pypi` environment, including
any required environment approval. The repository cannot verify those account
settings offline. PyPI publication is permanent; inspect the candidate and
the four wheels before approving that job. The old layer Python publisher has
different source and artifact assumptions and remains separate.

## For maintainers cutting a release

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
