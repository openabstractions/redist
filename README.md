# redist

The Open Abstractions redistributable packages programs built from published
module versions: `jobd`, `dl`, `jobctl` and the `openabstractions` service host.
Windows also includes the windowless `jobdw` supervisor and Abstraction Panel.

See [Releases](https://github.com/openabstractions/redist/releases) for available
downloads and their release-specific verification. Draft builds are not releases.

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

The central CLI is available on PATH, for example:

    openabstractions serve logging
    openabstractions serve config
    openabstractions serve router-v1

Run one selected command in the foreground. Installing the binary does not
register these capability processes to start automatically. The existing
background registration belongs to the download supervisor.

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

Start the release workflow manually from the reviewed branch commit with a new
`version` such as `v0.1.5`. It pins that commit, builds the published modules and
packages, and runs the existing installer and signing gates before creating any
version tag. A build failure leaves the proposed tag absent. Existing tags are
refused and never moved, including tags left by older failed release workflows.

After verification, it creates the tag at the exact tested commit and drafts a
release using that run's already checked artifacts, without rebuilding. An
explicit `preview` retains the existing machine-scope evidence exception; it
does not bypass compilation, packaging or installer checks. The workflow never
publishes the draft. Publishing is a person's decision. If drafting fails after
tag creation, inspect that run's artifacts and recover explicitly; rerunning
with the existing version will refuse it rather than replace it.

## What is not here

- **No source for the programs.** They are built from the modules above.
- **Automatic startup of the central capability services.** The CLI is
  installed; capability registration is not added by this package.
- **Uniform platform evidence.** The workflow builds Linux tarballs and macOS
  packages, but each release reports which checks ran and which assets ship.
For NAS delivery, see [docker-jobd](https://github.com/openabstractions/docker-jobd).
