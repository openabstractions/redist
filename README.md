# redist

**The Open Abstractions redistributable: one installer per platform, built from
published tags.**

The package contains `jobd`, which supervises downloads; `dl`, which fetches
and verifies them; `jobctl`, which inspects and controls jobs; and
`openabstractions`, which exposes the individual capability services. Windows
also includes the Panel and the windowless supervisor image. Get them from [Releases](https://github.com/openabstractions/redist/releases).

**In development.** Check the selected release and its build evidence for
actual assets, signing and installation coverage; a draft is not a published
release.

## Installing

Download `abstraction-x64.msi` from the latest release, check it against
`SHA256SUMS`, and run it. It installs to
`%LOCALAPPDATA%\Programs\OpenAbstractions`, puts the `tools\` folder inside it
on your `PATH`, and needs no administrator rights.

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

Every program here is a published Go module, so the installer is a convenience
and never the only route. The `module` column of [`tools.tsv`](tools.tsv) is
the module path and version of each, and is what the release workflow builds
from:

    go install <module>

Use the module and package columns together: for a package other than `.`,
append its package path before the `@version`. The suite installer version is
separate from the versions of the modules it contains.

## What this repository is

One repository, not one per platform: a suite split across three would drift
into three versions with three release cadences. `tools.tsv` names each program
and the published module version it is built from; the platform-specific
packaging lives in a directory of its own — `windows/` holds the WiX sources.

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
- **A container.** `jobd` for a NAS is
  [docker-jobd](https://github.com/openabstractions/docker-jobd).
