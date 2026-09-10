# redist

**The Open Abstractions redistributable: one installer per platform, built from
published tags.**

Three command-line programs in one package — `jobd`, which keeps downloads
running when no application is open; `dl`, which fetches a URL resumably and
verifies its digest; and `jobctl`, which lists and controls what they are
doing. Get them from [Releases](https://github.com/openabstractions/redist/releases).

**In development. No published release yet.** Today the route is `go install`,
below.

## Installing

Download `abstraction-x64.msi` from the latest release, check it against
`SHA256SUMS`, and run it. It installs to
`%LOCALAPPDATA%\Programs\OpenAbstractions`, puts the `tools\` folder inside it
on your `PATH`, and needs no administrator rights.

    sha256sum -c SHA256SUMS

**The packages are not signed.** SmartScreen will warn, and the publisher will
show as unknown. Each release says so on its own page, with what follows from
it.

## Without an installer

Every program here is a published Go module, so the installer is a convenience
and never the only route. The `module` column of [`tools.tsv`](tools.tsv) is
the module path and version of each, and is what the release workflow builds
from:

    go install <module>

Nothing else in this repository types a version: two lists of the same three
versions are two lists that disagree.

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

The workflow drafts a release; it never publishes one. Publishing is a person's
decision.

## What is not here

- **No source for the programs.** They are built from the modules above.
- **macOS and Linux packages.** Neither is built yet; `go install` works on
  both.
- **A container.** `jobd` for a NAS is
  [docker-jobd](https://github.com/openabstractions/docker-jobd).
