The Open Abstractions redistributable: three command-line programs in one
package per platform, built from our own published module versions rather than
from a source tree.

Which packages this release carries, and which of them is signed, are stated at
the end of this page by the run that built it. Nothing above that point is a
claim about this particular run.

## What is in it

| program | what it does |
|---|---|
| `jobd` | keeps downloads running when no application is open |
| `dl` | fetches a URL, resumably, verifying a digest if you give one |
| `jobctl` | drives the job store directly, for scripts and debugging |

Each is built from a published module version, and `tools.tsv` in this
repository at this tag is the list of them. It is the file the release workflow
reads, so it is the only place those versions are written down.

The workflow refuses to build if one of them does not resolve, so this package
is made of the same artifacts a stranger gets from `go install` and cannot
quietly drift into being built from something else. It resolves them through
`proxy.golang.org`, which goes on serving a version whose tag was later
deleted — so that check proves the artifact is fetchable, not that the tag is
still there.

**`jobctl` is not the friendly one.** All three find the store from
`ABSTRACTION_STORE`. `jobctl` also accepts `JOB_STORE`, which wins where it is
set, so one shell can point it at a store the other two are not using. Its verbs are
`submit`, `claim`, `progress`, `finish`, `show`, `cancel`, `intent`, `recall`
and `orphans` — there is no `jobctl list`. It is the low-level tool for the job
store, and it is in this package because it is what is published, not because
it is the command-line experience we want. `dl list` is the friendly view of
your own downloads.

The three programs do agree about the **store format**, which is the thing that
matters: the release workflow has `dl` fetch a file, then requires `jobd` to
see that download and `jobctl show` to return the record `dl` wrote. It fails
if any of them disagrees.

## Installing

**Windows.** Download `abstraction-x64.msi` — or `abstraction-arm64.msi` on
Windows on ARM — check it against `SHA256SUMS`, then run it. It installs to
`%LOCALAPPDATA%\Programs\OpenAbstractions` — the programs in `tools\`, runnable
examples in `examples\` — adds `tools\` to your `PATH`, and asks for no
administrator rights. Open a new terminal afterwards, or `PATH` will still be
the old one.

    dl https://example.com/some/file.bin -o D:\downloads

Uninstall from Apps & features, or `msiexec /x abstraction-x64.msi`. The
release workflow installs and uninstalls the x64 package on a clean machine on
every run and fails if anything is left behind.

**Linux.** Unpack the tarball for your architecture and run the `install.sh`
inside it. It puts the three programs in `~/.local/bin`, and an `uninstall.sh`
with the `MANIFEST` it removes in `~/.local/share/abstraction`. The release
workflow unpacks, installs and uninstalls the amd64 tarball on every run.

## Checking what you downloaded

`SHA256SUMS` is `sha256sum` output — one line per file, the hash, two spaces,
the filename. With `sha256sum` available (Git for Windows, WSL, macOS, Linux),
in the folder holding the downloads:

    sha256sum -c SHA256SUMS

It prints `abstraction-x64.msi: OK`. In PowerShell, with nothing installed:

    (Get-FileHash abstraction-x64.msi -Algorithm SHA256).Hash.ToLower()
    Select-String abstraction-x64.msi SHA256SUMS

The two strings match, or you did not get the file we built.

**What this does and does not prove.** It proves the bytes did not change
between this page and your disk. It does not prove they came from us: the
checksum file sits on the same page as the downloads, so anyone who could
replace one could replace the other. A signature is what proves origin, and
**Signatures** below says which of these files carries one. Both MSIs are built
twice in one job and compared byte for byte, and so are the Go binaries that go
into every package: a difference in the binaries fails the release, a
difference in an MSI is reported and does not, and the inputs are identical
either way.

## What may break

- The three programs come from three separately tagged modules, so they are
  three builds of one store format in a single package. The release workflow
  writes a job with `dl`, requires `jobd` to see it and `jobctl show` to return
  it, and fails if they disagree. That is one scenario, not a compatibility
  proof.
- **`JOB_STORE` overrides `ABSTRACTION_STORE` for `jobctl` alone**, as above.
  Set it and `jobctl` will be looking at a store `jobd` and `dl` are not.
- **The arm64 packages are unrun**: built on every release, installed by no
  arm64 machine, on either Windows or Linux.
- A partly fetched download does not resume across a reinstall.
- Nothing here has been measured on a machine that is not a CI runner.

## Source

Every program in this package is built from a public module. Nothing in the
package is built from a private tree.

- [service-jobd](https://github.com/openabstractions/service-jobd)
- [abstraction-download](https://github.com/openabstractions/abstraction-download)
- [abstraction-job](https://github.com/openabstractions/abstraction-job)
