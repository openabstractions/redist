The first release of the Open Abstractions redistributable: three command-line
programs in one Windows installer, built from our own published module versions
rather than from a source tree.

This is release one. It ships Windows and nothing else, the packages are **not
signed**, and the list of what is missing is longer than the list of what is
here. All three are stated below rather than left to be discovered.

## What is in it

| program | what it does | built from |
|---|---|---|
| `jobd.exe` | keeps downloads running when no application is open | `service-jobd@v0.2.0` |
| `dl.exe` | fetches a URL, resumably, verifying a digest if you give one | `abstraction-download/go@v0.3.0` |
| `jobctl.exe` | drives the job store directly, for scripts and debugging | `abstraction-job/go@v0.3.0` |

Every version in that last column exists on `proxy.golang.org`. The release
workflow refuses to build if one of them does not, so this package is made of
the same artifacts a stranger gets from `go install` and cannot quietly drift
into being built from something else.

**`jobctl` is not the friendly one.** `jobd` and `dl` find the store from
`ABSTRACTION_STORE`; `jobctl` reads **`JOB_STORE`** and nothing else, and will
say `JOB_STORE is not set` if you have only set the other. Its verbs are
`submit`, `claim`, `progress`, `finish`, `show`, `cancel`, `intent`, `recall`
and `orphans` — there is no `jobctl list`. It is the low-level tool for the job
store, and it is in this package because it is what is published, not because
it is the command-line experience we want. `dl list` is the friendly view of
your own downloads.

The three programs do agree about the **store format**, which is the thing that
matters: the release workflow has `dl` fetch a file, then requires `jobd` to
see that download and `jobctl show` to return the record `dl` wrote. It fails
if any of them disagrees.

## Assets

- `abstraction-x64.msi` — Windows on Intel or AMD
- `abstraction-arm64.msi` — Windows on ARM. **Built, and never run**: no arm64
  machine has installed this. Treat it as untested.
- `SHA256SUMS`

## Installing

Download `abstraction-x64.msi`, check it against `SHA256SUMS` below, then run
it. It installs to `%LOCALAPPDATA%\Programs\Abstraction`, adds that folder to
your `PATH`, and asks for no administrator rights. Open a new terminal
afterwards, or `PATH` will still be the old one.

    dl https://example.com/some/file.bin -o D:\downloads

Uninstall from Apps & features, or `msiexec /x abstraction-x64.msi`. The
release workflow installs and uninstalls the x64 package on a clean machine on
every run and fails if anything is left behind.

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
this release has none — see below. Both MSIs are built twice in one job and
compared byte for byte, so the hash below is a property of the inputs and not
of the minute the build ran.

## These packages are not signed

There is no code-signing certificate for Windows yet. Consequences, plainly:

- **SmartScreen will warn you**, and the publisher will show as unknown. That
  warning is correct. It is telling you exactly the thing this section is.
- **Our own strict mode refuses an unsigned service.** `jobd` installed from
  this package will not pass a strict-mode check.
- Nothing about these files can be traced to us cryptographically. If that is
  not a risk you want to take, build from source: every version is public, and
  `go install` reaches the same modules this package was built from.

Signing is a separate, manually approved step that is not wired to this
workflow. When a certificate exists, the four programs inside each MSI and the
MSIs themselves become signing targets.

## Absent from this release, deliberately

- **macOS.** No asset. The Developer ID exists but is not connected to CI, and
  an unsigned, unnotarised `.pkg` is worse than no `.pkg`.
- **Linux.** No asset. `go install` is the route there today; no `.deb` is
  built.
- **Abstraction Panel**, the graphical front end. It is published from nowhere,
  so no package can contain it.
- **The C++ developer headers.** No module carries them yet.
- **A container.** `jobd` for a NAS is a separate image; see
  [docker-jobd](https://github.com/openabstractions/docker-jobd).

## What may break

- The three programs come from three separately tagged modules, so they are
  three builds of one store format in a single package. The release workflow
  writes a job with `dl`, requires `jobd` to see it and `jobctl show` to return
  it, and fails if they disagree. That is one scenario, not a compatibility
  proof.
- **`jobctl` takes `JOB_STORE`, the other two take `ABSTRACTION_STORE`**, as
  above. Setting one does not set the other.
- **Windows on ARM is unrun**, as above.
- A partly fetched download does not resume across a reinstall.
- Nothing here has been measured on a machine that is not a CI runner.

## Source

Every program in this package is built from a public module. Nothing in the
package is built from a private tree.

- [service-jobd](https://github.com/openabstractions/service-jobd)
- [abstraction-download](https://github.com/openabstractions/abstraction-download)
- [abstraction-job](https://github.com/openabstractions/abstraction-job)
