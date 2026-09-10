# installer — what a Windows user actually installs

Two MSIs, `abstraction-x64.msi` and `abstraction-arm64.msi`, built by
`.github/workflows/release.yml` in `openabstractions/service-jobd`. Three
features, the shape .NET and Git for Windows already use:

| feature | default | what it is |
|---|---|---|
| Background service | on, cannot be unticked | `jobd`, and the scheduled task that runs it every five minutes |
| Command-line tools and panel | on | `dl`, `jobctl`, the panel, and this folder on `PATH` |
| Developer files | off | headers, the Python packages, the Go module paths |

The package is **per-user**: it installs into `%LOCALAPPDATA%\Programs\Abstraction`,
asks for no administrator, and registers its scheduled task as the person who
ran it. That is not a preference, and it is what decides the task shape.
`schtasks /create /sc onlogon` with no `/ru` registers a trigger for every
account on the machine, which an unelevated install may not do; naming an
account with `/ru` makes `schtasks` ask for that account's password, and a
`/qn` install has no console to answer with. So there is one task, the
five-minute sweep, which needs neither and picks up unfinished work within five
minutes of logon.

## Install

    msiexec /i abstraction-x64.msi

    msiexec /i abstraction-x64.msi /qn ADDLOCAL=Service,Tools,Developer

## Build it

WiX needs no .NET SDK. Unzip the two NuGet packages and run the tool:

    curl -Lo wix.zip https://api.nuget.org/v3-flatcontainer/wix/5.0.2/wix.5.0.2.nupkg
    curl -Lo ui.zip  https://api.nuget.org/v3-flatcontainer/wixtoolset.ui.wixext/5.0.2/wixtoolset.ui.wixext.5.0.2.nupkg
    unzip -q wix.zip -d wix && unzip -q ui.zip -d ui

    py -3 installer/build.py --arch x64 --version 0.2.0 \
      --wix wix/tools/net6.0/any/wix.exe \
      --ext ui/wixext5/WixToolset.UI.wixext.dll --out dist \
      --src self=. --src download=<abstraction-download> --src job=<abstraction-job>

`build.py` stages every `payload.tsv` row, writes `license.rtf` through
`mklicense.py`, runs `validate.py` and calls `wix build`. A source not named
with `--src` is left out, and it refuses to build a package missing a file
`abstraction.wxs` cannot gate away — which is how the UNRESOLVED rows leave the
package without anyone editing anything.

`--bin DIR` takes the programs from `DIR` instead of building them. That is the
release route: a package assembled out of published module versions, with no
repository checked out, which is what `openabstractions/redist` does and what a
stranger can reproduce.

**What comes out is unsigned**, and Windows will name the publisher unknown.
Signing is a separate, manually approved step, outside this build and outside
the release workflow, and it signs the programs inside each MSI as well as each
MSI — see `signpath.artifact-configuration.xml`.

## Check it

    py -3 installer/validate.py [package.msi ...] [--wix <wix>]

It parses `abstraction.wxs`, cross-checks it against `payload.tsv` and
`sources.tsv`, refuses a file that is in one and not the other or that two
features install, refuses a signing target that is not a PE file, refuses a
source pinned to anything but a 40-hex commit, and prints the signing targets.
`installer/signpath.artifact-configuration.xml` is checked against that list, so
adding a program without adding it to the signing configuration is a red build.

Given a built package it reads it back with `wix msi decompile` and refuses one
carrying a file `abstraction.wxs` does not install, or missing one it does and
cannot gate away.

## What may break

- **The panel and the C++ header have no publishable source.** Their rows in
  `payload.tsv` name `UNRESOLVED`, the workflow leaves them out and says so, and
  `abstraction.wxs` gates them on `$(var.Panel)` and `$(var.Cpp)`. Somebody has
  to decide which repository publishes them.
- **The Python packages are in the release build and not in the release
  package.** `$(var.Dev)` is the third gate. Those rows have a source, and a
  build assembled out of published module versions has no checkout to copy them
  from; they publish on their own registry instead. A build given `--src job`
  and `--src download` carries them, the release does not, and `dev/USING.txt`
  still tells the reader to install them from directories that are then not
  there. That sentence wants rewriting once it is settled where a person is
  told to get them.
- **A hosted runner is an administrator and a person is not.** The one CI run
  that installed this package — run 34364113642, 2026-09-09 — registered a
  logon task that an unelevated account cannot register at all. Measured
  2026-09-10 on a developer workstation, `research/dist189/RESULTS.md`: the same
  package fails `1603` for a normal user, and every green tick in that job was
  over a privilege the buyer does not have. Anything the `verify` job asserts is
  asserted as an administrator, and that is the one thing it cannot test.
- **Install and uninstall have been observed once each, off CI**, into a scratch
  prefix with `INSTALLFOLDER=`, on the package this directory builds today.
  Uninstall left no file, no registry key, no `PATH` entry, no task and no
  Apps & features row; the two fears recorded here before — the sweep task
  holding `jobd.exe` open, and `HKCU\Software\OpenAbstractions` surviving as an
  empty parent — did not happen. Neither has been observed while the sweep was
  actually mid-run.
- **Two builds of one version install alongside each other.** `abstraction.wxs`
  sets no `ProductCode`, so WiX generates one per build, and `MajorUpgrade`
  without `AllowSameVersionUpgrades` will not see the first install. The
  tag-driven workflow builds each version once and never hits this; anyone
  building locally twice does.
- **`jobd install` prints its `schtasks` lines rather than running them**, so the
  task shape has two owners and nothing compares them. Its logon line is the one
  this package had to drop, unchanged and untested: pasted into an unelevated
  shell it is the command that exits 1 here.
- **The Tools feature's title and description promise a panel** that is gated out
  and has no publishable source.
- **`sources.tsv` is behind the published tags.** Both pins resolve, neither is a
  tag any more.
