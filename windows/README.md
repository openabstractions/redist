# installer — what a Windows user actually installs

Two MSIs, `abstraction-x64.msi` and `abstraction-arm64.msi`. Four features, the
shape .NET and Git for Windows already use:

| feature | default | what it is |
|---|---|---|
| Background supervisor | on, cannot be unticked | `jobd`, and whatever starts it: a per-user service for everyone, a Startup shortcut for just you |
| Command-line tools and examples | on | `dl`, `jobctl`, three examples that run against this install, and the panel when there is one to pack |
| Add to PATH | on, a tick of its own | `tools\` on `PATH`; untick it and the tools are still installed |
| Developer files | off | headers, the Python packages, the Go module paths |

## What lands where

    OpenAbstractions\
      tools\      dl.exe, jobctl.exe, jobd.exe, the panel — the one folder on PATH
      examples\   three folders, each one runnable .cmd and the source it runs
      dev\        USING.txt, and the headers and Python packages when packed

`payload.tsv`'s `path` column is that layout: `validate.py` fails a package that
installs a file anywhere else, fails an executable in a folder no `PATH` entry
names, and fails a `PATH` entry that is anything but the resolved `tools\`
directory itself — so the tools cannot move out from under `PATH`.

## Two scopes, and which one is the baseline

The package is **dual-purpose**: `Scope="perUserOrMachine"`, and the person
chooses.

| chosen | goes to | `PATH` | markers | what supervises `jobd` | needs |
|---|---|---|---|---|---|
| **Just me** (the default) | `%LOCALAPPDATA%\Programs\OpenAbstractions` | the user's `PATH` | `HKCU` | a Startup shortcut, at your next sign-in and no sooner | nothing |
| Everyone | `%ProgramFiles%\OpenAbstractions` | the machine `PATH` | `HKLM` | a per-user service: your own session, no password stored, restarted when it dies | administrator |

Per-user is the default and stays installable with no rights at all, because
`METHOD.md` §14 lets a layer require *a helper process the library can start
itself, user-scope* and lets it require *a system service needing admin* only
as an upgrade. Asked for all users from a token without the rights, Windows
refuses by name — error 1925, *you do not have sufficient privileges to
complete this installation for all users of the machine* — and installs
nothing.

## How the supervisor starts

**Installed for everyone: a per-user service.** Windows has one — a template
registered with `SERVICE_USER_OWN_PROCESS`, which the operating system clones
into every interactive session as `<name>_<luid>`, running as that person with
no password stored and restarted when it dies. Registering the template needs
an administrator once, which is what the machine scope has; a deferred custom
action runs `jobd service install` during that install and `jobd service
uninstall` on the way out. A custom action is used because `ServiceInstall` cannot
express it.

**Installed just for you: a shortcut in the Startup folder** running
`jobd start`, minimized, at your next sign-in and no sooner. Nothing replaces
the supervisor if it dies before then, and that is the whole difference between
the two scopes. `examples\what-this-machine-does\run.cmd` asks `sc qc` and
prints which of the two this machine got.

`jobd start` is idempotent by the pipe name rather than by timing, so the
shortcut, a tool and a person can all call it and one supervisor exists
afterwards. It answers at `\\.\pipe\openabstractions-jobs-<your SID>`.

**`jobd.exe` is a console program, so that shortcut shows a console window.**
`Show="minimized"` is all the shell lets a shortcut say about it: the window is
created by the loader, minimized, and goes away when `jobd start` exits. Making
it invisible needs a launcher built for the windows subsystem, which is a
program and not a packaging choice.

There is **no scheduled task any more.** The five-minute `jobd once` sweep was
a second writer over a store the supervisor already owns, and a console window
every five minutes for ever — `FOOTPRINT.md`'s 2026-09-06 rows record that
exact experience being removed from a different program of ours.

## Install

    msiexec /i abstraction-x64.msi

    msiexec /i abstraction-x64.msi /qn ADDLOCAL=Service,Tools,Path,Developer

`APPLICATIONFOLDER=` overrides the install folder. `ALLUSERS=1` asks for the
machine scope.

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
features install, refuses a file that lands anywhere but its `payload.tsv`
path, refuses an executable no `PATH` entry reaches, refuses a signing target
that is not a PE file, refuses a source pinned to anything but a 40-hex commit,
and prints the signing targets.
`installer/signpath.artifact-configuration.xml` is checked against that list, so
adding a program without adding it to the signing configuration is a red build.

Given a built package it reads it back with `wix msi decompile` and refuses one
carrying a file `abstraction.wxs` does not install, or missing one it does and
cannot gate away.

## What may break

- **The panel and the C++ header have no publishable source.** Their rows in
  `payload.tsv` name `UNRESOLVED`, the workflow leaves them out and says so, and
  `abstraction.wxs` gates them on `$(var.Panel)` and `$(var.Cpp)`. The panel's
  home and the `tools.tsv` row it needs are written out in
  the loader gives it no console.
- **The Python packages are in the release build and not in the release
  package.** `$(var.Dev)` is the third gate. Those rows have a source, and a
  build assembled out of published module versions has no checkout to copy them
  from; they publish on their own registry instead. A build given `--src job`
  and `--src download` carries them and the release does not; `dev/USING.txt`
  names both cases and points at the registry, and where a person is told to
  get them is still one sentence in a text file rather than a page anywhere.
- **The machine scope has never been installed.** Everything above about
  `%ProgramFiles%`, the machine `PATH`, `HKLM` and the per-user service is read
  from the built package's tables and from one refusal; no elevated install has
  been run by anybody. What remains is the list of commands
  that closes it, and § 3.3 says `UNPROVEN` in those words.
- **A hosted runner is an administrator and a person is not.** Anything the
  release workflow's `verify` job asserts is asserted as an administrator, and
  that is the one privilege it cannot test.
- **`jobd install` prints `schtasks` lines this package no longer registers.**
  Its sweep and logon lines are a second, hand-driven answer to the question the
  Startup shortcut now answers, and nothing compares them.
- **`sources.tsv` is behind the published tags.** Both pins resolve, neither is a
  tag any more.
- **No upgrade over an earlier version has been run.** `MajorUpgrade` schedules
  `RemoveExistingProducts` after `InstallValidate`, so the old version is
  removed whole — its files, its `PATH` entry and its service registration —
  before this one is laid down, and nothing is left at a path this version no
  longer uses. That is read from the package's sequence table; no upgrade has
  been performed.
- **The paths in `signpath.artifact-configuration.xml` are how we think SignPath
  addresses a file inside an MSI, and nobody has submitted one.**
  the element vocabulary is as written
  from memory of the schema. `validate.py` keeps that file and `payload.tsv` in
  step; it cannot check what SignPath will accept.
