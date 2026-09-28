# Windows package qualification

Install instructions are in [README.md](README.md). This file keeps the build
steps, the validation checks, the qualification evidence and the known limits
for the Windows package: hosted CI run ids, dated field observations, the named
control-test script and the predecessor-version history a release gate reads.

## Build it

WiX needs no .NET SDK. Unzip the two NuGet packages and run the tool:

    curl -Lo wix.zip https://api.nuget.org/v3-flatcontainer/wix/5.0.2/wix.5.0.2.nupkg
    curl -Lo ui.zip  https://api.nuget.org/v3-flatcontainer/wixtoolset.ui.wixext/5.0.2/wixtoolset.ui.wixext.5.0.2.nupkg
    unzip -q wix.zip -d wix && unzip -q ui.zip -d ui

    py -3 installer/build.py --arch x64 --version 0.2.0 \
      --wix wix/tools/net6.0/any/wix.exe \
      --ext ui/wixext5/WixToolset.UI.wixext.dll --out dist \
      --src charter=<abstractions> --src panel=<abstractions>

With only a .NET runtime installed, run the same `wix.dll` through
`dotnet exec --roll-forward Major wix/tools/net6.0/any/wix.dll`, wrapped in a
one-line `.cmd` given to `--wix`.

The other route needs the .NET SDK, not just the runtime:
`dotnet tool install --global wix --version 5.0.2` installs the CLI itself as
a per-user global tool at `%USERPROFILE%\.dotnet\tools\wix.exe`, and `wix
extension add -g WixToolset.UI.wixext/5.0.2` adds the extension `--ext` names.
`dotnet tool install` is an SDK command; a machine carrying only the .NET
runtime, the way this one does, cannot run it directly. `FOOTPRINT.md`'s
2026-09-22 row records how WiX 5.0.2 was installed here: a temporary xcopy
.NET SDK, unpacked only to run that one `tool install` command and deleted
afterward, left `wix.exe` behind as an ordinary dotnet tool with no SDK of its
own needed to run it.

`build.py` stages every `payload.tsv` row, writes `license.rtf` through
`mklicense.py`, runs `validate.py` and calls `wix build`. A source not named
with `--src` is left out, and it refuses to build a package missing a file
`abstraction.wxs` cannot gate away — which is how the UNRESOLVED rows leave the
package without anyone editing anything.

The Panel detects the Evergreen runtime through its Windows registry
registration and loads WebView2 support from the installed runtime's
`EmbeddedBrowserWebView.dll`. When the runtime is unavailable, the Panel keeps
its browser fallback. No SDK loader DLL is downloaded or shipped with the MSI.
The installed-package `test_user_runtime.ps1 -Mode Verify -CheckTools` and
`-Unscoped` cases run `Abstraction Panel.exe -check-webview2` through the
fixture's bounded process helper. Exit 0 records `WebView2: available (native
rendering untested)` in `webview2-availability.txt`; exit 3 records
`WebView2: unavailable (browser fallback)` and passes under the Panel's
fallback policy. Any other exit or an inconsistent response fails
qualification. This resolves the installed Evergreen registration, DLL and
environment-creation export without starting a WebView2 browser process or a
window. Visible native rendering remains a separate field check.

The focused source-tree availability check is:

    go -C monitor/win test -run '^TestWebView2AvailableInstalled$' -count=1

This checks the local installed-runtime availability/export path and skips
when the runtime is absent. It supplements the installed-package result.

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

The installed per-user fixture, `test_user_runtime.ps1 -CheckTools`, downloads
a file from a loopback origin through the installed runtime with no store
named, reads it back with `jobs show`, `jobs list` and `jobs result --out
<file>`, and requires an equal submission to return the original operation.

## What may break

- **No release-route package carries either optional provider yet.**
  `abstraction-storage-over-local-stores` has no rule in
  `scripts/split.manifest` and no row in `published.tsv`, so `inventoryd` has
  never been published; `openabstractions-mcp` has no row in
  `redist/tools.tsv`. A `--bin` build obtains neither, gates both features
  away and names them in `ARPCOMMENTS`. Both are in a `--src` build today.
- **The bundled program path needs the runtime half.** A declaration file the
  installation places names its program as a file beside the runtime, which is
  how the Panel is named (`serve/runtime_credentials.go`, `operatorSiblings`).
  `serve/provider.go`'s `validProviderDeclaration` still requires
  `filepath.IsAbs` of every provider's program, so until it resolves a bundled
  name against the declarations directory's parent, the runtime reports
  `local-stores.json` as `invalid program` and leaves it out of the registry.
  Nothing else in the feature depends on it.
- **The Windows declaration files are not published.**
  `scripts/split.manifest`'s `redist` block names `installer/` file by file and
  has no rule for `installer/declarations/`, so
  `installer/test_central_cli.py` fails staging the published Windows payload.
  One line beside `tree windows/examples installer/examples` fixes it:
  `tree windows/declarations installer/declarations`.
- **The optional curl adapter header has no verified public commit.** Its
  declared home is `abstraction-download-over-curl`, but the public repository
  had no refs when checked on 2026-09-12. Its row remains `UNRESOLVED` and gated
  by `$(var.Cpp)`. Panel has a public module and a `tools.tsv` row; it is included
  when its prebuilt executable or source is supplied.
- **Large results move through 64 KiB exchanges.** `openabstractions download`
  and `jobs result` copy a result through the runtime's `ReadResult`; an 8 GiB
  file is about 131,000 exchanges. Typed result references are designed
  (VISION.md 2026-09-15) and not built.
- **Machine-scope evidence depends on the release run.** The workflow checks
  registration, configuration and recovery policy; a running per-user service
  instance also requires a suitable session. Read the run result and any
  explicit preview limitation; source tables alone do not prove installation.
- **Per-user verification uses a fresh non-administrator account.** The release
  workflow checks immediate readiness, removal, an upgrade from the predecessor
  release the caller names with `-PredecessorVersion`, and same-version reinstall
  in that account. The release run records their actual outcomes.
- **`sources.tsv` is behind the published tags.** Both pins resolve, neither is a
  tag any more.
- **The stop-free upgrade sequence needs an installed test.** WiX linking and
  MSI table inspection (`test_upgrade_sequence.py --wix`) verify that the
  exclusion executes before the new files, that no action stops a process and
  that the predecessor goes after the commit. Isolated tests cover the host's
  restart registration, a real `RmShutdown` of an inert host and its child, and
  the rollback activation mapping. Whether Restart Manager restarts a registered
  host after a real upgrade, the rollback activation of an installed 0.1.7, and
  the Startup shortcut's component after a late removal are measured only by an
  installed upgrade.
- **The machine-scope post-removal registration is unmeasured.**
  `RegisterSupervisorAfterRemoval` runs in the immediate sequence, so it reaches
  the SCM with the token that started msiexec. A machine upgrade driven from an
  elevated session has it; whether an upgrade started from Explorer's
  "for everyone" path does has not been measured. Its failure is checked, not
  ignored: the upgrade reports the error and re-running the installer registers
  the supervisor through `RegisterSupervisor`.
- **A quiet removal exits 0 while a reboot is still needed.** `msiexec /x
  /qn /norestart` sets `REBOOT=ReallySuppress`. When Restart Manager finds a
  critical application holding the product's files, Windows Installer moves the
  files aside, schedules their deletion for the next reboot (Info 1903) and
  logs "Removal success or error status: 0". Hosted run 34906434707 did this
  and left the runtime running. No package mechanism reports that state:
  `MsiRMFilesInUse` is shown only at full UI, `REBOOTPROMPT` only suppresses
  prompts, and `ReplacedInUseFiles` is set when an installation overwrites a
  file in use and was absent from that removal's log. The removal log records
  it. `test_removal_log.py` reads it, and the per-user fixture fails its removal
  verdict with the log's cause before its process deadline.
- **`signpath.artifact-configuration.xml` names a file inside an MSI in the
  vocabulary SignPath's published schema uses, and nobody has submitted a
  signing request yet.** `<zip-file>`, `<msi-file path="...">`,
  `<pe-file path="...">` and `<authenticode-sign/>` match
  docs.signpath.io/artifact-configuration/syntax, read 2026-09-22; the
  application plan is `research/ci76/SIGNPATH.md`. `validate.py` keeps this
  file and `payload.tsv` in step; it cannot check what SignPath will accept
  from a real signing request.
