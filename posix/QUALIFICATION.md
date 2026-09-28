# installer/posix package qualification

Install instructions are in [README.md](README.md). This file keeps the build
steps, the signing state, the dated field observations and the known limits
for the Linux and macOS packages: what has been built, what has been measured
on a real machine, and what a release gate still needs.

## Field observations

Observed on macOS 26.6.2 (25G83), 2026-09-15, by double-clicking the 0.1.7
package in Finder:
Installer logs `Set authorization level to none for session` and asks for no
password. It starts a per-user `installd` and `package_script_service` as the
installing user (uid 501), so `preinstall` and `postinstall` run as that user.
`PKInstallRequest` names `destination=/Users/<user>`, the payload lands under the
home directory, and the receipt is written to `~/Library/Receipts`
(`pkgutil --volume "$HOME" --pkg-info com.openabstractions.abstraction`). The
system receipt database holds nothing for this package. Installing over a
running earlier version worked the same way: `preinstall` booted out the old
LaunchAgent, and `postinstall` registered the new one.

`openabstractions serve logging`, `openabstractions serve config`, and
`openabstractions serve router-v1` run the selected capability in the foreground.
Current source registers the runtime's XPC services with launchd and selects the
expected runtime executable and user from the current account's installation
database. Source-built installed-layout tests in a temporary home passed runtime
start/status and a `Discover` config denial through that path. A four-service
protected configuration test also passed authorized, denied, wrong-runtime,
concurrent and restart cases. The XPC client path requires macOS 12 or newer;
these executions used macOS 26.6.2. Publisher `Code` and `Package` remain
unknown, so policy must use only the evidence the transport reports.

The published signed 0.2.0 package predates this source support. It does not gain
XPC behavior from a source change, and the next package still needs its own
installation qualification. Local launchd lifecycle checks passed for the
source layout. Neither deleting a tarball
nor deleting a `.pkg` performs uninstall; the installed `uninstall.sh` is the
supported removal entry point. A receipt cleanup failure stops removal with the
payload and the uninstaller in place.

## Build it

Both build from published sources checked out at the commits `sources.tsv`
pins, never from a working tree. `build.py` re-reads `git rev-parse HEAD` in
each checkout and refuses a build where it does not match.

    py -3 installer/posix/build.py --platform linux --arch amd64 --version 0.2.0 \
      --out dist --src charter=<abstractions>

    python3 installer/posix/build.py --platform macos --version 0.2.0 \
      --out dist --src charter=<abstractions>

The release route passes `--bin DIR` with `openabstractions` built from the
module version in redist's `tools.tsv` instead of a checkout.

The Linux tarball is deterministic: fixed mtimes, uid 0, sorted names, gzip with
no timestamp. Two builds of one commit are byte-identical. The macOS package is
not claimed to be; `pkgbuild` writes a bom and a payload archive of its own.

`--platform macos` needs `lipo`, `pkgbuild` and `productbuild`, and refuses by
name on a machine that has none of them rather than skipping the package.

`sh scripts/wsl_posix_tests.sh --run` runs this directory's `python3 -m unittest`
fixtures inside WSL. `qualify_linux.py --run` qualifies a tarball against a real
systemd user manager in a temporary account, including a download through the
runtime with no store named.

## Signing

The local packager emits unsigned packages. The redist workflow can sign and
notarize the macOS package and its program; it attaches a macOS asset only
after those gates pass. Linux tarballs remain unsigned. Consult the selected
release for its actual signing and installation evidence.

Signing needs material only the project owner can produce, and what he has to
produce is not a stranger's business: it names a certificate, a person and a
team identifier. It is kept in the private tree.

## What may break

- **The optional features are unbuilt and uninstalled on both platforms.**
  The feature column, the split into one component package per feature, the
  distribution's choices, `install.sh --with` and the multi-receipt
  `uninstall.sh` were written and read back on Windows, where there is no
  `pkgbuild`, `productbuild` or `lipo`. `installer/test_features.py` runs the
  Linux selection and file filter through a real `sh` and parses the
  distribution the builder writes; nothing has built a `pkg` or installed one.
- **`inventoryd` has never been published.**
  `abstraction-storage-over-local-stores` has no rule in
  `scripts/split.manifest` and no row in `published.tsv`, so `sources.tsv`
  gives it no commit. A `--bin` build obtains no `inventoryd`, leaves the
  localstores feature out of the package and says so.
- **A declaration's program is a name and the runtime wants a path.**
  `local-stores.json` names `inventoryd` beside the runtime, the way the Panel
  is named. `serve/provider.go`'s `validProviderDeclaration` still requires
  `filepath.IsAbs`, so until it resolves a bundled name the runtime reports the
  file as `invalid program`.
- **Building and signing are not installation proof.** The hosted workflow
  builds the macOS package and conditionally signs/notarizes it. This does not
  establish that its postinstall, LaunchAgent or uninstall behavior was tested
  on an actual user installation.
- **The macOS label rename is unmeasured on a Mac.** The fixtures prove that
  `preinstall` boots out both labels and `postinstall` removes the retired plist
  the predecessor listed. An installed upgrade from 0.1.7 on a Mac has not run.
- **An older macOS uninstaller leaves the receipt and fails.** The receipt lives
  on the home volume, and `uninstall.sh` as of commit 114eb78e ran
  `pkgutil --forget` without `--volume "$HOME"`
  (`test_fixture_macos_uninstall_114eb78e.sh` keeps that script as a control). On 2026-09-15 that call printed
  `No receipt … found at '/'` and the script exited 1 after deleting the
  payload, including `uninstall.sh` itself. `MANIFEST` and the receipt remained.
  Manual cleanup: `pkgutil --volume "$HOME" --forget
  com.openabstractions.abstraction`, then delete
  `~/.local/share/abstraction/MANIFEST`.
- **The home-domain install location works.** A component built with
  `--install-location /` and installed into the home domain landed under the
  home directory on macOS 26.6.2.
- **Source-build pins and release module versions differ.** `sources.tsv`
  describes explicit checkout builds; redist builds `openabstractions` from its
  `tools.tsv` module version and passes it with `--bin`. A historical `-`
  tag field is not a statement about all tags now in that repository.
- **`~/.local/bin` is on `PATH` by default on most Linux distributions and on no
  macOS.** Both installers print the line; neither writes it.
- **The Windows package offers four features and these offer none.** A tarball
  and a `pkg` with `customize="never"` install everything they contain,
  developer files included. That is a deliberate divergence from
  `abstraction.wxs`, which makes Developer opt-in.
- **The Windows package ships runnable examples and these ship none.** Both
  packages agree on the program — `openabstractions` in one directory on `PATH`,
  `~/.local/bin` here and `OpenAbstractions\tools\` there — and
  `installer/examples/` has no counterpart on either platform. Its three `.cmd`
  files are Windows shells; a person on Linux or macOS is given `USING.txt` and
  nothing to run.
- **Large results move through 64 KiB exchanges.** `download` and `jobs result`
  copy a result through the runtime's `ReadResult`.
