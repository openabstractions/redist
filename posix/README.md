# installer/posix — what a Linux or macOS user actually installs

Three assets, built by the release workflow in `openabstractions/redist`:

| asset | what it is |
|---|---|
| `abstraction-<version>-linux-amd64.tar.gz` | a tarball with `install.sh` |
| `abstraction-<version>-linux-arm64.tar.gz` | the same, for aarch64 |
| `abstraction-<version>-macos-universal.pkg` | one `pkg`, x86_64 and arm64 in one binary |

All three are **per-user**. They install into the home directory, ask for no
root and no administrator password, and the background runtime each registers
belongs to the person who installed it — a systemd **user** unit on Linux, a
**LaunchAgent** on macOS. Neither is a system service, for the same reason the
Windows package is per-user: the runtime that finishes your accepted work runs
as you, and registering one for another account needs that account's password.

Each package installs one program, `openabstractions`. It hosts the runtime
(`openabstractions serve runtime`), submits and observes downloads through it
(`openabstractions download`, `openabstractions jobs list|show|wait|cancel|result`)
and reports readiness (`openabstractions status`). None of these names a store.
`jobd`, `dl`, `jobctl`, the `abstraction-jobd` sweep units and the Python
file-store packages leave the packages in 0.2.0
([docs/REMOVED.md](https://github.com/openabstractions/abstractions/blob/main/docs/REMOVED.md)).

## Why a tarball on Linux and not `.deb` and `.rpm`

A `.deb` or an `.rpm` is a system package by construction. It is unpacked by
root, it lands under `/usr`, and there is no supported way for it to register a
systemd **user** unit for the person who typed `apt install` — `dpkg` does not
know who that was, and postinst scripts that guess get it wrong on multi-user
machines. Making this product a `.deb` would mean making it a system daemon,
which is a different product with different security properties and a different
answer to "what happens when you log out".

The second reason is cost. Two formats, two signing keys, two repository
layouts, and a per-distribution matrix that grows every time a distribution
does. The tarball is one artifact per architecture, works on every distribution
including the ones with no packaging story, and is the format `rustup`, `go`,
Node and every Go single-binary tool already ship.

What we give up: no `apt upgrade`, no dependency solving (there are no
dependencies — the binary is static, `CGO_ENABLED=0`), and no distribution
review. Reinstalling over an existing install is how you upgrade, and
`uninstall.sh` then `install.sh` is how you are sure.

## Linux — what it places, and what removes it

    tar -xzf abstraction-0.3.0-linux-amd64.tar.gz
    cd abstraction-0.3.0-linux-amd64
    ./install.sh

| what | where |
|---|---|
| `openabstractions` | `~/.local/bin/` |
| shared runtime | `~/.config/systemd/user/abstraction-runtime.service` |
| `USING.txt` | `~/.local/share/abstraction/dev/` |
| `LICENSE` | `~/.local/share/abstraction/` |
| the uninstaller, its lifecycle helper and the list it works from | `~/.local/share/abstraction/{uninstall.sh,lifecycle.sh,MANIFEST}` |

`install.sh` enables `abstraction-runtime.service` through the systemd user
manager. The runtime executes `openabstractions serve runtime` and restarts on
failure. Installation polls the installed read-only `status` command within 15
seconds and reports failure if any default runtime contract is unavailable. The
runtime owns durable jobs, logging and configuration; `openabstractions start`
starts it on demand and is idempotent with a running one.

It does **not** edit any shell profile. If `~/.local/bin` is not on `PATH` it
prints the one line to add and says why it will not add it for you.

It does **not** fail when there is no systemd user manager — a container, WSL
without systemd, a machine with no user bus. It installs the program, prints
that nothing starts the runtime in the background and the command that runs it
in a terminal, and records `timer no` in the manifest. The key keeps its 0.1.7
name so an older ledger stays readable; it records whether a user manager owns
registration. Absence is reported, never passed.

**Upgrading from 0.1.7 or earlier.** The candidate's `lifecycle.sh` stops
`abstraction-jobd.timer`, then `abstraction-jobd.service`, then the runtime,
before any file is replaced, and `install.sh` disables the timer before it
enables the runtime. The predecessor's `jobd`, `dl`, `jobctl` and sweep unit
files become `retired` entries in the new `MANIFEST` with the hashes the
predecessor recorded; `uninstall.sh` deletes each one whose bytes still match and
reports the ones a person changed. Downloads the predecessor's `dl` or `jobd`
left unfinished in `~/.abstraction` are abandoned: nothing reads or finishes
them, and removal keeps them as user data.

Removal, exactly:

    ~/.local/share/abstraction/uninstall.sh

It stops a retired sweep timer and service if a predecessor left them loaded,
then the runtime, before disabling registration. Each service has
`TimeoutStopSec=10s` and `KillMode=control-group`: systemd sends SIGTERM, then
can force remaining cgroup members to exit. The uninstaller records the service
result; a forced stop is reported separately from graceful completion. Manager
commands have a 20-second external bound (plus a two-second kill margin).
`timeout` from coreutils is required. A failed stop, active service, or
unavailable previously registered manager retains the payload and returns
failure. Upgrade also stops existing units before replacing files. The candidate
executable then runs `storage check` against the retained runtime state before
the installer changes any payload file or the removal manifest. An incompatible
store or busy participating host refuses the upgrade and preserves those files;
the previously stopped services remain stopped for the operator to inspect. This
check performs no migration. The runtime checks compatibility again when it takes
ownership. After verified stops, removal deletes every path in `MANIFEST` and
nothing else, removes every directory that is then empty up to your home
directory, and prints what it deliberately leaves: the runtime state and cache,
`~/.abstraction`, a legacy job store an earlier release wrote, and
`~/.config/abstraction`, the configuration.

## macOS — what it places, and what removes it

    open abstraction-0.3.0-macos-universal.pkg

One `productbuild` archive around one `pkgbuild` component, identifier
`com.openabstractions.abstraction`, with
`<domains enable_currentUserHome="true" enable_localSystem="false"/>` so the only
destination the installer offers is the current user's home.

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

| what | where |
|---|---|
| `openabstractions`, universal | `~/.local/bin/` |
| the LaunchAgent template | `~/.local/share/abstraction/com.openabstractions.runtime.plist` |
| the LaunchAgent, written by `postinstall` | `~/Library/LaunchAgents/com.openabstractions.runtime.plist` |
| `USING.txt` | `~/.local/share/abstraction/dev/` |
| `LICENSE` | `~/.local/share/abstraction/` |
| the uninstaller, its lifecycle helper and its two lists | `~/.local/share/abstraction/{uninstall.sh,lifecycle.sh,FILES,MANIFEST}` |

**LaunchAgent identifier: `com.openabstractions.runtime`**, at
`~/Library/LaunchAgents/com.openabstractions.runtime.plist`. It runs
`openabstractions serve runtime` with `RunAtLoad` and `KeepAlive`. The package
scripts run as the installing user for a home-domain install. The payload
carries the plist as a template in the share directory. `scripts/postinstall`
substitutes the absolute path of the program into a temporary file beside the
template, renames the finished file into `~/Library/LaunchAgents`, so Background
Task Management never reads the `@BIN@` placeholder, writes `MANIFEST`, changes
ownership of listed payload files and their ancestor directories below the
verified home, and runs `launchctl bootstrap gui/<uid>`. Manager-query,
bootout, enable, or bootstrap errors fail installation. Register from the target
user's graphical login session; the installed plist remains available after an
activation failure.

**Upgrading from 0.1.7 or earlier.** Those releases registered the same runtime
under the label `com.openabstractions.jobd`. `preinstall` boots out both
`com.openabstractions.jobd` and `com.openabstractions.runtime` and verifies each
absent before any file is replaced. `postinstall` then removes the retired
LaunchAgent plist, the retired template and `jobd`, `dl` and `jobctl`, each only
when the predecessor's `MANIFEST` lists it, because that plist would otherwise
start a second runtime at the next login. Downloads the predecessor left
unfinished in `~/.abstraction` are abandoned and kept as user data.

Removal, exactly the same command as on Linux:

    ~/.local/share/abstraction/uninstall.sh

Removal runs from the installing user's graphical login session: `manageruid`
and `managername` must identify that user's Aqua bootstrap. A successful,
validated `launchctl list` enumeration establishes presence or absence. An already
absent agent permits removal, including after a failed registration. A present
agent requires successful `bootout` followed by verified absence. Query errors,
unknown output, and SSH/other bootstrap contexts retain the payload and fail.
Directory ownership restoration walks installed paths only, refuses symlink
ancestors, and preserves unrelated sibling files.
`ExitTimeOut=10` bounds launchd's cooperative shutdown interval, and
`AbandonProcessGroup=false` retains launchd's process-group cleanup. This does not
establish that shutdown was graceful, or impose a verified wall-clock bound on
launchctl IPC. After stop verification it forgets the package receipt with
`pkgutil --volume "$HOME" --forget com.openabstractions.abstraction`, because a
home-domain install records its receipt in `~/Library/Receipts`; it falls back
to `/` only when the receipt is there, and an absent receipt lets a rerun finish.
It then deletes every other path in `MANIFEST`, prunes the empty directories, and
removes the runtime's `openabstractions-*-$USER.sock.lock` files in `$TMPDIR`
whose sockets are gone. `uninstall.sh`, `lifecycle.sh` and `MANIFEST` are deleted
last. Success and every failure print the retained data:
`~/.abstraction`, `~/Library/Application Support/abstraction`,
`~/Library/Application Support/openabstractions/runtime-v1` and
`~/Library/Caches/openabstractions`. A failure also prints the exact recovery
command, which is runnable because the uninstaller is still in place.

`openabstractions serve logging`, `openabstractions serve config`, and
`openabstractions serve router-v1` run the selected capability in the foreground.
Current macOS peer proof cannot establish the Program identity required by shared
runtime clients. This package makes no macOS capability-readiness promise.
Native macOS lifecycle verification remains required. Neither deleting a tarball
nor deleting a `.pkg` performs uninstall; the installed `uninstall.sh` is the
supported removal entry point. A receipt cleanup failure stops removal with the
payload and the uninstaller in place.

## Build it

Both build from published sources checked out at the commits `sources.tsv`
pins, never from a working tree. `build.py` re-reads `git rev-parse HEAD` in
each checkout and refuses a build where it does not match.

    py -3 installer/posix/build.py --platform linux --arch amd64 --version 0.3.0 \
      --out dist --src charter=<abstractions>

    python3 installer/posix/build.py --platform macos --version 0.3.0 \
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
