# installer/posix — what a Linux or macOS user actually installs

Three assets, built by the release workflow in `openabstractions/redist`:

| asset | what it is |
|---|---|
| `abstraction-<version>-linux-amd64.tar.gz` | a tarball with `install.sh` |
| `abstraction-<version>-linux-arm64.tar.gz` | the same, for aarch64 |
| `abstraction-<version>-macos-universal.pkg` | one `pkg`, x86_64 and arm64 in one binary |

Locally built packages are unsigned. The redist release workflow can sign and
notarize the macOS package. Qualification evidence, the build steps and the
known limits for these packages are in
[QUALIFICATION.md](QUALIFICATION.md).

## What you get

Each package installs one program, `openabstractions`. It hosts the runtime
(`openabstractions serve runtime`), submits and observes downloads through it
(`openabstractions download`, `openabstractions jobs list|show|wait|cancel|result`)
and reports readiness (`openabstractions status`). None of these names a store.
`jobd`, `dl`, `jobctl`, the `abstraction-jobd` sweep units and the Python
file-store packages leave the packages in 0.2.0
([docs/REMOVED.md](https://github.com/openabstractions/abstractions/blob/main/docs/REMOVED.md)).

### Linux

| what | where | feature |
|---|---|---|
| `openabstractions` | `~/.local/bin/` | service |
| the four default host declarations | `~/.local/bin/declarations/` | service |
| shared runtime | `~/.config/systemd/user/abstraction-runtime.service` | service |
| `USING.txt` | `~/.local/share/abstraction/dev/` | service |
| `LICENSE` | `~/.local/share/abstraction/` | service |
| the uninstaller, its lifecycle helper and the list it works from | `~/.local/share/abstraction/{uninstall.sh,lifecycle.sh,MANIFEST}` | service |
| which feature puts each file there, and each one's default | `~/.local/share/abstraction/FEATURES` | service |
| `inventoryd` and `declarations/local-stores.json` | `~/.local/bin/` | localstores |
| `openabstractions-mcp` | `~/.local/bin/` | mcpgateway |

`./install.sh --help` lists the optional features this tarball carries and
their defaults. `localstores` is installed unless `--without` names it,
because it only reads; `mcpgateway` is installed only when `--with` names it.
A feature turned off is a file that never lands and never enters `MANIFEST`,
so `uninstall.sh` has nothing to say about it. Adding one later is
`./install.sh --with <feature>` over the existing installation, which is how
every other change to this installation is made.

### macOS

One `productbuild` archive around one `pkgbuild` component per feature, with
`<domains enable_currentUserHome="true" enable_localSystem="false"/>` so the only
destination the installer offers is the current user's home. The runtime's
component keeps the identifier every earlier version wrote,
`com.openabstractions.abstraction`, and is not a choice. Each optional
provider is a component and a choice of its own, because a distribution choice
selects a package and cannot select part of one:

| choice | identifier | ticked when the list opens |
|---|---|---|
| Local model stores | `com.openabstractions.abstraction.localstores` | yes |
| MCP gateway | `com.openabstractions.abstraction.mcpgateway` | no |

`customize="allow"`: Install takes those defaults, Customize opens the list.
The optional components install before the runtime's, whose `postinstall`
writes `MANIFEST` out of the files that are on disk — a choice not taken
leaves no path in the removal ledger. `uninstall.sh` forgets whichever of the
three receipts is present. A feature added later is the package run again with
that choice ticked, the way every other change to this installation is made.

| what | where |
|---|---|
| `openabstractions`, universal | `~/.local/bin/` |
| the LaunchAgent template | `~/.local/share/abstraction/com.openabstractions.runtime.plist` |
| the LaunchAgent, written by `postinstall` | `~/Library/LaunchAgents/com.openabstractions.runtime.plist` |
| `USING.txt` | `~/.local/share/abstraction/dev/` |
| `LICENSE` | `~/.local/share/abstraction/` |
| the uninstaller, its lifecycle helper and its two lists | `~/.local/share/abstraction/{uninstall.sh,lifecycle.sh,FILES,MANIFEST}` |

### Why a tarball on Linux and not `.deb` and `.rpm`

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

## Scope

All three assets are **per-user**. They install into the home directory, ask
for no root and no administrator password, and the background runtime each
registers belongs to the person who installed it — a systemd **user** unit on
Linux, a **LaunchAgent** on macOS. The runtime runs with the installing user's
permissions. Windows additionally offers a machine-wide installation that
registers per-user service instances.

`install.sh` enables `abstraction-runtime.service` through the systemd user
manager on Linux. The runtime executes `openabstractions serve runtime` and
restarts on failure. Installation polls the installed read-only `status`
command within 15 seconds and reports failure if any default runtime contract
is unavailable. The runtime owns durable jobs, logging and configuration;
`openabstractions start` starts it on demand and is idempotent with a running
one.

It does **not** fail when there is no systemd user manager — a container, WSL
without systemd, a machine with no user bus. It installs the program, prints
that nothing starts the runtime in the background and the command that runs it
in a terminal, and records `timer no` in the manifest. The key keeps its 0.1.7
name so an older ledger stays readable; it records whether a user manager owns
registration. Absence is reported, never passed.

On macOS, the runtime's LaunchAgent identifier is
`com.openabstractions.runtime`, at
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

## Commands

    tar -xzf abstraction-0.2.0-linux-amd64.tar.gz
    cd abstraction-0.2.0-linux-amd64
    ./install.sh
    ./install.sh --with mcpgateway --without localstores

It does **not** edit any shell profile. If `~/.local/bin` is not on `PATH` it
prints the one line to add and says why it will not add it for you.

    open abstraction-0.2.0-macos-universal.pkg

## Uninstall

Removal on Linux, exactly:

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

Removal on macOS, exactly the same command:

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
launchctl IPC. After stop verification it forgets each component package's receipt with
`pkgutil --volume "$HOME" --forget <identifier>`, because a
home-domain install records its receipt in `~/Library/Receipts`; it falls back
to `/` only when the receipt is there, and an absent receipt lets a rerun
finish. A receipt that is on neither volume is a feature that was not
installed, which is not an error.
It then deletes every other path in `MANIFEST`, prunes the empty directories, and
removes the runtime's `openabstractions-*-$USER.sock.lock` files in `$TMPDIR`
whose sockets are gone. `uninstall.sh`, `lifecycle.sh` and `MANIFEST` are deleted
last. Success and every failure print the retained data:
`~/.abstraction`, `~/Library/Application Support/abstraction`,
`~/Library/Application Support/openabstractions/runtime-v1` and
`~/Library/Caches/openabstractions`. A failure also prints the exact recovery
command, which is runnable because the uninstaller is still in place.
[QUALIFICATION.md](QUALIFICATION.md) records a known older-uninstaller receipt
failure and its manual recovery.

## Upgrade

Upgrading from 0.1.7 or earlier stops and retires the predecessor's `jobd`,
`dl`, `jobctl` and scheduled-sweep unit on Linux and its
`com.openabstractions.jobd` LaunchAgent label on macOS in favor of
`com.openabstractions.runtime`, before any file is replaced, while leaving any
downloads the predecessor left unfinished in `~/.abstraction` abandoned as
user data.
