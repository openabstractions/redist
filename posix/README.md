# installer/posix — what a Linux or macOS user actually installs

Three assets, built by the release workflow in `openabstractions/redist`:

| asset | what it is |
|---|---|
| `abstraction-<version>-linux-amd64.tar.gz` | a tarball with `install.sh` |
| `abstraction-<version>-linux-arm64.tar.gz` | the same, for aarch64 |
| `abstraction-<version>-macos-universal.pkg` | one `pkg`, x86_64 and arm64 in one binary |

All three are **per-user**. They install into the home directory, ask for no
root and no administrator password, and the background sweep each registers
belongs to the person who installed it — a systemd **user** unit on Linux, a
**LaunchAgent** on macOS. Neither is a system service, for the same reason the
Windows package is per-user: a supervisor that finishes your downloads runs as
you, and registering one for another account needs that account's password.

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
dependencies — the binaries are static, `CGO_ENABLED=0`), and no distribution
review. Reinstalling over an existing install is how you upgrade, and
`uninstall.sh` then `install.sh` is how you are sure.

## Linux — what it places, and what removes it

    tar -xzf abstraction-0.3.0-linux-amd64.tar.gz
    cd abstraction-0.3.0-linux-amd64
    ./install.sh

| what | where |
|---|---|
| `jobd`, `dl`, `jobctl`, `openabstractions` | `~/.local/bin/` |
| the sweep unit and its timer | `~/.config/systemd/user/abstraction-jobd.{service,timer}` |
| the Python packages and `USING.txt` | `~/.local/share/abstraction/dev/` |
| `LICENSE` | `~/.local/share/abstraction/` |
| the uninstaller and the list it works from | `~/.local/share/abstraction/{uninstall.sh,MANIFEST}` |

`install.sh` then runs `systemctl --user enable --now abstraction-jobd.timer`.
The timer fires 30 seconds after the user manager starts — which is your login —
and every 5 minutes after that, which is the same shape as the two Windows
scheduled tasks, `jobd-logon` and `jobd`.

It does **not** edit any shell profile. If `~/.local/bin` is not on `PATH` it
prints the one line to add and says why it will not add it for you.

It does **not** fail when there is no systemd user manager — a container, WSL
without systemd, a machine with no user bus. It installs the four programs,
prints that nothing will sweep in the background and what to run instead, and
records `timer no` in the manifest. Absence is reported, never passed.

Removal, exactly:

    ~/.local/share/abstraction/uninstall.sh

It disables and stops the timer, deletes every path in `MANIFEST` and nothing
else, removes every directory that is then empty up to your home directory, and
prints the command for the two things it deliberately leaves: `~/.abstraction`,
your job store, and `~/.config/abstraction`, what `jobd setup` recorded.

## macOS — what it places, and what removes it

    open abstraction-0.3.0-macos-universal.pkg

One `productbuild` archive around one `pkgbuild` component, identifier
`com.openabstractions.abstraction`, with
`<domains enable_currentUserHome="true" enable_localSystem="false"/>` so the only
destination the installer offers is the current user's home.

| what | where |
|---|---|
| `jobd`, `dl`, `jobctl`, `openabstractions`, universal | `~/.local/bin/` |
| the LaunchAgent | `~/Library/LaunchAgents/com.openabstractions.jobd.plist` |
| the Python packages and `USING.txt` | `~/.local/share/abstraction/dev/` |
| `LICENSE` | `~/.local/share/abstraction/` |
| the uninstaller and its two lists | `~/.local/share/abstraction/{uninstall.sh,FILES,MANIFEST}` |

**LaunchAgent identifier: `com.openabstractions.jobd`**, at
`~/Library/LaunchAgents/com.openabstractions.jobd.plist`. `RunAtLoad` is the
logon task; `StartInterval 300` is the five-minute sweep. `scripts/postinstall`
substitutes the absolute path of `jobd`, writes `MANIFEST`, chowns everything to
the installing user, and runs `launchctl bootstrap gui/<uid>`. If that user has
no graphical session right now, it says so and the agent loads at the next
login; it does not fail the install.

Removal, exactly the same command as on Linux:

    ~/.local/share/abstraction/uninstall.sh

It runs `launchctl bootout`, deletes every path in `MANIFEST`, prunes the empty
directories, runs `pkgutil --forget com.openabstractions.abstraction`, and
prints the command for `~/.abstraction` and
`~/Library/Application Support/abstraction`.

`openabstractions serve logging`, `openabstractions serve config`, and
`openabstractions serve router-v1` run the selected capability in the foreground.
The package supplies the executable but does not add automatic registration
for these commands. Its existing timer/LaunchAgent belongs to jobd.

## Build it

Both build from published sources checked out at the commits `sources.tsv`
pins, never from a working tree. `build.py` re-reads `git rev-parse HEAD` in
each checkout and refuses a build where it does not match.

    py -3 installer/posix/build.py --platform linux --arch amd64 --version 0.3.0 \
      --out dist --src jobd=<service-jobd> --src download=<abstraction-download> \
      --src job=<abstraction-job> --src charter=<abstractions>

    python3 installer/posix/build.py --platform macos --version 0.3.0 \
      --out dist --src jobd=<service-jobd> --src download=<abstraction-download> \
      --src job=<abstraction-job> --src charter=<abstractions>

The Linux tarball is deterministic: fixed mtimes, uid 0, sorted names, gzip with
no timestamp. Two builds of one commit are byte-identical. The macOS package is
not claimed to be; `pkgbuild` writes a bom and a payload archive of its own.

`--platform macos` needs `lipo`, `pkgbuild` and `productbuild`, and refuses by
name on a machine that has none of them rather than skipping the package.

## Signing

The local packager emits unsigned packages. The redist workflow can sign and
notarize the macOS package and its programs; it attaches a macOS asset only
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
- **The `enable_currentUserHome` install location is the least-travelled part.**
  A component built with `--install-location /` and installed into the home
  domain lands relative to the home directory; if that turns out to be wrong on
  a current macOS the payload lands at the filesystem root instead, and the
  first CI run is what will say so.
- **`jobd install` prints `schtasks` lines on every platform.** Run it on Linux
  or macOS and it tells you to type Windows commands. These packages therefore
  register the timer and the agent themselves, and now three places own the
  shape of that schedule instead of two.
- **Source-build pins and release module versions differ.** `sources.tsv`
  describes explicit checkout builds; redist builds programs from its
  `tools.tsv` module versions and passes them with `--bin`. A historical `-`
  tag field is not a statement about all tags now in that repository.
- **`~/.local/bin` is on `PATH` by default on most Linux distributions and on no
  macOS.** Both installers print the line; neither writes it.
- **The Windows package offers three features and these offer none.** A tarball
  and a `pkg` with `customize="never"` install everything they contain,
  developer files included. That is a deliberate divergence from
  `abstraction.wxs`, which makes Developer opt-in.
- **The Windows package ships runnable examples and these ship none.** Both
  packages agree on the tools — all four programs in one directory on `PATH`,
  `~/.local/bin` here and `OpenAbstractions\tools\` there — and `installer/examples/`
  has no counterpart on either platform. Its three `.cmd` files are Windows
  shells; a person on Linux or macOS is given `USING.txt` and nothing to run.
- **Upgrading is reinstalling.** Neither format removes a file that a previous
  version installed and this one does not.
