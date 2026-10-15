# redist

The Open Abstractions redistributable packages programs built from published
module versions: the `openabstractions` service host and command.
Windows also includes `openabstractionsw`, the windowless runtime host, and
Abstraction Panel.

See [Releases](https://github.com/openabstractions/redist/releases) for available
downloads and their release-specific verification. Draft builds are not releases.
Each release lists its included capabilities, platform verification and signing state.

## For people installing

### Available now: 0.3.0

Download [Open Abstractions 0.3.0](https://github.com/openabstractions/redist/releases/tag/v0.3.0).
The release adds provider admission and credential protections, resource and
rights contracts, expanded inference APIs, `inventoryd`, `modelhostd`, an
optional MCP gateway, and the Windows Panel. Windows and Linux packages are
unsigned; ARM64 packages are cross-built. The macOS universal package is signed
and notarized. Its exact package passed installation, runtime/XPC readiness,
same-version reinstall, removal and postflight checks on macOS 26.6.2 arm64.
This acceptance does not establish crash-recovery behavior or older-system
qualification. See the release notes for package contents and signing details.

### Installing

The Windows MSI defaults to *Just me*, under
`%LOCALAPPDATA%\Programs\OpenAbstractions`. *Everyone* installs under
`%ProgramFiles%\OpenAbstractions` and requires elevation. **Add to PATH** is
optional; programs remain available by full path when it is unchecked.

Linux tarballs install for the current user through `install.sh`. The macOS
universal `.pkg`, when attached, also installs for the current user.
[Release notes](NOTES.md) explain the contents and installation choices.
Each release's appended notes name its actual assets and signing state;
consult that release's build for platform verification. Availability, signatures
and installation results are not promises made by this general README.

Compare downloads against the release's `SHA256SUMS`:

    sha256sum -c SHA256SUMS

**Check the release-specific signing notes.** Windows MSI and Linux tarball
assets are unsigned in the current workflow; macOS assets are attached only
after its signing and notarization gates. A checksum is not a signature.

The 0.3.0 CLI provides:

    openabstractions status --json
    openabstractions probe --json
    openabstractions applications list

`status` reports service readiness. `probe` performs bounded reads and prints
typed outcomes. `applications list` shows the caller's permission-filtered local
application directory. The 0.3.0 installers register the shared runtime,
which supervises configured capabilities.
Windows per-user installation starts it immediately and registers a windowless
Startup launcher. Check `openabstractions status --json` for readiness. Consult
the selected release notes for the behavior qualified in that release.

Developers can also run individual hosts in the foreground with
`openabstractions serve logging`, `serve config` and `serve router-v1`. These
commands do not install or register a service.

## For developers using `go install`

### Without an installer

[`tools.tsv`](tools.tsv) names each published module version and package.
Build the package at that version with `go install <package>@<version>`.
The windowless Windows executables additionally need the build flags specified by
the release workflow; plain `go install` does not reproduce their subsystem.

### What this repository is

One packaging repository for Windows, Linux and macOS. `tools.tsv` is the
version list consumed by the workflow; `windows/` and `posix/` hold packaging.
Programs' source stays in their own public modules. The candidate workflow
resolves pinned modules and retains verified packages. A separate promotion
workflow creates the release draft from those packages.

`tools.tsv` may name only versions that are tags on their repositories, so a
module we broke stops the release by name instead of shipping; the workflow
checks that with `git ls-remote --tags` rather than `proxy.golang.org`, which
can still serve a version whose tag was later deleted.

### Platform evidence and language packages

Each release reports which platform checks ran and which assets ship.
For NAS delivery, see [docker-jobd](https://github.com/openabstractions/docker-jobd).

The candidate also retains Python wheels and JavaScript package archives as
separate artifacts. `pypi.tsv` pins the source of the native `abstraction-ipc`
wheels, and `npm.tsv` pins JavaScript package sources. Installer promotion
consumes the `verified-release-N` and `setup-bundle-N` artifacts. Package-index publication needs its
own configured publisher and authorization; running a candidate does not upload
packages to PyPI or npm.

### Publishing the qualified Python wheels

The `publish.yml` workflow is a manual PyPI trusted publisher for the native
`abstraction-ipc` wheels. Dispatch the reviewed publisher workflow with the
candidate's `vMAJOR.MINOR.PATCH` version, run ID, exact redist source SHA and
current run attempt. The run must have succeeded without preview. The verifier checks the
candidate's source, version and attempt metadata in `verified-release-N`, then
selects the latest successful Python matrix job for each of Windows x64, Linux
x64, macOS arm64 and macOS x64. A retry may retain a successful wheel from an
earlier attempt of the same run. Each selected artifact must match its job's
attempt and the candidate source. The verifier checks GitHub artifact digests,
per-wheel SHA256SUMS, the exact wheel filenames and native wheel contents before
staging four wheels. It builds nothing.

Current candidates give each Python matrix job a stable `python (<platform-id>)`
name. For an older candidate, the verifier accepts a matching default
`python (<platform-id>, ...)` name when GitHub's run-jobs response proves it;
unrecognized names or absent attempt numbers refuse. A failed upload can be
retried without rerunning verification: the upload job downloads the exact
artifact ID emitted by the successful verification job.

The publisher workflow can be introduced after a candidate completed. Its
dispatch ref may therefore be a later reviewed redist commit; the explicit
candidate source input is checked against the candidate run and its artifacts.

The upload job waits at the `pypi` environment gate and uses GitHub OIDC through
PyPI Trusted Publishing. Before dispatch, the owner must verify that the
`abstraction-ipc` PyPI publisher is configured for the `openabstractions/redist`
repository, `.github/workflows/publish.yml` and `pypi` environment, including
any required environment approval. The repository cannot verify those account
settings offline. PyPI publication is permanent; inspect the candidate and
the four wheels before approving that job. The old layer Python publisher has
different source and artifact assumptions and remains separate.

## For maintainers cutting a release

### First app producers and immutable app inputs

An explicit `app_producer_only=comfyui` candidate measures the first
app/source pair with an empty Setup catalog. It also needs the reviewed
exact `comfyui_producer_adopter_commit`. OpenCode installs through its official
installer and has no app producer. The existing public source checkouts,
Windows wheel/addon jobs, pinned inputs and clean-path pair inspector remain
required. This mode skips installer/platform/draft jobs and enables no Setup
selection. Its immutable `oa-app-APP-ATTEMPT` artifact retains measured
`app.json`, the original `producer.json`, `pair-receipt.json`, `inputs.json`
and both complete ZIPs. Artifact ID/digest is observed after upload.

After reviewing those real outputs, a later consumer source may pin the earlier
producer as an immutable dependency in the workflow's literal `APP_PRODUCERS`
object. Each app entry requires `candidate_source`, `run_id`, `artifact_id`,
`artifact_digest`, `inputs_sha256` and `derivation`. Keep `{}` until actual
reviewed identities exist. The same-run builder remains strict without such a
declaration. A producer JSON or local pair cannot authenticate a predecessor.

The consumer checks repository/manual workflow/source, newest successful app
job/attempt, exact artifact ID/digest/expiry and fixed streamed file roster.
It reinspects the original pair, preserves its actual older full corresponding
source and original producer receipt, and writes a separate current consumer
receipt. The app was built at producer P; current consumer C's source mirrors
and package pins remain current C. No bytes are relabeled or rebuilt.

All functional source commits must match. The only charter diff exceptions are
`monitor/internal/setup/adopter_assets.json`,
`docs/results/focused/shared-javascript-capabilities-windows.json` and
`docs/results/MATRIX.txt`, mapped by `split.manifest`. `derivation` binds these
three SHA-256 values, `record_input_digest`, `record_digest` and
`generator_receipt_sha256`, plus the existing website `coverage.html` and
`languages.html` output digests. Website outputs are declaration evidence,
never charter diff exceptions. The actual canonical recorder/generator receipt
and their input/output binding must be reviewed with C before publication;
record checksums alone do not prove source authenticity. Every other charter
path and app source change refuses and requires a fresh genuine producer.

Producer dispatch, source publication and final release promotion each need
exact owner authorization. Producer-only success proves no installed behavior
or final consumer release.

Run `candidate.yml` from the reviewed `release/X.Y.Z` branch with
`version=vX.Y.Z`. It builds from the published versions in `tools.tsv`, records
the selected module graph and tag commits, and runs packaging, installer,
reproducibility and signing checks. Its `verified-release-N` artifact contains
the checked packages, checksums, release notes and exact source/run metadata.
Its `setup-bundle-N` artifact contains the signed
`OpenAbstractions-Setup-X.Y.Z.exe`, any application MSIs it offers, its
`bundle-receipt.json` and `SHA256SUMS.setup`.
Artifacts are retained for 30 days. No release tag is created at this stage.

Windows release outputs require the public certificate policy in
`windows/certum_simplysign.json`. Fresh signing hosts consume exact producer
artifact IDs and digests. They sign the authoritative runtime PEs, x64 IPC DLL
and Node addon before language packaging and MSI assembly; the same signed DLL
bytes enter the wheel, npm package and x64 MSI. ARM64 has no IPC DLL. MSI
containers are signed before Burn records their hashes, then the detached
engine and outer Setup are signed. Independent Windows verification requires
the expected leaf, code-signing EKU, online trusted chains with resolved
revocation, and RFC3161 SHA-256 timestamps. Signing credentials occur only in
the protected `signing` environment on the reviewed release branch.

The unified release runner first dispatches `signing_probe_only=true` against
the exact prepared commit. This builds and signs a fixed hello EXE and minimal
MSI before expensive qualification. Its `windows-signing-probe-N` artifact is
distinct from final candidate and native installation evidence.

### Reviewed PyTorch input transport

When `tools.tsv` selects `pytorchd.exe`, the candidate requires the exact retained
reviewed native input ZIP and owner manifest. Both `pytorchimage` and
`pytorchengine` in `windows/sources.tsv` must pin the same provider commit.
Before dispatch, obtain authorization for the exact clean prepared redist
commit Q, the retained input pair and its temporary draft tag. From that
checkout run:

```text
python3 scripts/promote.py seed-pytorch-inputs --inputs <retained pair directory> --sources windows/sources.tsv --source <Q> --version X.Y.Z --output <owned seed receipt path>
```

The publication owner creates `oa-inputs-pytorch-<full Q>` as a direct commit
tag and draft release. It checks the reviewed names, sizes and digests, refuses
wrong source/tag/body, published releases and foreign or changed assets, and
uploads only missing exact files without replacement or deletion. Retry the
same command and receipt path after an interruption. Preserve any refused
draft for inspection; publishing or deleting this temporary seed is a separate
authorized action.

Use the returned release and asset IDs as `pytorch_input_release_id`,
`pytorch_input_bundle_asset_id` and `pytorch_input_manifest_asset_id` when
dispatching `candidate.yml` at this same Q. The authenticated intake verifies
the draft, exact asset IDs and every canonical bundle member, then uploads an
immutable Actions artifact. Its receipt records the original reviewed local
byte derivation and genuine CI intake; it does not claim a CI engine rebuild
or native qualification. Windows checks the newest intake job verdict, exact
artifact ID/digest/expiry and receipt before packaging. Its later consumer
receipt records the enclosing artifact, preserving the receipt chronology.

The jobs request contents/read and actions/read. Live draft visibility with
the repository token remains unproved until the authorized run; an API refusal
fails closed without a permission fallback. A source change requires a new Q
and candidate. The temporary input tag does not create the release version tag.

Inspect the failed step if a job fails. Retry failed jobs on that run;
successful build artifacts remain available. GitHub reruns the failed jobs
and their dependent jobs in a new attempt
([REST reference](https://docs.github.com/en/rest/actions/workflow-runs#re-run-failed-jobs-from-a-workflow-run)),
and every job except `bundle` is `draft` or upstream of it, so the new
attempt drafts again. When `bundle` alone failed after `draft` succeeded,
rerun all jobs instead: a failed-jobs rerun would run `bundle` without a new
`verified-release-N`, and promotion takes both artifacts of the current
attempt. `python3 scripts/promote.py --status --run <ID>` names the command. A source change requires a new
candidate. Preserve the run URL when handing work to another maintainer.

After the candidate passes, fast-forward `main` to its exact commit through
the publication tool. Run `release.yml` from that same release branch with the
same `version` and its `candidate_run` ID. Promotion verifies the run, artifact
digest and every package checksum, then creates the version tag and a draft
release from those bytes. It invokes no builds or installation tests.
The Setup bundle comes from `setup-bundle-N` of the same attempt, with
the same run and artifact checks. Its receipt must prove the signed bundle,
engine and MSI chain under the expected certificate policy,
and must name this release's `abstraction-x64.msi` as the first package, and
the release notes must name the bundle. The draft carries the bundle and its
application MSIs, and `SHA256SUMS` gains a line for each.
Review the draft and publish it as a separate action.

An explicit candidate `preview=true` records the existing machine-scope
evidence exception. Compilation and installer checks remain required.
If promotion stops after creating the tag or draft, inspect that run and use
`resume=true` with the same candidate. Recovery accepts only the exact tag,
notes and asset bytes already verified. Existing assets are never replaced.
