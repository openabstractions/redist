import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import stat
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath

from validate import rows
import runtime_imports
from modelhost_engine import (BUNDLE_NAME as MODELHOST_ENGINE_NAME,
                              RECEIPT_NAME as MODELHOST_RECEIPT_NAME,
                              pin as modelhost_pin, verify_bundle)

HERE = Path(__file__).resolve().parent
GOARCH = {"x64": "amd64", "arm64": "arm64"}
GATE = {"tools/Abstraction Panel.exe": "Panel",
        "tools/OpenAbstractions Presenter.exe": "Panel",
        "tools/abstraction_facade_appmodel.dll": "Panel",
        "dev/include/abstraction/download/over_curl.hpp": "Cpp",
        "tools/inventoryd.exe": "LocalStores",
        "tools/modelhostd.exe": "ModelHost",
        "tools/engines/llama-b10825-oa-win-vulkan-x64.zip": "ModelHostEngine",
        "tools/engines/llama-b10825-oa-win-vulkan-x64.receipt.json": "ModelHostEngine",
        "tools/engines/llama.cpp-MIT.txt": "ModelHostEngine",
        "tools/engines/BoringSSL-LICENSE.txt": "ModelHostEngine",
        "tools/lemonaded.exe": "LemonadeImage",
        "tools/pytorchd.exe": "PyTorchImage",
        "tools/declarations/lemonade-image.json": "LemonadeImage",
        "tools/openabstractions-mcp.exe": "McpGateway",
        "tools/abstraction_ipc.dll": "IpcLibrary",
        "tools/openabstractions-system.exe": "SystemHelper"}
MODELHOST_ENGINE_PAYLOAD = frozenset({"tools/engines/" + MODELHOST_ENGINE_NAME,
                                      "tools/engines/" + MODELHOST_RECEIPT_NAME,
                                      "tools/engines/llama.cpp-MIT.txt",
                                      "tools/engines/BoringSSL-LICENSE.txt"})
VISUALCPP_NOTICE = HERE / "engines/VisualCpp-runtime-notice.txt"
# The third-party Go modules every package compiles in, with their licences
# (scripts/third_party_notices.py writes it).
THIRD_PARTY_NOTICES = HERE.parent / "THIRD_PARTY_NOTICES.md"
BORINGSSL_NOTICE_SHA256 ="827c8d8fc207c2392794eef9e00fe246f9f61fdcc132556c275be3dd8c3cd97f"
PYTORCH_PAYLOAD = frozenset({"tools/pytorchd.exe"})


def licence_notices(out):
    """The notices the licence page carries after the licence: the compiled
    Go modules' notices always, and the Microsoft Visual C++ runtime notice
    when the package ships the engine bundle with those files."""
    notices = [str(THIRD_PARTY_NOTICES)]
    if (out / "payload/tools/engines" / MODELHOST_ENGINE_NAME).is_file():
        notices.append(str(VISUALCPP_NOTICE))
    return notices


def shipped_program_role(module, package):
    """Partition executable rows by their source owner's program identity."""
    module = module.split('@', 1)[0]
    if package == '.' and module == 'github.com/openabstractions/abstractions/serve':
        return 'runtime'
    if package == '.' and module == 'github.com/openabstractions/abstractions/monitor':
        return 'operator'
    return 'provider'


def encode_shipped_provider_images(images):
    """Encode final provider bytes for the runtime's private linker input."""
    if not isinstance(images, dict):
        raise ValueError('shipped provider images must be a mapping')
    if not images:
        return ''
    seen = set()
    for name, digest in images.items():
        if (not isinstance(name, str) or not name or '\\' in name
                or any(ord(c) < 32 or c in '<>:"|?*' for c in name)
                or any(part in ('', '.', '..') or part.endswith((' ', '.'))
                       for part in name.split('/'))
                or name.casefold() in seen):
            raise ValueError('invalid shipped provider relative path')
        seen.add(name.casefold())
        if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
            raise ValueError('invalid shipped provider raw SHA256')
    raw = json.dumps({'version': 1, 'images': images}, sort_keys=True,
                     separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return base64.b64encode(raw).decode('ascii')


def decode_shipped_provider_images(encoded):
    if encoded == '':
        return {}
    try:
        raw = base64.b64decode(encoded, validate=True)
        record = json.loads(raw.decode('utf-8'))
        if (not isinstance(record, dict) or set(record) != {'version', 'images'}
                or type(record['version']) is not int or record['version'] != 1
                or encode_shipped_provider_images(record['images']) != encoded):
            raise ValueError('noncanonical shipped provider record')
        return record['images']
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise ValueError('invalid shipped provider record') from exc


def _shipped_image(path, required_record=None):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('shipped image path is redirected')
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('shipped image must be an ordinary single-link file')
        digest = hashlib.sha256(); tail = b''; found = not required_record
        while block := stream.read(1 << 20):
            digest.update(block)
            if required_record:
                combined = tail + block
                found = found or required_record in combined
                tail = combined[-(len(required_record) - 1):]
        after = os.fstat(stream.fileno())
    def identity(value):
        return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_nlink,
                value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after) or identity(after) != identity(path.stat()):
        raise ValueError('shipped image changed while reading')
    if not found:
        raise ValueError('runtime image lacks the final shipped provider record')
    return digest.hexdigest()


def verify_shipped_runtime_record(path, images):
    """Read final image bytes without executing the newly linked runtime."""
    encoded = encode_shipped_provider_images(images)
    return _shipped_image(Path(path), encoded.encode('ascii') if encoded else None)


def shipped_provider_images(tools_dir, provider_names):
    """Hash ordinary final provider files while retaining their file identity."""
    tools_dir = Path(tools_dir)
    images = {}
    for name in provider_names:
        encode_shipped_provider_images({name: '0' * 64})
        path = tools_dir.joinpath(*name.split('/'))
        for candidate in (tools_dir, *path.parents[:len(Path(name).parts)-1], path):
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('shipped provider path is redirected')
        if name in images:
            raise ValueError('duplicate shipped provider path')
        images[name] = _shipped_image(path)
    encode_shipped_provider_images(images)
    return images


def prebuilt(binaries, kind, path):
    if binaries is None or kind != "gobuild":
        return None
    p = binaries / Path(path).name
    return p if p.is_file() else None


# The private checkout carries the picture engine providers beside this
# packager. Setup's picture plan installs the core's PyTorchImage feature on a
# Strix Halo computer and LemonadeImage elsewhere, so an x64 package built
# from this checkout's sources always receives the two provider-only
# features. TheNoise is not shipped (owner 2026-11-11). A --bin package takes
# the programs from --bin, and the published tree, which has no provider
# source here, keeps its explicit --src. The PyTorch runtime input ZIP (pytorch_engine.py) is never a
# core payload: it is a separate release component Setup downloads.
PROVIDER_SOURCES = HERE.parent / "openabstractions-flat"
LEMONADE_IMAGE_SOURCE = PROVIDER_SOURCES / "abstraction-provider-lemonade"
PYTORCH_IMAGE_SOURCE = PROVIDER_SOURCES / "abstraction-provider-pytorch"


def lemonade_image_declaration(declaration, pins):
    """Declare reviewed picture recipes; storage evidence decides installation."""
    declaration = json.loads(json.dumps(declaration))
    provider = next(p for p in declaration['providers'] if p['name'] == 'lemonade-image')
    qualified = pins['qualified_model']
    models = [(qualified['id'], [
        {'role': role, 'sha256': qualified[key]}
        for role, key in (('main', 'main_sha256'), ('text_encoder', 'encoder_sha256'), ('vae', 'vae_sha256'))])]
    models += [(model['id'], model['files']) for model in pins['declared_models']]
    provider['models'] = ([{'modality': 'image', 'model': name} for name, _ in models]
                          + [model for model in provider['models'] if model['modality'] != 'image'])
    # The speech recipes stay as the provider's reviewed table declares them.
    provider['recipes'] = [
        {'model': name, 'engine': 'sdcpp', 'modalities': ['image'],
         'objects': [{'role': file['role'], 'digest': 'sha256:' + file['sha256'], 'store': '', 'object': ''}
                     for file in files]}
        for name, files in models] + [recipe for recipe in provider['recipes'] if 'image' not in recipe['modalities']]
    return declaration


def checkout_sources(src, arch, binaries, lemonade=LEMONADE_IMAGE_SOURCE, pytorch=PYTORCH_IMAGE_SOURCE):
    """src with the checkout's lemonadeimage and pytorchimage sources added
    for an x64 source build. An explicit --src keeps its folder."""
    if arch != "x64" or binaries is not None:
        return src
    src = dict(src)
    for source, root, program in (("lemonadeimage", lemonade, "lemonaded"),
                                  ("pytorchimage", pytorch, "pytorchd")):
        if source not in src and (root / "go" / "cmd" / program).is_dir():
            src[source] = root
    return src


LOCAL_PACKAGE_VARIABLES = ('github.com/openabstractions/abstractions/monitor/internal/setup.LocalPackageFolder',
                           'github.com/openabstractions/abstractions/monitor/internal/setup.LocalPackageAssetsSHA256')


def local_package_flags(local_packages):
    """Link a private preview's package folder and its pin document's SHA-256 into the Panel."""
    if local_packages is None:
        return ''
    folder, digest = local_packages
    if (not Path(folder).is_absolute() or "'" in folder or not re.fullmatch('[0-9a-f]{64}', digest)
            or hashlib.sha256((Path(folder) / 'adopter_assets.json').read_bytes()).hexdigest() != digest):
        raise ValueError('local packages need an absolute folder whose adopter_assets.json has the given SHA-256')
    return ''.join(" -X '" + name + '=' + value + "'" for name, value in zip(LOCAL_PACKAGE_VARIABLES, (folder, digest)))


# The Panel and the Asks presenter are the monitor package built twice. Only
# the presenter build compiles the native question, credential-form and toast
# surfaces, and each build links its own version resource
# (monitor/internal/panelres, monitor/internal/presenterres).
GO_TAGS = {'tools/Abstraction Panel.exe': 'panel', 'tools/OpenAbstractions Presenter.exe': 'presenter'}


def ldflags(subsystem):
    return "-s -w -buildid=" + (" -H=windowsgui" if subsystem == "windows" else "")


def payload_program_role(source, package):
    identities = {('charter', 'serve'): 'github.com/openabstractions/abstractions/serve',
                  ('panel', 'monitor'): 'github.com/openabstractions/abstractions/monitor'}
    if (source, package) in identities:
        return shipped_program_role(identities[source, package], '.')
    return 'provider'


def included_provider_names(arch, available_names):
    available = set(available_names)
    return [path.removeprefix('tools/') for feature, path, kind, source, package, _, _ in rows('payload.tsv')
            if kind == 'gobuild' and path.startswith('tools/') and path.endswith('.exe')
            and path.removeprefix('tools/') in available and payload_program_role(source, package) == 'provider'
            and included_payload(path, feature, arch, 'pytorchd.exe' in available, 'modelhostd.exe' in available)]


def verify_shipped_runtime_cohort(programs, arch, *, require_runtime=False):
    images = {name: _shipped_image(Path(programs[name])) for name in included_provider_names(arch, programs)}
    runtimes = [path.removeprefix('tools/') for _,path,kind,source,package,_,_ in rows('payload.tsv')
                if kind == 'gobuild' and payload_program_role(source, package) == 'runtime']
    for name in runtimes:
        if name not in programs:
            if require_runtime:
                raise ValueError('runtime missing from shipped cohort: ' + name)
            continue
        verify_shipped_runtime_record(programs[name], images)
    return images


def windows_go_environment(base):
    # Private checkout and projected redist carry the same source-owned helper.
    paths = (HERE.parent / "scripts/windows_go_sdk.py", HERE.parent / "tools/windows_go_sdk.py")
    helper = next((path for path in paths if path.is_file()), None)
    if helper is None:
        raise ValueError("Windows build needs the carried verified Go SDK helper")
    spec = importlib.util.spec_from_file_location("oa_installer_windows_go_sdk", helper)
    sdk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sdk)
    linked = base.get("OA_WINDOWS_GO_SDK_RECEIPT")
    receipt = (sdk.validate_sdk_receipt(json.loads(Path(linked).read_bytes())) if linked
               else sdk.prepare_sdk(HERE.parent / ".forks/windows-go-sdk"))
    return sdk.sdk_environment(receipt, base), sdk, receipt


def included_payload(path, feature, arch, pytorch_program, host_program):
    """Existing architecture/provider-presence exclusions for one payload row."""
    if path in PYTORCH_PAYLOAD and (arch != 'x64' or not pytorch_program):
        return False
    if path in MODELHOST_ENGINE_PAYLOAD and (arch != 'x64' or not host_program):
        return False
    if feature == 'lemonadeimage' and arch != 'x64':
        return False
    return True


def require_admitted_panel(src, binaries):
    """A receipt-backed train package carries the complete existing Panel group."""
    required = [Path(path).name for path, feature in GATE.items()
                if feature == 'Panel' and path.endswith('.exe')]
    missing = [name for name in required if binaries is None or not (binaries / name).is_file()]
    native = src.get('appmodellibrary')
    if native is None or not (native / 'abstraction_facade_appmodel.dll').is_file():
        missing.append('abstraction_facade_appmodel.dll')
    if missing:
        raise ValueError('admitted train package requires complete Panel payload: ' + ', '.join(missing))


def panel_appmodel_input(src, arch, binaries):
    """Admit the Panel's selected native component before staging any file."""
    selected = prebuilt(binaries, "gobuild", "tools/Abstraction Panel.exe") is not None or "panel" in src
    directory = src.get("appmodellibrary")
    library = directory / "abstraction_facade_appmodel.dll" if directory is not None else None
    if selected and (library is None or not library.is_file()):
        raise ValueError("Panel requires its selected-architecture shared AppModel library")
    if library is not None and library.is_file():
        helper = HERE.parent / "scripts/windows_native.py"
        if not helper.is_file():
            raise ValueError("Panel native library requires the carried Windows dependency owner")
        spec = importlib.util.spec_from_file_location("oa_panel_native_dependencies", helper)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        owner.validate_portable_windows_dll(library, "win32-" + arch)
    return library


def resource_host_environment(environment):
    """Run source generators on the host, preserving the admitted build inputs."""
    host = dict(environment)
    for key in ('GOOS', 'GOARCH', 'GOFLAGS'):
        host.pop(key, None)
    return host


def agent_release_inputs(channel, version):
    """Explicit producer metadata has no clock, filename or source-hash default."""
    import re
    if not channel and not version:
        return False
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', channel or ''):
        raise ValueError('agent release requires an explicit channel and ordered version')
    parts = (version or '').split('.')
    if (len(parts) != 4 or any(not re.fullmatch(r'0|[1-9][0-9]*', p) or int(p) > 65535 for p in parts)
            or not any(int(p) for p in parts)):
        raise ValueError('agent release requires four canonical 16-bit ordered version components')
    return True


@contextmanager
def agent_release_object(source, out, arch, environment, channel, version):
    """Use existing catalogue/resource producers before Go links signed bytes."""
    if not agent_release_inputs(channel, version):
        yield
        return
    source = source.resolve()
    gateway = source / 'mcp-gateway'
    compiler = source / 'monitor/icon/gen'
    if not compiler.is_dir():
        compiler = source / 'tools/windows-resource-gen'
    if not gateway.is_dir() or not compiler.is_dir():
        raise ValueError('agent release source requires its catalogue and Windows resource compiler')
    object_path = gateway / ('rsrc_windows_' + GOARCH[arch] + '.syso')
    if object_path.exists() or object_path.is_symlink():
        raise ValueError('agent release object output must be absent')
    go = str(Path(environment['GOROOT']) / 'bin/go.exe') if 'GOROOT' in environment else 'go'
    host = resource_host_environment(environment)
    try:
        with tempfile.TemporaryDirectory(prefix='oa-agent-release-', dir=out) as directory:
            payload = Path(directory).resolve() / 'agent-release.json'
            subprocess.run([go, '-C', str(gateway), 'run', './cmd/messages-catalogue',
                            '--surface', 'agent-release', '--release-channel', channel,
                            '--release-version', version, '--out', str(payload)], check=True, env=host)
            files = [str(compiler / name) for name in ('main.go', 'native.go', 'agent_release.go')]
            subprocess.run([go, 'run', *files, '-agent-release-json', str(payload),
                            '-agent-release-object', str(object_path), '-agent-release-arch', GOARCH[arch]],
                           check=True, env=host)
            yield
    finally:
        object_path.unlink(missing_ok=True)


def installer_gateway_history(priors, destination, wix='wix', *, environment=None):
    """Producer-only inputs: exact admitted receipt hash and predecessor product.

    No runtime pathname becomes authority. The current signed Panel carries the
    extracted pins; absent explicit qualified predecessors the list stays empty.
    """
    import re
    import windows_signing
    if len(priors) > 8:
        raise ValueError('at most eight admitted predecessor bundles')
    pins, seen = [], set()
    for index, (receipt_name, expected_receipt, product) in enumerate(priors):
        receipt = Path(receipt_name).resolve()
        if not re.fullmatch('[0-9a-f]{64}', expected_receipt) or not re.fullmatch(r'\{[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}\}', product) or product in seen:
            raise ValueError('explicit predecessor receipt/product authority is invalid')
        body = receipt.read_bytes()
        if len(body) > 1 << 20 or hashlib.sha256(body).hexdigest() != expected_receipt:
            raise ValueError('prior bundle receipt differs from admitted hash')
        prior = json.loads(body)
        core = [row for row in prior['chain'] if row['id'] == 'OpenAbstractions']
        if len(core) != 1:
            raise ValueError('prior bundle needs one core MSI')
        for pin in (prior['bundle'], core[0]):
            if Path(pin['name']).name != pin['name'] or '/' in pin['name'] or '\\' in pin['name']:
                raise ValueError('prior bundle member must be a sibling leaf')
            member = receipt.parent / pin['name']
            if member.is_symlink() or member.is_junction() or not member.is_file():
                raise ValueError('prior bundle member is missing or linked')
            data = member.read_bytes()
            if len(data) != pin['bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256']:
                raise ValueError('prior bundle member differs from its admitted receipt')
        extracted = destination / ('prior-' + str(index))
        extracted.mkdir()
        subprocess.run([wix, 'msi', 'decompile', str(receipt.parent / core[0]['name']),
                        '-x', str(extracted / 'files'), '-o', str(extracted / 'package.wxs')], check=True,
                       **({'env':environment} if environment is not None else {}))
        actual, _, _, tree = windows_signing.msi_member_readback(extracted)
        package = next(node for node in tree.iter() if node.tag.rsplit('}', 1)[-1] == 'Package')
        if package.get('ProductCode') != product:
            raise ValueError('prior MSI ProductCode differs from admitted predecessor')
        gateways = [row for row in actual['files'] if row['path'].endswith('/OpenAbstractions/tools/openabstractions-mcp.exe')]
        if len(gateways) != 1:
            raise ValueError('prior core needs one installed gateway identity')
        gateway = gateways[0]
        pins.append(dict(product_code=product, msi_sha256=core[0]['sha256'], receipt_sha256=expected_receipt,
                         bundle_sha256=prior['bundle']['sha256'], gateway_id=gateway['id'], gateway_path=gateway['path'],
                         gateway_sha256=gateway['sha256'], gateway_bytes=gateway['bytes']))
        seen.add(product)
    return json.dumps(dict(schema=1, predecessors=pins), sort_keys=True, separators=(',', ':')).encode()


@contextmanager
def installer_history_object(source, out, arch, environment, priors, wix='wix'):
    if not priors:
        yield
        return
    source = source.resolve()
    compiler = source / 'monitor/icon/gen'
    if not compiler.is_dir():
        compiler = source / 'tools/windows-resource-gen'
    panel = source / 'monitor'
    object_path = panel / 'internal/panelres' / ('rsrc_windows_' + GOARCH[arch] + '.syso')
    if not panel.is_dir() or object_path.is_symlink() or not object_path.is_file():
        raise ValueError('installer history needs the existing Panel resource object')
    original = object_path.read_bytes()
    composed = None
    try:
        with tempfile.TemporaryDirectory(prefix='oa-installer-history-', dir=out) as temporary:
            folder = Path(temporary).resolve()
            body = installer_gateway_history(priors, folder, wix)
            payload = folder / 'history.json'
            payload.write_bytes(body)
            output = folder / ('rsrc_windows_' + GOARCH[arch] + '.syso')
            go = str(Path(environment['GOROOT']) / 'bin/go.exe') if 'GOROOT' in environment else 'go'
            host = resource_host_environment(environment)
            subprocess.run([go, 'run', *[str(compiler / name) for name in ('main.go', 'native.go', 'agent_release.go')],
                            '-installer-history-json', str(payload), '-agent-release-object', str(output),
                            '-agent-release-arch', GOARCH[arch], '-installer-history-panel-dir', str(panel)], check=True, env=host)
            composed = output.read_bytes()
            shutil.copyfile(output, object_path)
            yield
    finally:
        if composed is not None:
            if object_path.read_bytes() != composed:
                raise ValueError('Panel resource changed outside its producer')
            object_path.write_bytes(original)


def stage(src, out, arch, binaries=None, agent_channel=None, agent_version=None, installer_priors=(), wix='wix',
          program_proof=None, local_packages=None):
    # A private preview passes its package folder as an argument; an
    # environment variable must never reach a release Panel.
    if 'OA_LOCAL_PACKAGE_FOLDER' in os.environ:
        raise ValueError('OA_LOCAL_PACKAGE_FOLDER is set; only a private preview links a package folder, by argument')
    package_flags = local_package_flags(local_packages)
    release_metadata = agent_release_inputs(agent_channel, agent_version)
    panel_appmodel_input(src, arch, binaries)
    go_env = None
    sdk = receipt = None
    pytorch_program = prebuilt(binaries, "gobuild", "tools/pytorchd.exe") is not None or "pytorchimage" in src
    host_program = prebuilt(binaries, "gobuild", "tools/modelhostd.exe") is not None or "modelhost" in src
    engine_root = src.get("modelhostengine")
    engine_bundle = engine_root / MODELHOST_ENGINE_NAME if engine_root else None
    engine_receipt = engine_root / MODELHOST_RECEIPT_NAME if engine_root else None
    engine_pin = engine_root / "pin.json" if engine_root else None
    has_engine = (engine_bundle is not None and engine_bundle.is_file()
                  and engine_receipt.is_file() and engine_pin.is_file())
    if arch == "x64":
        if host_program != has_engine:
            raise ValueError("x64 ModelHost requires modelhostd and the exact reviewed reduced b10825 bundle together")
        if has_engine:
            verify_bundle(engine_bundle, engine_receipt, modelhost_pin(engine_pin))
            notice = HERE / "engines/BoringSSL-LICENSE.txt"
            notice_bytes = notice.read_bytes()
            notice_hash = hashlib.sha256(notice_bytes).hexdigest()
            if notice_hash != BORINGSSL_NOTICE_SHA256:
                raise ValueError("source checkout ModelHost BoringSSL notice differs from reviewed text: "
                                 f"sha256={notice_hash} bytes={len(notice_bytes)} "
                                 f"crlf={notice_bytes.count(bytes([13, 10]))} lf={notice_bytes.count(bytes([10]))}")
    dropped = []
    payload_rows = list(rows("payload.tsv"))
    if binaries is not None:
        runtime_names = [Path(row[1]).name for row in payload_rows
                         if row[2] == 'gobuild' and payload_program_role(row[3], row[4]) == 'runtime'
                         and prebuilt(binaries, row[2], row[1]) is not None]
        if runtime_names:
            if program_proof is None:
                raise ValueError('prebuilt runtime requires pinned admitted producer proof')
            expected_provider_names = {row[1].removeprefix('tools/') for row in payload_rows
                if row[2] == 'gobuild' and row[1].startswith('tools/') and row[1].endswith('.exe')
                and payload_program_role(row[3], row[4]) == 'provider'
                and included_payload(row[1], row[0], arch, pytorch_program, host_program)
                and prebuilt(binaries, row[2], row[1]) is not None}
            if set(program_proof['provider_images']) != expected_provider_names:
                raise ValueError('producer provider record differs from staged executable roster')
            proof_programs = [p for p in program_proof['programs'] if p['arch'] == arch]
            by_name = {Path(p['artifact']['path']).name: p for p in proof_programs}
            if len(by_name) != len(proof_programs):
                raise ValueError('duplicate producer program proof')
            images = shipped_provider_images(binaries, program_proof['provider_images'])
            if images != program_proof['provider_images']:
                raise ValueError('prebuilt providers differ from admitted final runtime record')
            for name in runtime_names:
                if name not in by_name:
                    raise ValueError('prebuilt runtime missing from admitted producer proof')
                pin = by_name[name]['artifact']
                if shipped_provider_images(binaries, [name])[name] != pin['sha256']:
                    raise ValueError('prebuilt runtime differs from admitted producer bytes')
                if by_name[name].get('provider_images') != images:
                    raise ValueError('prebuilt runtime lacks matching final provider compilation proof')
                verify_shipped_runtime_record(binaries / name, images)
    # Runtime links consume the final bytes of every included provider row.
    payload_rows.sort(key=lambda row: payload_program_role(row[3], row[4]) == 'runtime')
    provider_names = []
    for feature, path, kind, source, frm, _, subsystem in payload_rows:
        if not included_payload(path, feature, arch, pytorch_program, host_program):
            dropped.append(path)
            continue
        ready = prebuilt(binaries, kind, path)
        if ready is None and source not in src:
            dropped.append(path)
            continue
        dst = out / "payload" / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        if ready is not None:
            if installer_priors and path == 'tools/Abstraction Panel.exe':
                raise ValueError('installer predecessor pins must be linked by the Panel source producer before signing')
            if release_metadata and path == 'tools/openabstractions-mcp.exe':
                raise ValueError('agent release metadata must be embedded by the source producer before signing')
            shutil.copyfile(ready, dst)
        elif kind == "gobuild":
            if go_env is None:
                go_env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "windows",
                          "GOARCH": GOARCH[arch], "GOFLAGS": "-trimpath"}
                if os.name == "nt":
                    go_env, sdk, receipt = windows_go_environment(go_env)
            with agent_release_object(src[source], out, arch, go_env,
                                      agent_channel if path == 'tools/openabstractions-mcp.exe' else None,
                                      agent_version if path == 'tools/openabstractions-mcp.exe' else None), installer_history_object(
                                          src[source], out, arch, go_env, installer_priors if path == 'tools/Abstraction Panel.exe' else (), wix):
                flags = ldflags(subsystem)
                if path in GO_TAGS:
                    # The presenter runs Setup's sign-in duties too.
                    flags += package_flags
                runtime_images = None
                if payload_program_role(source, frm) == 'runtime':
                    runtime_images = shipped_provider_images(out / 'payload/tools', provider_names)
                    record = encode_shipped_provider_images(runtime_images)
                    if record:
                        flags += ' -X main.shippedProviderImages=' + record
                tags = ['-tags', GO_TAGS[path]] if path in GO_TAGS else []
                subprocess.run(
                    [str(Path(go_env["GOROOT"]) / "bin/go.exe") if sdk else "go", "build", *tags, "-ldflags", flags, "-o", str(dst), "."],
                    cwd=src[source] / frm, check=True,
                    env=go_env)
                if runtime_images is not None:
                    verify_shipped_runtime_record(dst, runtime_images)
        elif path == "tools/declarations/lemonade-image.json":
            declaration = json.loads((src[source] / frm).read_text(encoding='utf-8'))
            provider_source = src.get('lemonadeimage', LEMONADE_IMAGE_SOURCE)
            pins_path = provider_source / 'packaging/windows-amd64.json'
            if not pins_path.is_file():
                pins_path = HERE / 'lemonade-image-pin.json'
            pins = json.loads(pins_path.read_text(encoding='utf-8'))
            dst.write_text(json.dumps(lemonade_image_declaration(declaration, pins), indent=2) + '\n', encoding='utf-8')
        else:
            shutil.copyfile(src[source] / frm, dst)
        if (kind == 'gobuild' and path.startswith('tools/') and path.endswith('.exe')
                and payload_program_role(source, frm) == 'provider'):
            provider_names.append(path.removeprefix('tools/'))
    if sdk is not None:
        sdk.validate_sdk_receipt(receipt)
    if binaries is not None and program_proof is not None:
        staged_tools = out / 'payload/tools'
        if shipped_provider_images(staged_tools, provider_names) != program_proof['provider_images']:
            raise ValueError('staged providers changed from admitted runtime record')
        for name in runtime_names:
            if shipped_provider_images(staged_tools, [name])[name] != by_name[name]['artifact']['sha256']:
                raise ValueError('staged runtime changed from admitted producer bytes')
            verify_shipped_runtime_record(staged_tools / name, program_proof['provider_images'])
    return dropped


PREVIEW_STAGES = ('actions-native', 'appmodel-native', 'panel-resources', 'panel-resource-readback',
                  'npm', 'opencode-native', 'opencode-package', 'core', 'core-readback', 'bundle')
PREVIEW_SOURCE_CHECKS = ('installer.test_setup_runtime', 'installer.test_runtime_candidate',
                         'installer.test_upgrade_sequence', 'installer.test_upgrade_log')
PREVIEW_FILES = frozenset(('python', 'wix', 'bal', 'util', 'ui', 'actions_receipt', 'go_sdk', 'node',
    'npm', 'cl', 'rc', 'cvtres', 'link', 'vcvars', 'cmd', 'ipc', 'opencode_desktop', 'parser', 'claude_validator'))
PREVIEW_STAGE_SECONDS = 600
PREVIEW_CHECK_SECONDS = 240


def preview_system_cmd(root):
    """Resolve the OS command processor from the existing Windows directory owner."""
    from scripts.file_boundary import windows_build_environment
    windows = windows_build_environment(root)
    return Path(windows['SystemRoot'])/'System32/cmd.exe'


def preview_owner(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    return owner


def preview_pin(path):
    path = Path(path)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path), 'sha256': digest, 'bytes': path.stat().st_size}


def preview_catalog_packages(base, opencode, out, version):
    """Add the compiled per-user MSI to this preview's private Catalog pins."""
    from installer.apps.build_app import member_segments
    from scripts.file_boundary import ordinary_path

    manifest = json.loads((base/'adopter_assets.json').read_bytes())
    extensions = manifest.get('extensions', [])
    if (manifest.get('schema') != 2 or manifest.get('release_tag') != 'v'+version
            or any(row['id'] == 'opencode' for row in extensions)):
        raise ValueError('preview Catalog needs its original schema-2 package pins')
    app = json.loads((opencode/'bundle-app.json').read_bytes())
    readback = json.loads((opencode/'msi-readback.json').read_bytes())['package']
    leaf = 'opencode-'+version+'.msi'
    image = opencode/leaf
    if (app['id'] != 'opencode' or Path(app['file']) != image or readback['Scope'] != 'perUser'
            or readback['Version'] != version or not re.fullmatch(r'\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\}', readback['ProductCode'])):
        raise ValueError('preview Catalog needs the exact compiled OpenCode MSI identity')
    package = {'id':'opencode', 'file':leaf, 'version':version, 'product_code':readback['ProductCode'],
               'sha256':app['sha256'], 'bytes':app['bytes']}
    files = [(image, package)]
    for row in manifest['apps']:
        for role in ('binary', 'source'):
            if row.get(role+'_zip'):
                files.append((base/row[role+'_zip'], {'file':row[role+'_zip'],
                    'sha256':row[role+'_sha256'], 'bytes':row[role+'_bytes']}))
    files.extend((base/row['file'], row) for row in extensions)
    # The staged Catalog is consumed on Windows. Reserve its manifest and
    # reject names that would collide there even on a case-sensitive host.
    names = {PureWindowsPath('adopter_assets.json')}
    for source, row in files:
        name = row['file']
        key = PureWindowsPath(name)
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or key in names:
            raise ValueError('preview Catalog package filename is unsafe or duplicated')
        member_segments(name)
        names.add(key)
        try:
            ordinary_path(source, kind='file')
        except (OSError, ValueError) as error:
            raise ValueError('preview Catalog package is missing or redirected: '+name) from error
        actual = preview_pin(source)
        if any(actual[key] != row[key] for key in ('bytes', 'sha256')):
            raise ValueError('preview Catalog package differs from its producer: '+name)
    out.mkdir()
    for source, row in files:
        target = out/row['file']
        with source.open('rb') as original, target.open('xb') as staged:
            shutil.copyfileobj(original, staged)
        actual = preview_pin(target)
        if any(actual[key] != row[key] for key in ('bytes', 'sha256')):
            raise ValueError('preview Catalog copy differs from its producer: '+row['file'])

    # Windows Installer retains PackageCode even when its cache changes the
    # container bytes. Read it from the private, verified Catalog copy.
    staged_image = out/leaf
    reader = preview_owner(HERE/'windows_signing.py', 'oa_preview_msi_identity')
    before = preview_pin(ordinary_path(staged_image, kind='file'))
    if any(before[key] != package[key] for key in ('bytes', 'sha256')):
        raise ValueError('preview Catalog OpenCode MSI copy changed before identity read')
    identity = reader.msi_catalogue_identity(staged_image)
    if preview_pin(ordinary_path(staged_image, kind='file')) != before:
        raise ValueError('preview Catalog OpenCode MSI copy changed during identity read')
    if identity['version'] != version or identity['product_code'] != package['product_code']:
        raise ValueError('preview Catalog OpenCode MSI identity differs from its producer')
    package['package_code'] = identity['package_code']
    manifest['extensions'] = [*extensions, package]
    with (out/'adopter_assets.json').open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(manifest, indent=2)+'\n')


def preview_git(root, *arguments):
    owner = preview_owner(root/'scripts/git_env.py', 'oa_preview_git_environment')
    result = subprocess.run(['git', *arguments], cwd=root, env=owner.clean_git_environment(), text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode and not (arguments[:2] == ('symbolic-ref','-q') and result.returncode == 1):
        raise ValueError('preview Git admission failed: '+result.stderr.strip())
    return result.stdout.rstrip('\r\n')


def preview_generated(root):
    """The existing Panel generator's fixed source outputs, restored by this owner."""
    paths = [root/'monitor'/name for name in ('panel.rc', 'presenter.rc', 'panel-application.json', 'internal/panelres/rsrc_windows_amd64.syso')]
    paths += [root/member for member in preview_git(root, 'ls-files', '--', 'monitor/static/native-sdk').splitlines()]
    return paths


def preview_source(root, source, *, generated=False):
    from scripts.file_boundary import relative_beneath_missing
    if preview_git(root, 'rev-parse', 'HEAD') != source:
        raise ValueError('preview HEAD differs from the exact source')
    if preview_git(root, 'symbolic-ref', '-q', 'HEAD'):
        raise ValueError('preview requires a detached worktree')
    changed = preview_git(root, 'status', '--porcelain', '--untracked-files=all')
    if changed:
        allowed = {relative_beneath_missing(path,root).as_posix() for path in preview_generated(root)} if generated else set()
        if any(line[3:].replace('\\','/') not in allowed for line in changed.splitlines()):
            raise ValueError('preview requires a clean source snapshot')


def preview_inputs(path, root, *, generated=False):
    """Admit the entire local batch before any producer or output-directory effect."""
    import re
    sys.path.insert(0, str(root))
    from release.testing.windows_lifetime import _plain
    from scripts.file_boundary import relative_beneath_missing, same_existing_file
    plain_path = lambda value:_plain(Path(value))
    raw = plain_path(path).read_bytes()
    if len(raw) > 1 << 20:raise ValueError('preview spec exceeds 1MiB')
    data = json.loads(raw)
    if (not isinstance(data, dict) or set(data) - {'local_packages'} != {'preview', 'source_sha', 'version', 'arch', 'output',
            'inputs', 'directories', 'priors', 'go_cache'} or data['preview'] != {'kind':'private-unqualified'}
            or not re.fullmatch('[0-9a-f]{40}', str(data['source_sha']))
            or not re.fullmatch(r'\d+\.\d+\.\d+', str(data['version'])) or data['arch'] != 'x64'):
        raise ValueError('preview needs the private-unqualified spec, exact source/version and supported x64 architecture')
    preview_source(root, data['source_sha'], generated=generated)
    output = Path(data['output'])
    common = Path(preview_git(root, 'rev-parse', '--path-format=absolute', '--git-common-dir')).parent
    boundary = common/'.forks/evidence'
    if not output.is_absolute() or not relative_beneath_missing(output,boundary).parts:
        raise ValueError('preview output must be under the shared .forks/evidence task root')
    plain_path(output)
    if 'claude_validator' not in data['inputs']:
        raise ValueError('preview requires a pinned claude_validator for canonical Claude Mod validation before packaging')
    if set(data['inputs']) != PREVIEW_FILES or set(data['directories']) != {'node_sdk','dependency_cache','modelhostengine'}:
        raise ValueError('preview input roles differ from the existing Windows producers')
    pins, errors = {}, []
    def admit(row, role=None):
        try:
            if (not isinstance(row, dict) or set(row) != {'path','sha256','bytes'} or not Path(row['path']).is_absolute()
                    or not re.fullmatch('[0-9a-f]{64}', str(row['sha256'])) or type(row['bytes']) is not int):
                raise ValueError('preview file needs absolute path, SHA256 and bytes')
            file = plain_path(row['path'])
            actual = preview_pin(file)
            if role == 'cmd':
                if not same_existing_file(file,preview_system_cmd(root)):
                    raise ValueError('preview cmd must be the actual Windows System32 command processor')
            elif file.stat().st_nlink != 1:
                raise ValueError('preview input is multiply linked: '+str(file))
            if any(actual[key] != row[key] for key in ('sha256','bytes')):
                raise ValueError('preview input changed: '+str(file))
            pins[str(file)] = row['sha256']
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(str(error))
    for role,row in data['inputs'].items():admit(row,role)
    qualifier = preview_owner(root/'scripts/stage_qualify.py','oa_preview_directory_owner')
    for row in data['directories'].values():
        try:
            if (set(row) != {'path','sha256'} or not Path(row['path']).is_absolute()
                    or not re.fullmatch('[0-9a-f]{64}',str(row['sha256']))
                    or qualifier.directory_digest(plain_path(row['path'])) != row['sha256']):
                raise ValueError('preview directory input changed')
            for directory, dirs, files in os.walk(row['path'],followlinks=False):
                for name in dirs+files:
                    member = plain_path(Path(directory)/name)
                    if member.is_file() and member.stat().st_nlink != 1:
                        raise ValueError('preview directory contains a multiply linked file')
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(str(error))
    priors = data['priors']
    if not isinstance(priors,list) or not 1 <= len(priors) <= 8:
        errors.append('preview P1 requires one to eight authenticated predecessor triples')
        priors = []
    seen = set()
    for triple in priors:
        try:
            if (not isinstance(triple,list) or len(triple) != 3 or not Path(triple[0]).is_absolute()
                    or not re.fullmatch('[0-9a-f]{64}',str(triple[1]))
                    or not re.fullmatch(r'\{[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}\}',str(triple[2])) or triple[2] in seen):
                raise ValueError('preview predecessor triple is invalid or duplicated')
            seen.add(triple[2])
            receipt = plain_path(triple[0]); pin = preview_pin(receipt)
            if pin['sha256'] != triple[1] or pin['bytes'] > 1 << 20:
                raise ValueError('preview prior receipt differs from its admitted SHA256')
            admit(pin)
            prior = json.loads(receipt.read_bytes())
            core = [row for row in prior['chain'] if row['id'] == 'OpenAbstractions']
            if len(core) != 1:raise ValueError('preview prior receipt needs exactly one core MSI')
            for row in (prior['bundle'], core[0]):
                if Path(row['name']).name != row['name'] or '/' in row['name'] or '\\' in row['name']:
                    raise ValueError('preview prior package must be a sibling leaf')
                admit({'path':str(receipt.parent/row['name']),'sha256':row['sha256'],'bytes':row['bytes']})
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(str(error))
    if not Path(data['go_cache']).is_absolute():errors.append('preview Go cache must be absolute')
    # Setup installs pinned release assets found in this folder (ComfyUI and
    # the PyTorch component before publication); see setup.LocalPackageFolder.
    packages = data.get('local_packages')
    if packages is not None and (not isinstance(packages, str) or not Path(packages).is_absolute()
                                 or not Path(packages).is_dir() or "'" in packages):
        errors.append('preview local_packages must name an existing absolute folder')
    elif packages is not None:
        try:
            manifest = plain_path(Path(packages)/'adopter_assets.json')
            admit(preview_pin(manifest))
        except (OSError, ValueError) as error:
            errors.append(str(error))
    if errors:raise ValueError('preview prerequisites: '+'; '.join(dict.fromkeys(errors)))
    if not same_existing_file(data['inputs']['python']['path'],sys.executable):
        raise ValueError('preview Python must be the selected frontcontroller interpreter')
    pins[str(Path(path).resolve())] = preview_pin(Path(path).resolve())['sha256']
    return data, pins


def preview_build_environment(base, directory):
    """Use the existing Windows build environment with task-owned profile/cache paths."""
    from scripts.file_boundary import windows_build_environment
    from release.testing.windows_lifetime import _plain
    directory = _plain(Path(directory))
    folders = {name:directory/name for name in ('temp','profile','appdata','localappdata','npm-cache','dotnet-home','bun-cache')}
    for folder in folders.values():_plain(folder).mkdir(parents=True,exist_ok=True)
    # Shell known folders expand %USERPROFILE%\AppData\*; MSBuild's FileTracker
    # throws IndexOutOfRangeException when Local AppData resolves to a missing folder.
    for name in ('Local','LocalLow','Roaming'):_plain(folders['profile']/'AppData'/name).mkdir(parents=True,exist_ok=True)
    controlled = {'TEMP','TMP','USERPROFILE','HOME','HOMEDRIVE','HOMEPATH','APPDATA','LOCALAPPDATA',
                  'XDG_CACHE_HOME','XDG_CONFIG_HOME','DOTNET_CLI_HOME','NODE_OPTIONS','NODE_PATH',
                  'TEST_TELEMETRY_DIR','GO_TELEMETRY_CHILD','GO_TELEMETRY_CHILD_UPLOAD'}
    owned = windows_build_environment(folders['temp'])
    owned_keys = {key.upper() for key in owned}
    env = {key:value for key,value in base.items() if key.upper() not in controlled|owned_keys
           and not key.upper().startswith(('NPM_CONFIG_','BUN_'))}
    env.update(owned,PATH=base['PATH'])
    env.update(USERPROFILE=str(folders['profile']),HOME=str(folders['profile']),APPDATA=str(folders['appdata']),
        LOCALAPPDATA=str(folders['localappdata']),DOTNET_CLI_HOME=str(folders['dotnet-home']),
        NPM_CONFIG_CACHE=str(folders['npm-cache']),BUN_INSTALL_CACHE_DIR=str(folders['bun-cache']))
    env.update(HOMEDRIVE=folders['profile'].drive,HOMEPATH=str(folders['profile'])[len(folders['profile'].drive):],
               XDG_CACHE_HOME=str(folders['localappdata']),XDG_CONFIG_HOME=str(folders['appdata']))
    for name in ('USERCONFIG','GLOBALCONFIG'):
        path = directory/('npm-'+name.lower())
        _plain(path)
        if not path.exists():path.write_text('',encoding='utf-8')
        if path.stat().st_nlink != 1 or path.read_bytes():raise ValueError('private preview npm configuration changed')
        env['NPM_CONFIG_'+name] = str(path)
    return env


def preview_go_telemetry_off(go, env):
    # The pinned Go command skips counters and the detached telemetry child for this invocation.
    # Run it before any other Go command uses the owned profile.
    subprocess.run([str(go),'telemetry','off'],cwd=env['USERPROFILE'],env=env,check=True,timeout=10,
                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)


def preview_node_version(node, env):
    # check_output's finite timeout kills and joins the metadata child before raising.
    return subprocess.check_output([str(node),'--version'],env=env,text=True,timeout=10).strip().lstrip('v')


def preview_environment(data, root):
    from scripts.file_boundary import same_existing_file
    """Select the admitted SDK and native owner's effective race profile once."""
    sys.path.insert(0,str(root))
    from scripts.windows_go_sdk import sdk_environment, validate_sdk_receipt
    inputs = data['inputs']
    env = {key:value for key,value in os.environ.items() if key.upper() not in
        {'GOROOT','GOWORK','GOENV','GOFLAGS','CGO_ENABLED','GOOS','GOARCH','CC','CXX','GOBIN','PYTHONPATH'}}
    env.update(GOWORK=str(root/'go.work'),GOPROXY='off',GOSUMDB='off',GOMAXPROCS='2',GOMEMLIMIT='2GiB',
        GOCACHE=data['go_cache'],PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(root))
    receipt = validate_sdk_receipt(json.loads(Path(inputs['go_sdk']['path']).read_bytes()))
    env = sdk_environment(receipt,env)
    native = preview_owner(root/'scripts/build_node_addon.py','oa_preview_native_owner')
    # Metadata uses an owned temporary profile before the output root exists.
    temporary = root/'.forks';temporary.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='installer-preview-preflight-',dir=temporary) as folder:
        metadata_env = preview_build_environment(env,Path(folder))
        preview_go_telemetry_off(receipt['go'],metadata_env)
        env, go_pins = native.appmodel_go_environment(metadata_env)
        node = Path(inputs['node']['path'])
        version = preview_node_version(node,env)
        sdk = native.node_sdk(Path(data['directories']['node_sdk']['path']),version)
        if sdk is None:raise ValueError('preview selected Node SDK does not match the selected Node')
        go_pins.update(native.appmodel_inputs(node,sdk))
    expected = native.appmodel_tools()
    for role, selected in (('cl','compiler'),('vcvars','vcvars'),('cmd','cmd')):
        if not same_existing_file(inputs[role]['path'],expected[selected]):
            raise ValueError('preview selected tool differs from existing native owner: '+role)
    env['PATH'] = os.pathsep.join(dict.fromkeys(str(Path(inputs[key]['path']).parent) for key in ('node','npm','wix','cl','rc','cvtres','link'))) + os.pathsep + env['PATH']
    return env, {**go_pins,str(Path(receipt['go'])):preview_pin(receipt['go'])['sha256']}


def preview_appmodel(root, data):
    """The unchanged AppModel owner admits only this checkout's .build placement."""
    identity = hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()[:20]
    return root/'.build'/('installer-preview-'+identity)/'build'


def preview_publish(path, data):
    """The final atomic bundle receipt publication is the last fallible effect."""
    temporary = path.with_name(path.name+'.preview-complete.tmp')
    created = False
    try:
        with temporary.open('x',encoding='utf-8') as stream:
            created = True
            stream.write(json.dumps(data,indent=2));stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    except BaseException:
        if created:
            try:temporary.unlink(missing_ok=True)
            except OSError:pass
        raise


def preview_go_dependency_inputs(raw, env):
    from scripts.file_boundary import relative_beneath_existing
    """Pin the selected test's effective files; the admitted SDK owns stdlib bytes."""
    decoder = json.JSONDecoder(); position = 0; pins = {}
    while position < len(raw):
        while position < len(raw) and raw[position].isspace():position += 1
        if position == len(raw):break
        package,position = decoder.raw_decode(raw,position)
        if package.get('Error') or package.get('DepsErrors'):raise ValueError('Claude validator dependency discovery failed')
        directory = Path(package['Dir'])
        if package.get('Standard'):
            relative_beneath_existing(directory,env['GOROOT'])
            continue
        paths = []
        for field in ('GoFiles','CgoFiles','CFiles','CXXFiles','HFiles','SFiles','SysoFiles','EmbedFiles'):
            paths += [directory/name for name in package.get(field,[])]
        module = package.get('Module',{})
        if module.get('GoMod'):
            mod = Path(module['GoMod']);paths.append(mod)
            if mod.with_name('go.sum').is_file():paths.append(mod.with_name('go.sum'))
        for path in paths:pins[str(path)] = preview_pin(path)['sha256']
    if not pins:raise ValueError('Claude validator dependency discovery returned no source inputs')
    return pins


def preview_run(data, root, spec_path, pins, env, *, run_source=None, validation_pins=None):
    """One tracked, ordered composition; each stage has the existing native lifetime."""
    if run_source is None:
        sys.path.insert(0,str(root))
        from release.testing.source_check import run_source_check
        run_source = run_source_check
    output = Path(data['output'])
    binding = {'spec':preview_pin(spec_path),'source_sha':data['source_sha'],'input_pins':pins}
    marker = output/'preview-receipt.json'
    if output.exists():
        if not marker.is_file() or json.loads(marker.read_bytes()).get('binding') != binding:
            raise ValueError('existing preview output has different input pins; preserve it and choose a new task output')
        raise ValueError('preview output is retained; choose a new task output for another build')
    output.mkdir(parents=True)
    env = preview_build_environment(env,output/'build-environment')
    result = {'binding':binding,'preview':{'kind':'private-unqualified','status':'running',
        'source_sha':data['source_sha'],'arch':data['arch'],'priors':data['priors'],
        'signed':False,'qualified':False,'stage_receipts':[],'appmodel_build':str(preview_appmodel(root,data)),
        'stage_budget_seconds':PREVIEW_STAGE_SECONDS,
        'stage_budget_basis':f'ten producer stages at {PREVIEW_STAGE_SECONDS}s each, plus source-checks and normal-validator at {PREVIEW_CHECK_SECONDS}s each and Claude dependency discovery/validation at {PREVIEW_CHECK_SECONDS}s each; finite producer ceiling unmeasured',
        'prior_qualification':'not established; explicit receipt/package pins and MSI ProductCode are checked'}}
    def save():marker.write_text(json.dumps(result,indent=2),encoding='utf-8')
    originals = {path:path.read_bytes() if path.exists() else None for path in preview_generated(root)}
    save()
    try:
        python = data['inputs']['python']['path']
        phases = [('source-checks',[python,'-B','-m','unittest',*PREVIEW_SOURCE_CHECKS],PREVIEW_CHECK_SECONDS)]
        go = str(Path(env['GOROOT'])/'bin/go.exe')
        preview_go_telemetry_off(go,env)
        phases.append(('claude-mod-dependencies',[go,'-C','mcp-gateway','list','-deps','-test','-json','./cacheproducer'],PREVIEW_CHECK_SECONDS))
        phases.append(('claude-mod-validation',[go,'-C','mcp-gateway',
            'test','-v','-trimpath','-count=1','-timeout=240s','-run','^TestClaudePluginCacheNativeManifest$','./cacheproducer'],PREVIEW_CHECK_SECONDS))
        phases += [(name,[python,'-B',str(root/'installer/build.py'),'preview',str(spec_path),'--stage',name],
                    PREVIEW_STAGE_SECONDS) for name in PREVIEW_STAGES]
        phases.append(('normal-validator',[python,'-B',str(root/'installer/validate.py'),
                       '--wix',data['inputs']['wix']['path'],str(output/'bundle/abstraction-x64.msi')],PREVIEW_CHECK_SECONDS))
        for name, argv, seconds in phases:
            log, receipt = output/(name+'.log'), output/(name+'.jsonl')
            selected_env = env
            if name == 'source-checks':
                selected_env = dict(env,PYTHONPATH=os.pathsep.join(str(path) for path in (root,root/'scripts',root/'installer')))
            elif name == 'claude-mod-validation':
                selected_env = dict(env,OA_CLAUDE_CACHE_VALIDATION_CLI=data['inputs']['claude_validator']['path'],
                    OA_CLAUDE_CACHE_VALIDATION_SHA256=data['inputs']['claude_validator']['sha256'],
                    OA_CLAUDE_CACHE_VALIDATION_REQUIRED='1',OA_CLAUDE_CACHE_VALIDATE_ONLY='1',GOWORK=str(root/'go.work'))
            print('Preview stage: '+name,flush=True)
            go_phase = name in ('claude-mod-dependencies','claude-mod-validation')
            selected_pins = validation_pins if go_phase and validation_pins is not None else pins
            if name in ('core','bundle') and data.get('local_packages'):
                assets = output/'catalog-packages/adopter_assets.json'
                selected_pins = {**selected_pins, str(assets):preview_pin(assets)['sha256']}
            roster = [{'path':path,'sha256':digest,'bytes':Path(path).stat().st_size} for path,digest in selected_pins.items()]
            if len(selected_pins) > 1024 or len(json.dumps(roster).encode()) > 220 << 10:
                raise ValueError('preview selected input roster exceeds the existing finite source receipt bound')
            native = run_source(argv,cwd=root,env=selected_env,log=log,receipt=receipt,inputs=selected_pins,
                work_seconds=seconds,log_bytes=32<<20,input_bytes=1<<30,go_source=go_phase)
            result['preview']['stage_receipts'].append({'name':name,'sha256':preview_pin(receipt)['sha256']})
            save()
            if (native.get('state') != 'COMPLETE' or not native.get('accepted') or native.get('exit_code') != 0 or not native.get('inputs_unchanged')
                    or not native.get('join',{}).get('quiescent') or not native.get('owned_handles',{}).get('handles_closed')):
                raise ValueError('preview stage failed: '+name+'; retained '+str(receipt))
            if name == 'claude-mod-validation' and re.search(
                    r'^--- PASS: TestClaudePluginCacheNativeManifest(?:\s|$)', log.read_text(encoding='utf-8'), re.MULTILINE) is None:
                raise ValueError('Claude Mod validation did not report the required native test PASS; retained '+str(log))
            if name == 'claude-mod-dependencies':
                validation_pins = {**selected_pins,**preview_go_dependency_inputs(log.read_text(encoding='utf-8'),env)}
            preview_inputs(spec_path,root,generated=True)
    except BaseException:
        result['preview']['status'] = 'failed'
        raise
    finally:
        try:
            for path, body in originals.items():
                if body is None:path.unlink(missing_ok=True)
                else:path.write_bytes(body)
        except BaseException:
            result['preview']['status'] = 'failed'
            raise
        finally:save()
    try:
        preview_source(root,data['source_sha'])
        bundle_receipt = output/'bundle/bundle-receipt.json'
        bundled = json.loads(bundle_receipt.read_bytes())
        if bundled['bundle'].get('signed') is not False:
            raise ValueError('private preview bundle is signed')
        (output/'bundle/UNQUALIFIED.txt').write_text('Private unsigned development preview. Release qualification and installed acceptance are absent.\n',encoding='utf-8')
        # This marker records stage progress. Only the final bundle receipt
        # below can publish complete-local-preview, after every prerequisite.
        result['preview']['status'] = 'stages-complete'
        result['result_receipt'] = str(bundle_receipt)
        save()
        result['preview']['status'] = 'complete-local-preview'
        bundled['preview'] = result['preview']
        preview_publish(bundle_receipt,bundled)
    except BaseException:
        result['preview']['status'] = 'failed'
        try:save()
        except OSError:pass
        raise
    return result


def preview_main(arguments):
    parser = argparse.ArgumentParser(description='Build one private unsigned, UNQUALIFIED Windows Setup through the existing bounded source owner.',
        epilog='Spec: preview={"kind":"private-unqualified"}; source_sha, version, arch="x64", output (fresh .forks/evidence/<task>/build), go_cache; '
        'inputs maps each of '+', '.join(sorted(PREVIEW_FILES))+' to {path,sha256,bytes}; '
        'directories maps node_sdk,dependency_cache,bootstrap,modelhostengine to {path,sha256} using stage_qualify.directory_digest; '
        'priors is an ordered nonempty list of [receipt-path,receipt-sha256,ProductCode]. '
        f'Ten producer stages have {PREVIEW_STAGE_SECONDS}s each; source-checks and normal-validator have {PREVIEW_CHECK_SECONDS}s each. '
        f'Claude-mod-validation has {PREVIEW_CHECK_SECONDS}s before producers and requires the pinned claude_validator; '
        f'its selected Go dependency discovery has a separate {PREVIEW_CHECK_SECONDS}s bound. '
        'it runs the existing canonical native manifest fixture in validate-only mode with disposable configuration. '
        'The finite producer ceiling is unmeasured until a tracked build supplies timings. '
        'Source-checks runs PREVIEW_SOURCE_CHECKS before compilers: '+', '.join(PREVIEW_SOURCE_CHECKS)+'. '
        'The normal bundle MSI validator runs before completion. '
        'Prior release qualification is not established here; explicit receipt/package pins and ProductCodes are verified. '
        'No signing, installation, CI, publication or release qualification is performed. Failed outputs are retained; another build needs a fresh output root.')
    parser.add_argument('spec',type=Path,help='Exact private-unqualified JSON: source_sha, version, x64 arch, output under .forks/evidence, pinned input files/directories, go_cache and ordered nonempty priors')
    parser.add_argument('--stage',choices=PREVIEW_STAGES,help=argparse.SUPPRESS)
    args = parser.parse_args(arguments)
    root = HERE.parent
    try:
        data,pins = preview_inputs(args.spec.resolve(),root,generated=args.stage is not None)
        env,tool_pins = preview_environment(data,root)
        pins.update(tool_pins)
        validation_pins = {str(Path(data['inputs'][role]['path'])):data['inputs'][role]['sha256']
            for role in ('claude_validator','go_sdk')}
        validation_pins[str(args.spec.resolve())] = preview_pin(args.spec.resolve())['sha256']
        if 'GOROOT' in env:
            go = Path(env['GOROOT'])/'bin/go.exe'
            validation_pins[str(go)] = pins[str(go)]
            for name in ('compile','link','asm'):
                tool = Path(env['GOROOT'])/'pkg/tool/windows_amd64'/(name+'.exe')
                if tool.is_file():validation_pins[str(tool)] = preview_pin(tool)['sha256']
        compiler_owner = preview_owner(root/'scripts/build_node_addon.py','oa_preview_compiler_owner') if any(env.get(key) for key in ('CC','CXX')) else None
        for key in ('CC','CXX'):
            if env.get(key):
                fields,_ = compiler_owner.appmodel_cc_fields(env[key])
                found = fields[0] if Path(fields[0]).is_absolute() else shutil.which(fields[0],path=env.get('PATH'))
                if found is None:raise ValueError('selected Go '+key+' executable is unavailable')
                tool = Path(found)
                validation_pins[str(tool)] = preview_pin(tool)['sha256']
        generated = set(preview_generated(root))
        for member in preview_git(root,'ls-files','--','installer','mcp-gateway/go.mod','mcp-gateway/go.sum','monitor/icon/gen','scripts/build_node_addon.py',
                'scripts/npm_packages.py','scripts/windows_native.py','scripts/git_env.py','scripts/stage_qualify.py',
                'scripts/file_boundary.py','scripts/windows_go_sdk.py','release/testing','adopters/opencode/installer',
                'research/ci76/redist-candidate.yml','research/ci76/redist-service-check.yml',
                'scripts/train/steps/run_linux_installed_lifecycle.py',
                'go.work','go.work.sum','LICENSE').splitlines():
            path = root/member
            if path.is_file() and path not in generated:
                digest = preview_pin(path)['sha256']
                if member.startswith(('mcp-gateway/','release/testing/')) or member in ('installer/build.py','go.work','go.work.sum','scripts/windows_go_sdk.py','scripts/file_boundary.py'):
                    validation_pins[str(path)] = digest
                if not member.startswith('mcp-gateway/'):pins[str(path)] = digest
        for selected in (pins,validation_pins):
            roster = [{'path':path,'sha256':value,'bytes':Path(path).stat().st_size} for path,value in selected.items()]
            if any(row['bytes'] > 1 << 30 for row in roster) or len(json.dumps(roster).encode()) > 220 << 10:
                raise ValueError('preview selected input roster exceeds the existing finite source receipt bound')
        if args.stage is not None:
            return preview_stage(args.stage,data,root,env)
        preview_run(data,root,args.spec.resolve(),pins,env,validation_pins=validation_pins)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('FAIL preview: '+str(error),file=sys.stderr)
        return 1


def preview_resource(image, name, kind=10):
    """Read a resource through a data-only mapping; never execute a product image."""
    import ctypes
    k = ctypes.WinDLL('kernel32',use_last_error=True)
    k.LoadLibraryExW.argtypes=[ctypes.c_wchar_p,ctypes.c_void_p,ctypes.c_uint32];k.LoadLibraryExW.restype=ctypes.c_void_p
    k.FindResourceExW.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint16];k.FindResourceExW.restype=ctypes.c_void_p
    k.SizeofResource.argtypes=[ctypes.c_void_p,ctypes.c_void_p];k.SizeofResource.restype=ctypes.c_uint32
    k.LoadResource.argtypes=[ctypes.c_void_p,ctypes.c_void_p];k.LoadResource.restype=ctypes.c_void_p
    k.LockResource.argtypes=[ctypes.c_void_p];k.LockResource.restype=ctypes.c_void_p
    k.FreeLibrary.argtypes=[ctypes.c_void_p];k.FreeLibrary.restype=ctypes.c_int
    handle = k.LoadLibraryExW(str(image),None,0x20|2)
    if not handle:raise ValueError('preview data-only resource mapping failed')
    try:
        named = ctypes.c_wchar_p(name) if isinstance(name,str) else ctypes.c_void_p(name)
        resource = k.FindResourceExW(handle,ctypes.c_void_p(kind),ctypes.cast(named,ctypes.c_void_p),0)
        if not resource:raise ValueError('preview resource is absent: '+str(name))
        size = k.SizeofResource(handle,resource)
        if not 0 < size <= 1 << 20:raise ValueError('preview resource is unbounded')
        address = k.LockResource(k.LoadResource(handle,resource))
        if not address:raise ValueError('preview resource read failed')
        return ctypes.string_at(address,size)
    finally:
        if not k.FreeLibrary(handle):raise ValueError('preview data-only resource handle did not close')


def preview_history_readback(image, expected, priors):
    actual = preview_resource(image,'OA_INSTALLER_GATEWAY_HISTORY')
    if actual != expected:
        raise ValueError('preview Panel RCDATA differs from its authenticated ordered predecessor data')
    pins = json.loads(actual)['predecessors']
    if [(row['receipt_sha256'],row['product_code']) for row in pins] != [(row[1],row[2]) for row in priors]:
        raise ValueError('preview Panel predecessor order differs from the spec')
    return hashlib.sha256(actual).hexdigest()


def preview_capture_vcvars(root, vcvars, env):
    # Match build_node_addon.under_vcvars: quoted CALL text belongs in an
    # owned batch file, while cmd receives only the batch filename as argv.
    with tempfile.TemporaryDirectory(prefix='preview-vcvars-',dir=env['TEMP']) as directory:
        batch = Path(directory)/'environment.cmd'
        batch.write_text('@echo off\r\nset "ERRORLEVEL="\r\ncall "'+str(vcvars)+'" >nul\r\n'
                         'if not "%errorlevel%"=="0" exit /b %errorlevel%\r\nset\r\n',
                         encoding='utf-8',newline='')
        return subprocess.check_output([str(preview_system_cmd(root)),'/d','/c',str(batch)],env=env,text=True)


# VS18 vsdevcmd/core/vsdevcmd_end.bat :clean_env and ext/vcvars.bat
# :clean_env consume these saved values only to undo developer-prompt setup.
# Compiler children consume PATH/INCLUDE/LIB/etc., which remain unchanged.
PREVIEW_VSCMD_RESTORE = frozenset('__VSCMD_PREINIT_'+name for name in
    ('PATH','INCLUDE','LIB','LIBPATH','EXTERNAL_INCLUDE','VS180COMNTOOLS','VCTOOLSVERSION'))


def preview_merge_vcvars(base, captured):
    env = {key.upper():value for key,value in base.items() if key.upper() not in PREVIEW_VSCMD_RESTORE}
    for line in captured.splitlines():
        key,separator,value = line.partition('=')
        if separator and key and not key.startswith('=') and key.upper() not in PREVIEW_VSCMD_RESTORE:
            env[key.upper()] = value
    return env


def preview_stage(name, data, root, env):
    """Compose existing producers inside the caller's finite native source Job."""
    from scripts.file_boundary import same_existing_file
    inputs = {key:Path(row['path']) for key,row in data['inputs'].items()}
    directories = {key:Path(row['path']) for key,row in data['directories'].items()}
    out = Path(data['output']); version = data['version']
    env = preview_build_environment(env,out/'build-environment')
    def run(argv, selected=None):
        subprocess.run([str(value) for value in argv],cwd=root,env=selected or env,check=True)
    # Reuse the exact compiler environment selected by the existing native owner.
    captured = preview_capture_vcvars(root,inputs['vcvars'],env)
    native_env = preview_merge_vcvars(env,captured)
    for role in ('cl','rc','cvtres','link','node','npm'):
        actual = shutil.which(inputs[role].name,path=native_env.get('PATH'))
        if actual is None or not same_existing_file(actual,inputs[role]):
            raise ValueError('preview compiler environment differs from pinned '+role)
    go = Path(env['GOROOT'])/'bin/go.exe'
    core_env = dict(native_env,CGO_ENABLED='0',GOOS='windows',GOARCH='amd64',GOFLAGS='-trimpath')
    for key in ('CC','CXX'):core_env.pop(key,None)
    python = inputs['python']
    assembler = preview_owner(root/'installer/apps/build_bundle.py','oa_preview_bundle_owner')
    appmodel = preview_appmodel(root,data); npm = out/'npm'; oc = out/'opencode'; core = out/'core'
    if name == 'actions-native':
        authority = out/'prior-authority';authority.mkdir()
        # ProductCode and prior physical bytes are checked before native compilation.
        (authority/'history.json').write_bytes(installer_gateway_history(data['priors'],authority,str(inputs['wix'])))
        actions = out/'actions';actions.mkdir()
        packages = data.get('local_packages')
        catalog_maintenance = packages is not None
        if catalog_maintenance:
            assembler.preview_catalog_document(packages,version)
        facts = assembler.setup_actions_inputs(catalog_maintenance=catalog_maintenance)
        admitted = json.loads(inputs['actions_receipt'].read_bytes())
        if admitted.get('inputs') != facts['inputs']:
            raise ValueError('admitted actions receipt differs from current source/role map')
        (actions/'actions_map.h').write_text(facts['header'],encoding='utf-8',newline='\n')
        roles = [row['id'] for row in facts['inputs']['map']]
        run(assembler.bundle_actions_compile(roles,actions,str(inputs['cl']),catalog_maintenance=catalog_maintenance),native_env)
        pin = preview_pin(actions/facts['output'])
        (actions/'native-receipt.json').write_text(json.dumps({'schema':1,'inputs':facts['inputs'],
            'native':{'name':facts['output'],'sha256':pin['sha256'],'bytes':pin['bytes']}}),encoding='utf-8')
    elif name == 'appmodel-native':
        from release.testing.windows_lifetime import _plain
        _plain(appmodel)
        if appmodel.parent.exists():raise ValueError('preview AppModel source build must be fresh')
        appmodel.parent.mkdir(parents=True)
        run([python,'-B',root/'scripts/build_node_addon.py','--run','--appmodel-tests','--appmodel-worker',
            '--appmodel-build-root',appmodel,'--appmodel-node',inputs['node'],'--node-sdk',directories['node_sdk']],native_env)
        run([python,'-B',root/'scripts/build_node_addon.py','--run','--force','--node-sdk',directories['node_sdk']],native_env)
    elif name == 'panel-resources':
        host_env = resource_host_environment(core_env)
        run([go,'run','./monitor/icon/gen','-resources','-version',version,'-panel-dir',root/'monitor'],host_env)
        resource = out/'resources';resource.mkdir()
        object_path = resource/'rsrc_windows_amd64.syso'
        run([go,'run','./monitor/icon/gen','-installer-history-json',out/'prior-authority/history.json',
            '-agent-release-object',object_path,'-agent-release-arch','amd64',
            '-installer-history-panel-dir',root/'monitor','-vcvars',inputs['vcvars']],host_env)
        shutil.copyfile(object_path,root/'monitor/internal/panelres/rsrc_windows_amd64.syso')
    elif name == 'panel-resource-readback':
        image = out/'resources/panel-data.dll'
        run([inputs['link'],'/DLL','/NOENTRY','/MACHINE:X64','/OUT:'+str(image),out/'resources/rsrc_windows_amd64.syso'],native_env)
        digest = preview_history_readback(image,(out/'prior-authority/history.json').read_bytes(),data['priors'])
        (out/'resources/readback.json').write_text(json.dumps({'history_sha256':digest,'product_executed':False}),encoding='utf-8')
    elif name == 'core':
        sources = {'charter':root,'panel':root,'modelpack':root/'openabstractions-flat/abstraction-provider-kit',
            'localstores':root/'openabstractions-flat/abstraction-storage-over-local-stores',
            'modelhost':root/'openabstractions-flat/abstraction-provider-modelhost',
            'modelhostengine':directories['modelhostengine'],'ipclibrary':inputs['ipc'].parent,'appmodellibrary':appmodel}
        argv = [python,'-B',root/'installer/build.py','--arch',data['arch'],'--version',version,
                '--wix',inputs['wix'],'--ext',inputs['ui'],'--out',core]
        for key,path in sources.items():argv += ['--src',key+'='+str(path)]
        for triple in data['priors']:argv += ['--installer-prior',*triple]
        if data.get('local_packages'):
            packages = out/'catalog-packages'
            assets = packages/'adopter_assets.json'
            argv += ['--local-package-folder',packages,
                     '--local-package-assets-sha256',hashlib.sha256(assets.read_bytes()).hexdigest()]
        run(argv,core_env)
    elif name == 'core-readback':
        msi = core/'abstraction-x64.msi'
        run([python,'-B',root/'installer/validate.py','--wix',inputs['wix'],msi],core_env)
        extracted = out/'core-readback';extracted.mkdir()
        run([inputs['wix'],'msi','decompile',msi,'-x',extracted/'files','-o',extracted/'package.wxs'],core_env)
        import windows_signing
        actual,members,_,_ = windows_signing.msi_member_readback(extracted)
        panels = [row for row in actual['files'] if row['path'].endswith('/OpenAbstractions/tools/Abstraction Panel.exe')]
        if len(panels) != 1:raise ValueError('preview MSI needs exactly one Panel')
        panel,_,_ = members[('File',panels[0]['id'])]
        preview_history_readback(panel,(out/'prior-authority/history.json').read_bytes(),data['priors'])
        prefix = panels[0]['path'].rsplit('/', 1)[0] + '/'
        programs = {row['path'][len(prefix):]: members[('File',row['id'])][0] for row in actual['files']
                    if row['path'].startswith(prefix) and row['path'].endswith('.exe')}
        verify_shipped_runtime_cohort(programs, data['arch'], require_runtime=True)
    elif name == 'npm':
        run([python,'-B',root/'scripts/npm_packages.py','--version',version,'--output',npm,
            '--library',inputs['ipc'],'--addon',root/'openabstractions-flat/abstraction-identity/javascript/native/oa_ipc_node.node',
            '--facade-library',appmodel/'abstraction_facade_appmodel.dll','--facade-addon',appmodel/'oa_appmodel_node.node',
            '--dependency-cache',directories['dependency_cache'],'--platform','win32-x64'],native_env)
    elif name == 'opencode-native':
        plugin = preview_pin(npm/('openabstractions-opencode-'+version+'.tgz'))
        run([python,'-B',root/'adopters/opencode/installer/build_installer.py','--phase','prepare-native',
            '--app-builder',root/'installer/apps/build_app.py','--plugin',plugin['path'],'--plugin-sha256',plugin['sha256'],
            '--plugin-bytes',str(plugin['bytes']),'--parser-tgz',inputs['parser'],'--package-set',npm,
            '--dependency-cache',directories['dependency_cache'],'--out',oc,'--version',version,'--cl',inputs['cl']],native_env)
    elif name == 'opencode-package':
        prepared = json.loads((oc/'payload-receipt.json').read_bytes())['prepared_native']
        argv = [python,'-B',root/'adopters/opencode/installer/build_installer.py','--phase','package',
            '--app-builder',root/'installer/apps/build_app.py','--out',oc,'--version',version,'--cl',inputs['cl'],
            '--wix',inputs['wix'],'--desktop',inputs['opencode_desktop']]
        for key,option in (('host','installer-host'),('preflight','preflight')):
            row = prepared[key]
            argv += ['--'+option,row['path'],'--'+option+'-sha256',row['sha256'],'--'+option+'-bytes',str(row['bytes'])]
        run(argv,native_env)
        if data.get('local_packages'):
            preview_catalog_packages(Path(data['local_packages']), oc, out/'catalog-packages', version)
    elif name == 'bundle':
        catalog_maintenance = data.get('local_packages') is not None
        if catalog_maintenance:
            assembler.preview_catalog_document(out/'catalog-packages',version,built=True)
        bundle = out/'bundle';bundle.mkdir()
        pin = preview_pin(core/'abstraction-x64.msi')
        chain = {'version':version,'core':{'file':pin['path'],'sha256':pin['sha256'],'bytes':pin['bytes']},
                 'apps':[]}
        # The OpenCode MSI remains owned by the independent Catalog package stage.
        for _,_,package,_ in assembler.chain_packages(chain):
            source = Path(package['file']); target = bundle/source.name
            actual = preview_pin(source)
            if any(actual[key] != package[key] for key in ('sha256','bytes')):
                raise ValueError('preview chain package changed before bundle assembly')
            shutil.copyfile(source,target)
            package['file'] = target.name
        chain_path = bundle/'chain.json';chain_path.write_text(json.dumps(chain),encoding='utf-8')
        actions = out/'actions'
        run(assembler.setup_command(python=python,chain=chain_path,bal_ext=inputs['bal'],
            util_ext=inputs['util'],upgrade_binary=core/'payload/tools/openabstractions.exe',
            out=bundle,wix=inputs['wix'],actions_dll=actions/assembler.ACTIONS_NAME,
            actions_receipt=actions/'native-receipt.json',
            actions_receipt_sha256=preview_pin(actions/'native-receipt.json')['sha256'],
            catalog_maintenance=catalog_maintenance),native_env)
        receipt = json.loads((bundle/'bundle-receipt.json').read_bytes())
        if receipt['bundle'].get('signed') is not False:raise ValueError('private bundle must remain unsigned')
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'preview':
        return preview_main(sys.argv[2:])
    ap = argparse.ArgumentParser(description="Build one unsigned MSI from payload.tsv.",
        epilog='Private Setup preview: build.py preview SPEC.json; use build.py preview --help for the exact pinned-input format.')
    ap.add_argument("--arch", choices=GOARCH, default="x64")
    ap.add_argument("--version", default="0.0.0")
    ap.add_argument("--agent-release-channel", help="explicit signed helper release channel; requires --agent-release-version")
    ap.add_argument("--agent-release-version", help="explicit MAJOR.MINOR.PATCH.SEQUENCE; omission preserves legacy fresh Update")
    ap.add_argument('--installer-prior', action='append', nargs=3, default=[], metavar=('RECEIPT', 'SHA256', 'PRODUCT_CODE'),
                    help='qualified prior bundle receipt, its exact admitted hash and expected core ProductCode; producer data only')
    ap.add_argument("--wix", default="wix")
    ap.add_argument("--ext", default="WixToolset.UI.wixext")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--license", type=Path, default=HERE.parent / "LICENSE")
    ap.add_argument("--src", action="append", default=[], metavar="ID=DIR",
                    help="where the sources.tsv source ID is checked out; "
                         "a source not given here is left out of the package")
    ap.add_argument("--bin", type=Path, metavar="DIR",
                    help="take the programs from DIR instead of building them, "
                         "for a package assembled out of published module "
                         "versions rather than out of checkouts")
    ap.add_argument('--producer-receipt', type=Path, help='existing admitted producer receipt snapshot for --bin')
    ap.add_argument('--producer-receipt-sha256', help='exact producer-owned receipt SHA256')
    ap.add_argument('--local-package-folder', help='private preview only: folder of release assets Setup installs from')
    ap.add_argument('--local-package-assets-sha256', help="SHA-256 of that folder's adopter_assets.json")
    a = ap.parse_args()
    if (a.local_package_folder is None) != (a.local_package_assets_sha256 is None):
        ap.error('--local-package-folder and --local-package-assets-sha256 go together')

    # wix runs with cwd=out, so a relative --out would be applied twice and the
    # package would land under itself.
    a.out = a.out.resolve()

    src = {"installer": HERE}
    for pair in a.src:
        sid, _, d = pair.partition("=")
        src[sid] = Path(d).resolve()
    src = checkout_sources(src, a.arch, a.bin)

    program_proof = None
    if a.producer_receipt is not None or a.producer_receipt_sha256 is not None:
        if a.producer_receipt is None or a.producer_receipt_sha256 is None:
            ap.error('producer receipt and exact SHA256 are required together')
        if shipped_provider_images(a.producer_receipt.parent, [a.producer_receipt.name])[
                a.producer_receipt.name] != a.producer_receipt_sha256:
            ap.error('producer receipt differs from admitted input')
        raw = a.producer_receipt.read_bytes()
        if hashlib.sha256(raw).hexdigest() != a.producer_receipt_sha256:
            ap.error('producer receipt differs from admitted input')
        program_proof = json.loads(raw)['program_proof']
        require_admitted_panel(src, a.bin)

    if subprocess.run([sys.executable, str(HERE / "validate.py")]).returncode:
        return 1

    a.out.mkdir(parents=True, exist_ok=True)
    try:
        dropped = stage(src, a.out, a.arch, a.bin, a.agent_release_channel, a.agent_release_version, a.installer_prior, a.wix,
                        program_proof=program_proof,
                        local_packages=(a.local_package_folder, a.local_package_assets_sha256) if a.local_package_folder else None)
    except ValueError as error:
        print("FAIL ", error)
        return 1
    for path in dropped:
        if path not in GATE:
            print(f"FAIL  {path} has no --src for its source, no --bin holding it, "
                  f"and no gate to leave it out")
            return 1
    # A clean Windows has no Visual C++ runtime: every staged program,
    # library and engine bundle member carries the runtime DLLs it imports.
    missing = runtime_imports.problems(a.out / "payload")
    for line in missing:
        print("FAIL  " + line)
    if missing:
        return 1

    notices = licence_notices(a.out)
    subprocess.run([sys.executable, str(HERE / "mklicense.py"),
                    str(a.license), str(a.out / "license.rtf"), *notices], check=True)

    msi = a.out / f"abstraction-{a.arch}.msi"
    off = {GATE[p] for p in dropped}
    defs = {"Version": a.version}
    for v in dict.fromkeys(GATE.values()):
        defs[v] = "no" if v in off else "yes"
    cmd = [a.wix, "build", "-arch", a.arch, "-bindpath", str(a.out),
           *[x for k, v in defs.items() for x in ("-d", f"{k}={v}")],
           "-ext", a.ext, "-o", str(msi), str(HERE / "abstraction.wxs")]
    print(" ".join(cmd))
    if subprocess.run(cmd, cwd=a.out).returncode:
        return 1

    for path in dropped:
        print(f"note  {path} left out, so {GATE[path]}=no")
    print(f"ok    {msi.name} {msi.stat().st_size} bytes, UNSIGNED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
