"""Build the existing official-ComfyUI extension from selected public sources.

The train owns source selection and API artifact intake. These fixed producer
hooks reuse the extension composer, MSI builder and normal signature receiver.
No ComfyUI runtime, Python distribution or model is packaged here.
"""
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from file_boundary import ordinary_path, relative_beneath_existing

MODULE = 'github.com/openabstractions/adopter-comfyui/connector'
PROGRAM = 'comfyui-connector.exe'
ACTION = 'hostfolder.dll'


def load(path, name):
    path = Path(path)
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    owner = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), owner.__dict__)
    return owner


def pin(path):
    path = ordinary_path(path, kind='file')
    if path.stat().st_nlink != 1:
        raise ValueError('extension input must be an ordinary single-link file')
    digest = hashlib.sha256()
    size = 0
    with Path(path).open('rb') as reader:
        for block in iter(lambda: reader.read(1 << 20), b''):
            digest.update(block)
            size += len(block)
    return dict(bytes=size, sha256=digest.hexdigest())


def write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True) + '\n', encoding='utf-8')


def owners(shared):
    shared = Path(shared)
    scripts = shared / 'scripts'
    windows = shared / 'windows'
    return (load(scripts / 'app_producer_inputs.py', 'extension_input_owner'),
            load(scripts / 'module_provenance.py', 'extension_graph_owner'),
            load(windows / 'apps/build_extension.py', 'extension_msi_owner'),
            load(windows / 'windows_signing.py', 'extension_signature_owner'))


def source_context(shared, sources, pins, inputs, version):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('extension requires an exact release version')
    required = {'openabstractions/redist', 'openabstractions/abstractions',
                'openabstractions/adopter-comfyui', 'openabstractions/abstraction-identity'}
    if not required <= set(pins):
        raise ValueError('extension lacks its selected public source closure')
    helper, graph_owner, builder, relay = owners(shared)
    received = helper.pinned_input_receipt(pins, sources, inputs)
    # Authenticate the executing shared owner through the selected clone too.
    for name in ('windows/apps/build_extension.py', 'windows/apps/extension.wxs',
                 'windows/apps/hostfolder.c', 'windows/apps/hostfolder_io.h',
                 'windows/apps/native_windows.h', 'scripts/module_provenance.py'):
        if pin(Path(shared) / name) != pin(Path(sources) / 'redist' / name):
            raise ValueError('extension shared source differs from selected public owner: ' + name)
    descriptor = Path(sources) / 'adopter-comfyui/.installer/extension.json'
    extension = builder.read_extension(descriptor)
    if extension['id'] != 'comfyui' or extension['programs'] != [PROGRAM]:
        raise ValueError('extension must select the declared ComfyUI connector')
    return helper, graph_owner, builder, relay, received, descriptor


def stage_payload(shared, sources, pins, destination):
    package = load(Path(sources) / 'abstractions/scripts/package_comfyui_integration.py',
                   'selected_official_extension_composer')
    repositories = {name: dict(repository=name, commit=commit) for name, commit in pins.items()}
    return package.stage_wrapper(Path(sources) / 'abstractions', Path(sources) / 'adopter-comfyui',
        destination, public_source_root=sources, redist_source_root=shared, public_pins=repositories)


def graph_context(sources, version, graph_owner):
    redist = Path(sources) / 'redist'
    graph = json.loads((redist / 'public-go-graph.json').read_bytes())
    raw = (redist / 'public-go-graph.zip').read_bytes()
    graph_owner.unpack_staged_graph(raw, None, graph)
    rows = [row for row in graph['modules'] if row['module'] == MODULE]
    if graph['version'] != 'v' + version or len(rows) != 1:
        raise ValueError('extension connector is absent from the exact prepared Go graph')
    return graph, raw, rows[0]


def prepare(shared, sources, pins, inputs, output, version, go, cl, sdk_receipt):
    """Build only the frozen connector and the existing MSI host-folder action."""
    helper, graph_owner, builder, _, received, descriptor = source_context(
        shared, sources, pins, inputs, version)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    sdk_path = Path(sources) / 'redist/tools/windows_go_sdk.py'
    sdk = load(sdk_path, 'extension_selected_go_sdk')
    sdk_value = sdk.validate_sdk_receipt(json.loads(Path(sdk_receipt).read_bytes()))
    go = Path(go).resolve(strict=True)
    if go != Path(sdk_value['go']).resolve(strict=True):
        raise ValueError('extension compiler differs from canonical Windows Go SDK')
    graph, archive, row = graph_context(sources, version, graph_owner)
    with zipfile.ZipFile(io.BytesIO(archive)) as capsule:
        graph_owner.require_program_package(capsule.read(
            'proxy/' + graph_owner.escape_module(MODULE) + '/@v/' + row['version'] + '.zip'),
            MODULE, row['version'], '.')
    shutil.copyfile(Path(sdk_value['goroot']).parent / 'archive.zip', output / 'go-sdk-archive.zip')
    with tempfile.TemporaryDirectory(prefix='oa-extension-go-') as temporary:
        work = Path(temporary)
        proxy = work / 'go-inputs'
        graph_owner.unpack_staged_graph(archive, proxy, graph)
        environment = dict(os.environ, GOWORK='off', GOENV='off', GOTOOLCHAIN='local',
            CGO_ENABLED='0', GOOS='windows', GOARCH='amd64', GOFLAGS='-mod=readonly',
            GOPROXY=(proxy / 'proxy').as_uri(), GOSUMDB='off', GOPRIVATE='', GONOPROXY='',
            GOMODCACHE=str(work / 'modcache'), GOCACHE=str(work / 'gocache'), GOPATH=str(work / 'gopath'))
        downloaded = json.loads(subprocess.check_output([str(go), 'mod', 'download', '-json',
            MODULE + '@' + row['version']], cwd=work, env=environment, text=True))
        if any(downloaded.get(key) != expected for key, expected in (
                ('Path', MODULE), ('Version', row['version']), ('Sum', row['sum']), ('GoModSum', row['gomodsum']))):
            raise ValueError('extension connector module hashes differ from the prepared graph')
        module = Path(downloaded['Dir']).resolve(strict=True)
        relative_beneath_existing(module, work / 'modcache')
        subprocess.run([str(go), 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w',
                        '-o', str(output / PROGRAM), '.'], cwd=module, env=environment, check=True)
        buildinfo = subprocess.check_output([str(go), 'version', '-m', str(output / PROGRAM)], text=True)
    (output / 'go-buildinfo.txt').write_text(buildinfo, encoding='utf-8')
    builder.build_action(output, str(Path(cl).resolve(strict=True)))
    payload = stage_payload(shared, sources, pins, output / 'wrapper')
    original = dict(schema=1, id='comfyui', version=version, platform='windows/amd64',
        input_receipt=received, descriptor=pin(descriptor), payload=payload,
        native_action_sources=builder.native_action_sources(),
        go=dict(module=row, sdk=sdk_value['source_identity'], buildinfo=pin(output / 'go-buildinfo.txt')),
        native_files={name: pin(output / name) for name in (PROGRAM, ACTION)})
    if helper.pinned_input_receipt(pins, sources, inputs) != received:
        raise ValueError('extension preparation changed selected source/input closure')
    write(output / 'extension-native-receipt.json', original)
    return original


def receive(shared, sources, pins, inputs, output, version, *, signed=False, policy=None, signtool=None):
    """Recheck selected sources before native signing or package receiving."""
    _, graph_owner, builder, relay, received, descriptor = source_context(
        shared, sources, pins, inputs, version)
    output = ordinary_path(output, kind='directory').resolve(strict=True)
    original = json.loads((output / 'extension-native-receipt.json').read_bytes())
    _, _, row = graph_context(sources, version, graph_owner)
    sdk = load(Path(sources) / 'redist/tools/windows_go_sdk.py', 'extension_receiving_go_sdk')
    sdk.archived_compiler_facts(output / 'go-sdk-archive.zip', original['go']['sdk'])
    with tempfile.TemporaryDirectory(prefix='oa-extension-source-') as temporary:
        payload = stage_payload(shared, sources, pins, Path(temporary) / 'wrapper')
    if (set(original) != {'schema','id','version','platform','input_receipt','descriptor','payload',
                         'native_action_sources','go','native_files'} or original['schema'] != 1
            or original['id'] != 'comfyui' or original['version'] != version
            or original['platform'] != 'windows/amd64' or original['input_receipt'] != received
            or original['descriptor'] != pin(descriptor) or original['payload'] != payload
            or original['native_action_sources'] != builder.native_action_sources()
            or original['go']['module'] != row or original['go']['buildinfo'] != pin(output / 'go-buildinfo.txt')
            or set(original['native_files']) != {PROGRAM, ACTION}):
        raise ValueError('extension producer source/input closure differs')
    actual = {}
    def inventory(directory, prefix=''):
        ordinary_path(directory, kind='directory')
        for path in directory.iterdir():
            name = prefix + path.name
            ordinary_path(path)
            if path.is_dir():
                inventory(path, name + '/')
            else:
                actual[name] = pin(path)
    inventory(output / 'wrapper')
    if actual != payload:
        raise ValueError('extension staged source payload differs')
    if signed:
        proof = relay.verify_receipt(json.loads((output / 'signatures.json').read_bytes()), policy, output,
            policy_sha256=hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest())
        if {row['name'] for row in proof['files']} != {PROGRAM, ACTION} or len(proof['files']) != 2:
            raise ValueError('extension native signature roster differs')
        for name in (PROGRAM, ACTION):
            relay.verify(output / name, policy, signtool)
        relay.verify_go_content(output / PROGRAM, original['native_files'][PROGRAM])
    elif any(pin(output / name) != value for name, value in original['native_files'].items()):
        raise ValueError('extension unsigned native input differs')
    return original, builder, relay


def sign_native(shared, sources, pins, inputs, output, version, policy, signtool):
    _, _, relay = receive(shared, sources, pins, inputs, output, version)
    proof = dict(schema=1, result='pass',
        policy_sha256=hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(),
        files=[dict(relay.sign(Path(output) / name, policy, signtool), name=name) for name in (PROGRAM, ACTION)])
    write(Path(output) / 'signatures.json', proof)
    receive(shared, sources, pins, inputs, output, version, signed=True, policy=policy, signtool=signtool)
    return proof


def package(shared, sources, pins, inputs, output, version, wix, policy, signtool):
    original, builder, _ = receive(shared, sources, pins, inputs, output, version,
                                   signed=True, policy=policy, signtool=signtool)
    output = Path(output).resolve()
    descriptor = json.loads((Path(sources) / 'adopter-comfyui/.installer/extension.json').read_bytes())
    # The selected composer already resolved every include into this exact tree.
    descriptor.update(payload='wrapper', include=[])
    prepared = output / 'prepared-extension.json'
    write(prepared, descriptor)
    action = pin(output / ACTION)
    destination = output / 'package'
    result = builder.main(['--extension', str(prepared), '--publisher', 'OpenAbstractions',
        '--version', version, '--out', str(destination), '--wix', str(Path(wix).resolve(strict=True)),
        '--program', str(output / PROGRAM), '--action-dll', str(output / ACTION),
        '--action-sha256', action['sha256'], '--action-bytes', str(action['bytes']),
        '--input-receipt', str(output / 'extension-native-receipt.json')])
    if result:
        raise ValueError('official ComfyUI extension MSI construction failed')
    receive(shared, sources, pins, inputs, output, version, signed=True, policy=policy, signtool=signtool)
    receipt = json.loads((destination / 'installer-receipt.json').read_bytes())
    if receipt['test_build'] or receipt['descriptor'] != pin(prepared):
        raise ValueError('extension MSI must use its exact release descriptor')
    return receipt


def expected_payload(shared, sources, pins, inputs, output, version, policy, signtool):
    original, builder, relay = receive(shared, sources, pins, inputs, output, version,
                                 signed=True, policy=policy, signtool=signtool)
    output = Path(output)
    receipt = json.loads((output / 'package/installer-receipt.json').read_bytes())
    expected = receipt['expected_payload']
    signatures = json.loads((output / 'signatures.json').read_bytes())
    proofs = {row['name']: row for row in signatures['files']}
    inventory = dict(original['payload'], **{PROGRAM: pin(output / PROGRAM)})
    ordered = [name.as_posix() for name in builder.payload_files(output / 'wrapper')] + [PROGRAM]
    files = [dict(inventory[name], id='ExtFile' + str(index),
                  path='LocalAppDataFolder/OpenAbstractions-extension-unset/comfyui-openabstractions/' + name)
             for index, name in enumerate(ordered)]
    if (receipt.get('test_build') is not False or receipt['payload'] != inventory
            or expected['files'] != files or expected['binaries'] != [dict(pin(output / ACTION), id='HostFolderAction')]
            or expected.get('icons') != [] or receipt['native_action_sources'] != original['native_action_sources']):
        raise ValueError('extension MSI expectations differ from selected source payload')
    connector = next(row for row in files if row['path'].endswith('/' + PROGRAM))
    expected = dict(expected, own_pe=[dict(table='File', id=connector['id'], signature=proofs[PROGRAM]),
        dict(table='Binary', id='HostFolderAction', signature=proofs[ACTION])], supplier_pe=[])
    return relay.validate_expected_payload(expected)


def sign_msi(shared, sources, pins, inputs, output, version, policy, signtool):
    expected = expected_payload(shared, sources, pins, inputs, output, version, policy, signtool)
    relay = owners(shared)[3]
    name = 'comfyui-' + version + '.msi'
    proof = relay.sign_app_msi(Path(output) / 'package' / name, policy, signtool, expected)
    write(Path(output) / 'package/signatures.json', dict(schema=1, result='pass',
        policy_sha256=hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(),
        files=[dict(proof, name=name)]))
    return proof


def catalogue_pin(shared, sources, pins, inputs, output, version, policy, signtool):
    """Return the existing ConnectorPackagePin only after real signed readback."""
    expected = expected_payload(shared, sources, pins, inputs, output, version, policy, signtool)
    relay = owners(shared)[3]
    msi = Path(output) / 'package' / ('comfyui-' + version + '.msi')
    signatures = relay.verify_receipt(json.loads((msi.parent / 'signatures.json').read_bytes()), policy, msi.parent,
        policy_sha256=hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest())
    if len(signatures['files']) != 1 or signatures['files'][0]['name'] != msi.name:
        raise ValueError('extension signed MSI roster differs')
    relay.verify_msi_payload(msi, policy, signtool, expected_payload=expected, container_proof=signatures['files'][0])
    return dict(id='comfyui', file=msi.name, version=version, **pin(msi),
                connector_sha256=pin(Path(output) / PROGRAM)['sha256'],
                connector_bytes=pin(Path(output) / PROGRAM)['bytes'])
