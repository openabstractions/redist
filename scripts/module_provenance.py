#!/usr/bin/env python3
"""Verify and record the published Go modules selected by tools.tsv."""
from __future__ import annotations
import argparse
import filecmp
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from urllib.parse import urlsplit
from urllib.request import url2pathname
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_tsv_rows import rows as release_rows, platform_tools

ORG = "github.com/openabstractions/"
VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
IMMUTABLE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
PSEUDO_VERSION = re.compile(r"v0\.0\.0-[0-9]{14}-([0-9a-f]{12})$")
APPROVED_PSEUDO_MODULE = "github.com/openabstractions/websocket"
APPROVED_PSEUDO_VERSION = "v0.0.0-20260926143434-ce87d3641bd1"
APPROVED_PSEUDO_COMMIT = "ce87d3641bd1e04e7acfd4a848d193951d5da73f"
Runner = Callable[..., subprocess.CompletedProcess[str]]

PANEL_MODULE = 'github.com/openabstractions/abstractions/monitor'
PANEL_CATALOGUE = 'internal/setup/adopter_assets.json'
PANEL_INSTALLER_RESOURCE = 'internal/panelres/rsrc_windows_amd64.syso'
RUNTIME_MODULE = 'github.com/openabstractions/abstractions/serve'


def panel_native_source_roster(sdk_roster, provenance):
    """Select Panel's native readset from its already-verified Go inputs.

    Language SDK producers retain their independent source pins. The unchanged
    Panel launcher checks these rows against the same selected Go provenance.
    """
    required = {'https://github.com/openabstractions/abstraction-' + name
                for name in ('identity', 'facade', 'download', 'router', 'rights')}
    if provenance.get('kind') == 'prepared-module-provenance':
        records = [(row.get('repository'), row.get('commit'))
                   for row in provenance.get('graph', {}).get('modules', [])]
    else:
        records = [(row.get('repository'), row.get('expected_commit'))
                   for module in provenance.get('modules', []) for row in module.get('selected', [])]
    selected = {}
    for repository in required:
        matches = {commit for repo, commit in records if repo == repository}
        if len(matches) != 1 or not re.fullmatch('[0-9a-f]{40}', next(iter(matches)) or ''):
            raise ValueError('Panel native repository lacks one selected Go commit: ' + repository)
        selected[repository.removeprefix('https://github.com/')] = next(iter(matches))
    rows = [tuple([package, repository, selected[repository], directory])
            for package, repository, _, directory in release_rows(sdk_roster, 'pypi.tsv')
            if repository in selected]
    if {row[1] for row in rows} != set(selected):
        raise ValueError('Panel native source roster lacks its complete repository closure')
    return 'package\trepository\tcommit\tdirectory\n' + ''.join('\t'.join(row) + '\n' for row in rows)


def program_tags(name, module, package, subsystem):
    # The existing monitor owner builds its Asks presenter from the same module
    # with this fixed tag (installer/build.py GO_TAGS). No roster-supplied flags.
    if name != 'OpenAbstractions Presenter.exe':
        return []
    if module != PANEL_MODULE or package != '.' or subsystem != 'windows':
        raise ValueError('Presenter requires the selected monitor root and Windows subsystem')
    return ['-tags', 'presenter']


def runtime_program(row):
    return _windows_build_owner().shipped_program_role(row[1].rsplit('@', 1)[0], row[2]) == 'runtime'


def _windows_build_owner():
    path = Path(__file__).parent.parent / 'windows/build.py'
    if not path.is_file():
        path = Path(__file__).resolve().parents[3] / 'installer/build.py'
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location('oa_shipped_images_build_owner', path)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        return owner
    finally:
        sys.path.pop(0)


def require_program_package(raw, module, version, package):
    """Refuse a program absent from the selected immutable module's source."""
    prefix = module + '@' + version + '/' + ('' if package == '.' else package + '/')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        present = any(name.startswith(prefix) and '/' not in name[len(prefix):] and
                      name.endswith('.go') and not name.endswith('_test.go')
                      for name in archive.namelist())
    if not present:
        raise ValueError('program package is absent from the selected module archive: ' + package)


def _panel_assets_owner():
    # The selected helper owns this sibling. Ambient imports can name another
    # checkout or a different byte representation of the same source.
    path=Path(__file__).with_name('app_assets.py')
    raw,pin=observed_input(path)
    spec=importlib.util.spec_from_file_location('oa_panel_catalogue_owner',path)
    owner=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec',dont_inherit=True),owner.__dict__)
    return owner,pin


def select_panel_source(prepared_graph, proxy_root, catalogue_directory, *, expected_producer, expected_apps,
                        expected_installer_priors=None, history_environment=None, history_wix='wix'):
    """Join authenticated produced metadata to the selected immutable module ZIP.

    The caller receives catalogue_directory through the existing API artifact
    intake. Its descriptor supplies the expected generated bytes independently
    of the file; the graph supplies the original module archive pin.
    """
    assets,_=_panel_assets_owner()
    staged_graph_rows(prepared_graph)
    rows = [row for row in prepared_graph['modules'] if row['module'] == PANEL_MODULE]
    if len(rows) != 1:raise ValueError('prepared graph omits exact Panel module')
    module = rows[0]
    prefix = escape_module(PANEL_MODULE) + '/@v/' + module['version'] + '.zip'
    archives = [row for row in prepared_graph['files'] if row['path'] == 'proxy/' + prefix]
    if len(archives) != 1:raise ValueError('prepared graph omits exact Panel ZIP')
    directory = Path(catalogue_directory)
    if any(path.is_symlink() or path.is_junction() for path in (directory,*directory.parents)):
        raise ValueError('linked Panel catalogue input directory')
    descriptor_path = directory/'panel-catalogue-input.json'
    if descriptor_path.is_symlink() or descriptor_path.is_junction() or not descriptor_path.is_file():
        raise ValueError('Panel catalogue descriptor is not ordinary')
    descriptor = json.loads(descriptor_path.read_bytes(),object_pairs_hook=assets.strict_object)
    if (set(descriptor) != {'schema','kind','producer','catalogue','expected_apps','source_catalogue','produced_rows'}
            or type(descriptor['schema']) is not int or descriptor['schema'] != 1
            or descriptor['kind'] != 'monitor-compiled-catalogue-input'
            or descriptor['producer'] != expected_producer
            or descriptor['expected_apps'] != sorted(expected_apps)):
        raise ValueError('Panel catalogue input differs from selected producer or rows')
    for key in ('catalogue','source_catalogue','produced_rows'):
        value=descriptor[key]
        if (not isinstance(value,dict) or set(value) != {'bytes','sha256'} or
                type(value['bytes']) is not int or value['bytes'] <= 0 or
                not re.fullmatch('[0-9a-f]{64}',str(value['sha256']))):
            raise ValueError('invalid Panel catalogue input pin')
    carrier = dict(module_zip=Path(proxy_root)/prefix,catalogue_path=directory/'panel-catalogue.json',
        module_row=module,expected_archive={key:archives[0][key] for key in ('bytes','sha256')},
        expected_catalogue=descriptor['catalogue'],producer=dict(expected_producer),expected_apps=list(expected_apps))
    intake = directory / 'installer-priors' / 'installer-prior-intake.json'
    if expected_installer_priors is not None:
        path = Path(__file__).parent.parent / 'windows/windows_signing.py'
        spec = importlib.util.spec_from_file_location('oa_panel_prior_intake_owner', path)
        relay = importlib.util.module_from_spec(spec); spec.loader.exec_module(relay)
        relay.installer_prior_descriptor(expected_installer_priors)
        received = json.loads(intake.read_bytes(), object_pairs_hook=assets.strict_object)
        if (set(received) != {'schema', 'descriptor', 'producer'} or received['schema'] != 1
                or received['descriptor'] != expected_installer_priors or received['producer'] != expected_producer
                or expected_installer_priors['source'] != prepared_graph['source']):
            raise ValueError('Panel installer predecessor intake differs from authenticated prepared inputs')
        archives = [intake.parent / str(i) / row['asset']['name'] for i, row in enumerate(expected_installer_priors['priors'])]
        with tempfile.TemporaryDirectory(prefix='oa-panel-prior-history-') as temporary:
            raw = relay.installer_prior_history(expected_installer_priors, archives, Path(temporary)/'history',
                wix=history_wix,environment=history_environment)
        carrier['installer_history'] = json.loads(raw)
    elif intake.exists():
        raise ValueError('Panel installer predecessor intake lacks independently selected authority')
    arguments = dict(carrier)
    module_zip,catalogue_path = arguments.pop('module_zip'),arguments.pop('catalogue_path')
    _panel_projection_inputs(module_zip,catalogue_path,**arguments)
    return carrier


def _panel_projection_inputs(module_zip, catalogue_path, *, module_row, expected_archive,
                             expected_catalogue, producer, expected_apps, installer_history=None):
    """Read one authenticated module and catalogue; retain their distinct pins."""
    assets,catalogue_owner=_panel_assets_owner()
    def read(path, expected):
        path = Path(path)
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or path.is_junction()
                or info.st_nlink != 1):raise ValueError('Panel projection input is not ordinary')
        if any(parent.is_symlink() or parent.is_junction() for parent in path.parents):
            raise ValueError('linked Panel projection input parent')
        raw = path.read_bytes()
        pin = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        if (not isinstance(expected,dict) or type(expected.get('bytes')) is not int or expected['bytes'] <= 0 or
                any(pin[key] != expected[key] for key in pin)):
            raise ValueError('Panel projection input differs from authenticated pin')
        return raw, pin
    if (not isinstance(module_row, dict) or not isinstance(producer, dict) or
            not isinstance(expected_apps, (list, tuple)) or
            any(not isinstance(app,str) for app in expected_apps) or
            module_row.get('module') != PANEL_MODULE or not VERSION.fullmatch(str(module_row.get('version')))
            or any(not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', str(module_row.get(key))) for key in ('sum','gomodsum'))
            or set(producer) != {'source','run_id','run_attempt'}
            or not re.fullmatch(r'[0-9a-f]{40}', str(producer['source']))
            or any(type(producer[key]) is not int or producer[key] <= 0 for key in ('run_id','run_attempt'))):
        raise ValueError('Panel source module or producer identity differs')
    archive, archive_pin = read(module_zip, expected_archive)
    catalogue, catalogue_pin = read(catalogue_path, expected_catalogue)
    rows = assets.panel_catalogue_rows(catalogue)
    if (rows.version != module_row['version'].removeprefix('v') or
            len(set(expected_apps)) != len(expected_apps) or
            {row['id'] for row in rows} != set(expected_apps)):
        raise ValueError('Panel catalogue version or selected rows differ')
    # Match Go's module ZIP size ceiling; this is an owned source projection.
    limit = 500 << 20
    if len(archive) > limit:raise ValueError('Panel module ZIP exceeds Go module bound')
    prefix = PANEL_MODULE + '@' + module_row['version'] + '/'
    files, names, expanded = {}, set(), 0
    with zipfile.ZipFile(io.BytesIO(archive)) as content:
        for entry in content.infolist():
            if not entry.filename.startswith(prefix):raise ValueError('foreign Panel module ZIP member')
            name = entry.filename[len(prefix):].rstrip('/')
            if (not name or '\\' in name or ':' in name or
                    any(part in ('','.', '..', '.git') for part in name.split('/')) or
                    name.casefold() in names):raise ValueError('unsafe or duplicate Panel module member')
            names.add(name.casefold())
            mode = entry.external_attr >> 16
            if entry.is_dir():
                if stat.S_IFMT(mode) not in (0,stat.S_IFDIR):raise ValueError('special Panel module directory')
                continue
            if stat.S_IFMT(mode) not in (0,stat.S_IFREG):raise ValueError('special Panel module file')
            expanded += entry.file_size
            if expanded > limit:raise ValueError('Panel module expanded source exceeds Go bound')
            files[name] = content.read(entry)
    if PANEL_CATALOGUE not in files or 'go.mod' not in files:
        raise ValueError('Panel module lacks its original compiled catalogue or go.mod')
    if not re.search(rb'(?m)^module[ \t]+' + re.escape(PANEL_MODULE.encode()) + rb'[ \t]*\r?$', files['go.mod']):
        raise ValueError('Panel module declaration differs from selected module')
    if any('/'.join(name.split('/')[:i]) in files for name in files
           for i in range(1,len(name.split('/')))):
        raise ValueError('Panel module has a file/directory collision')
    def pins(values):
        return [{'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                for name, raw in sorted(values.items())]
    original = pins(files)
    files[PANEL_CATALOGUE] = catalogue
    if installer_history is not None:
        if (not isinstance(installer_history,dict) or set(installer_history) != {'schema','predecessors'}
                or type(installer_history['schema']) is not int or installer_history['schema'] != 1
                or not isinstance(installer_history['predecessors'],list) or not 1 <= len(installer_history['predecessors']) <= 8):
            raise ValueError('Panel requires nonempty verified installer predecessor history')
        seen=set()
        for row in installer_history['predecessors']:
            if (not isinstance(row,dict) or set(row) != {'product_code','msi_sha256','receipt_sha256','bundle_sha256',
                    'gateway_id','gateway_path','gateway_sha256','gateway_bytes'}
                    or not re.fullmatch(r'\{[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}\}',str(row['product_code']))
                    or row['product_code'] in seen or not isinstance(row['gateway_id'],str) or not row['gateway_id']
                    or any(c in row['gateway_id'] for c in '/\\:\0')
                    or not isinstance(row['gateway_path'],str)
                    or not row['gateway_path'].endswith('/OpenAbstractions/tools/openabstractions-mcp.exe')
                    or type(row['gateway_bytes']) is not int or not 1 <= row['gateway_bytes'] <= 256 << 20
                    or any(not re.fullmatch('[0-9a-f]{64}',str(row[key])) for key in ('msi_sha256','receipt_sha256','bundle_sha256','gateway_sha256'))):
                raise ValueError('Panel installer predecessor history is malformed or duplicate')
            seen.add(row['product_code'])
        files['installer-gateway-history.json'] = json.dumps(installer_history,sort_keys=True,separators=(',',':')).encode()
        if len(files['installer-gateway-history.json']) > 16384:
            raise ValueError('Panel installer predecessor history exceeds the runtime resource bound')
    _, recipe = observed_input(Path(__file__))
    record = dict(recipe='monitor-compiled-catalogue-v1',
        recipe_input={key:recipe[key] for key in ('bytes','sha256')}, module=dict(module_row),
        catalogue_owner={key:catalogue_owner[key] for key in ('bytes','sha256')},
        source_archive=archive_pin, catalogue=catalogue_pin, producer=dict(producer),
        expected_apps=sorted(expected_apps), original_files=original, files=pins(files))
    if installer_history is not None:record['installer_history'] = installer_history
    return files, record


def prepare_panel_source(module_zip, catalogue_path, output, *, module_row, expected_archive,
                         expected_catalogue, producer, expected_apps, installer_history=None,
                         resource_environment=None, resource_runner=None):
    """Project the catalogue and selected installer history into fresh monitor source."""
    files, record = _panel_projection_inputs(module_zip, catalogue_path, module_row=module_row,
        expected_archive=expected_archive, expected_catalogue=expected_catalogue,
        producer=producer, expected_apps=expected_apps, installer_history=installer_history)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or output.is_junction():
        raise ValueError('Panel source projection must be new')
    for parent in output.parents:
        if parent.is_symlink() or parent.is_junction():raise ValueError('linked Panel projection parent')
    output.mkdir()
    for name, raw in files.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    if installer_history is not None:
        environment=dict(os.environ if resource_environment is None else resource_environment)
        go = str(Path(environment['GOROOT'])/'bin/go.exe') if 'GOROOT' in environment else shutil.which('go',path=environment.get('PATH'))
        if not go or not Path(go).is_absolute():raise ValueError('Panel history requires an admitted absolute Go executable')
        for key in ('GOOS','GOARCH','GOFLAGS','CGO_ENABLED','CC'):
            environment.pop(key,None)
        compiler=output/'icon/gen'
        resource=output/PANEL_INSTALLER_RESOURCE
        if not resource.is_file() or not compiler.is_dir():
            raise ValueError('Panel history requires the original combined resource and source generator')
        resource.unlink()  # The generator requires a fresh output in this new owned projection.
        argv=[go,'run',*[str(compiler/name) for name in ('main.go','native.go','agent_release.go')],
            '-installer-history-json',str(output/'installer-gateway-history.json'),
            '-agent-release-object',str(resource),'-agent-release-arch','amd64','-installer-history-panel-dir',str(output)]
        (resource_runner or subprocess.run)(argv,check=True,env=environment)
        record['installer_resource']={k:observed_file(resource)[k] for k in ('bytes','sha256')}
        record['resource_compiler']={k:observed_file(Path(go))[k] for k in ('bytes','sha256')}
        record['files']=[dict(row,**record['installer_resource']) if row['path']==PANEL_INSTALLER_RESOURCE else row for row in record['files']]
    verify_panel_source(output, record, module_zip=module_zip, catalogue_path=catalogue_path,
        module_row=module_row, expected_archive=expected_archive, expected_catalogue=expected_catalogue,
        producer=producer, expected_apps=expected_apps, installer_history=installer_history)
    return record


def verify_panel_source(output, provenance, *, module_zip, catalogue_path, module_row,
                        expected_archive, expected_catalogue, producer, expected_apps, installer_history=None):
    """Recompute from authenticated originals before/after link and cached reuse."""
    _, expected = _panel_projection_inputs(module_zip, catalogue_path, module_row=module_row,
        expected_archive=expected_archive, expected_catalogue=expected_catalogue,
        producer=producer, expected_apps=expected_apps, installer_history=installer_history)
    if installer_history is not None:
        for key in ('installer_resource','resource_compiler'):
            pin=provenance.get(key)
            if (not isinstance(pin,dict) or set(pin) != {'bytes','sha256'} or type(pin['bytes']) is not int
                    or pin['bytes'] <= 0 or not re.fullmatch('[0-9a-f]{64}',str(pin['sha256']))):
                raise ValueError('Panel installer resource provenance is incomplete')
            expected[key]=dict(pin)
        expected['files']=[dict(row,**expected['installer_resource']) if row['path']==PANEL_INSTALLER_RESOURCE else row for row in expected['files']]
    if provenance != expected:raise ValueError('Panel generated source provenance differs')
    output = Path(output)
    if output.is_symlink() or output.is_junction() or not output.is_dir():
        raise ValueError('Panel projection is not an ordinary directory')
    if any(parent.is_symlink() or parent.is_junction() for parent in output.parents):
        raise ValueError('linked Panel projection parent')
    actual = []
    directories = set()
    for path in sorted(output.rglob('*')):
        info = path.lstat()
        if path.is_symlink() or path.is_junction():raise ValueError('linked Panel projection member')
        if stat.S_ISDIR(info.st_mode):
            directories.add(path.relative_to(output).as_posix())
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:raise ValueError('special Panel projection member')
        pin = observed_file(path)
        actual.append(dict(path=path.relative_to(output).as_posix(),bytes=pin['bytes'],sha256=pin['sha256']))
    if sorted(actual,key=lambda row:row['path']) != expected['files']:
        raise ValueError('Panel projection files differ from exact generated source')
    implied = {'/'.join(row['path'].split('/')[:i]) for row in expected['files']
               for i in range(1,len(row['path'].split('/')))}
    if directories != implied:raise ValueError('Panel projection directories differ')


def go_cached_info(raw):
    """Exact RevInfo encoding written by the pinned Go module cache owner."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate module info field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if (not isinstance(value, dict) or set(value) - {'Version', 'Time', 'Origin'} or
            not isinstance(value.get('Version'), str) or not isinstance(value.get('Time'), str)):
        raise ValueError('unsupported Go module info')
    result = {'Version': value['Version'], 'Time': value['Time']}
    if 'Origin' in value:
        origin = value['Origin']
        keys = ('VCS', 'URL', 'Subdir', 'Hash', 'TagPrefix', 'TagSum', 'Ref', 'RepoSum')
        if (not isinstance(origin, dict) or set(origin) - set(keys) or
                any(not isinstance(item, str) for item in origin.values())):
            raise ValueError('unsupported Go module origin')
        result['Origin'] = {key: origin[key] for key in keys if origin.get(key)}
    # encoding/json.Marshal's compact object encoding and HTML-safe strings.
    encoded = json.dumps(result, ensure_ascii=False, separators=(',', ':'))
    for character, escaped in (('&', r'\u0026'), ('<', r'\u003c'), ('>', r'\u003e'),
                               ('\u2028', r'\u2028'), ('\u2029', r'\u2029')):
        encoded = encoded.replace(character, escaped)
    return encoded.encode('utf-8')


def observed_file(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError('observed build input/output must be an ordinary file: ' + str(path))
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return {'path': str(path.resolve()), 'sha256': digest.hexdigest(), 'bytes': path.stat().st_size}


def observed_input(path: Path) -> tuple[bytes, dict]:
    """Pin the bytes actually parsed, rather than a later file measurement."""
    if path.is_symlink() or not path.is_file():
        raise ValueError('observed input must be an ordinary file')
    data = path.read_bytes()
    return data, {'path': str(path.resolve()), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def observe_windows_builds(tools: Path, output: Path, provenance: Path,
                           runner: Runner | None = None, *, environment=None, receipt=None,
                           panel_source=None, phase='all', provider_images=None) -> dict:
    """Retain actual child exits, including failed/interrupted observations."""
    if receipt is not None and (receipt.exists() or receipt.is_symlink()):
        raise ValueError('observed build receipt must be new')
    state = {'schema': 1, 'status': 'running', 'commands': []}
    try:
        result = _observe_windows_builds(tools, output, provenance, runner, environment=environment,
                                        observation=state, panel_source=panel_source,
                                        phase=phase, provider_images=provider_images)
    except BaseException as error:
        state.update(status='failed', failure=type(error).__name__)
        if receipt is not None:
            receipt.write_text(json.dumps({'observed_windows_builds': state}, indent=2)+'\n', encoding='utf-8')
        raise
    if receipt is not None:
        receipt.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    return result


def _observe_windows_builds(tools: Path, output: Path, provenance: Path,
                            runner: Runner | None, *, environment, observation, panel_source=None,
                            phase='all', provider_images=None) -> dict:
    """Execute the fixed roster twice, retaining observed links and cache pins.

    Embedded modules describe the linked closure. Cache observations are not
    a claim to have traced every source-file read by the compiler.
    """
    provenance_bytes, provenance_pin = observed_input(provenance)
    tools_bytes, tools_pin = observed_input(tools)
    helpers = [observed_input(Path(__file__))[1], observed_input(Path(release_rows.__code__.co_filename))[1]]
    evidence = json.loads(provenance_bytes)
    if (evidence.get('schema') != 2 or evidence.get('kind') != 'prepared-module-provenance' or
            'observed_windows_builds' in evidence):
        raise ValueError('observed Windows builds require original prepared provenance')
    graph = evidence['graph']; staged_graph_rows(graph)
    producer = evidence['producer']
    env = dict(os.environ if environment is None else environment)
    if (not env.get('GOPROXY', '').startswith('file:///') or
            any(c in env['GOPROXY'] for c in ',|\r\n')):
        raise ValueError('observed Windows builds require the selected offline prepared proxy')
    location=urlsplit(env['GOPROXY'])
    proxy_path=url2pathname(location.path)
    if (location.scheme!='file' or location.netloc or location.query or location.fragment
            or proxy_path.startswith(('\\\\','//')) or '\x00' in proxy_path
            or not Path(proxy_path).is_absolute()):
        raise ValueError('observed Windows builds require a local prepared proxy directory')
    prepared_proxy=Path(proxy_path)
    if (producer != {'source': env.get('GITHUB_SHA'), 'run_id': int(env.get('GITHUB_RUN_ID', '0')),
                     'run_attempt': int(env.get('GITHUB_RUN_ATTEMPT', '0'))} or
            not re.fullmatch(r'[0-9a-f]{40}', str(producer['source'])) or
            any(type(producer[k]) is not int or producer[k] <= 0 for k in ('run_id', 'run_attempt'))):
        raise ValueError('observed producer identity differs from prepared provenance')
    tools_text = tools_bytes.decode('utf-8')
    rows = release_rows(tools_text, 'tools.tsv')
    read_modules(tools, text=tools_text)
    if phase not in ('all', 'providers', 'runtime'):
        raise ValueError('unknown observed build phase')
    if phase != 'all':
        helpers.append(observed_input(Path(_windows_build_owner().__file__))[1])
    if phase == 'runtime':
        if not isinstance(provider_images, dict) or set(provider_images) != {'amd64', 'arm64'}:
            raise ValueError('runtime build requires final signed provider images for both architectures')
        owner = _windows_build_owner()
        records = {arch: owner.encode_shipped_provider_images(images)
                   for arch, images in provider_images.items()}
        provider_images = {arch: owner.decode_shipped_provider_images(encoded)
                           for arch, encoded in records.items()}
    elif provider_images is not None:
        raise ValueError('provider image inputs belong to the final runtime build')
    if phase != 'all':
        rows = [row for row in rows if runtime_program(row) == (phase == 'runtime')]
        if not rows:
            raise ValueError('observed build phase has no selected programs')
    if len({row[0].lower() for row in rows}) != len(rows):
        raise ValueError('observed Windows output names collide')
    for name, module, package, _, subsystem in rows:
        if (not re.fullmatch(r'[A-Za-z0-9_. -]+\.exe', name) or name in ('.exe', '..exe') or
                any(p in ('', '.', '..') or not re.fullmatch(r'[A-Za-z0-9_.-]+', p)
                    for p in module.rsplit('@', 1)[0].split('/')) or
                (package != '.' and any(not re.fullmatch(r'[A-Za-z0-9_-]+', p) for p in package.split('/'))) or
                subsystem not in ('console', 'windows')):
            raise ValueError('invalid observed Windows program roster')
    panel_rows = [row for row in rows if row[1].rsplit('@',1)[0] == PANEL_MODULE
                  and row[0] == 'Abstraction Panel.exe']
    if panel_rows and (panel_source is None or any(row[2] != '.' for row in panel_rows)):
        raise ValueError('Windows amd64 Panel requires authenticated generated catalogue source')
    output = output.resolve()
    owned = output / '.observed-windows-build'
    if any(p.exists() or p.is_symlink() for p in (output / 'a', output / 'b', owned)):
        raise ValueError('observed build destinations must be new; preserve previous attempts')
    executable = shutil.which('go', path=env.get('PATH'))
    if executable is None:
        raise ValueError('selected Go executable is missing')
    go = str(Path(executable).resolve()); runner = runner or run
    executable_pin = observed_file(Path(go))
    calls = observation['commands']
    observation.update(producer=producer, provenance=provenance_pin, tools=tools_pin, helpers=helpers)
    def command(argv, selected):
        try:
            # A child receives selected values, never a mutable owner dictionary.
            result = runner(argv, env=dict(selected))
        except BaseException as error:
            calls.append({'argv': list(argv), 'exit_code': None, 'failure': type(error).__name__})
            raise
        record = {'argv': list(argv), 'exit_code': result.returncode,
                  'stdout': result.stdout or '', 'stderr': result.stderr or ''}
        calls.append(record)
        if result.returncode:
            raise RuntimeError('observed build command failed: ' + repr(argv))
        return record
    env.update(GOENV='off', GOTOOLCHAIN='local', GOWORK='off', GOOS='windows',
               CGO_ENABLED='0', GOFLAGS='-trimpath', GOSUMDB='off', GOPRIVATE='', GONOPROXY='')
    for key in ('GOBIN', 'GOCACHEPROG'):
        env.pop(key, None)
    info = json.loads(command([go, 'env', '-json', 'GOROOT', 'GOTOOLDIR', 'GOHOSTOS',
                               'GOHOSTARCH', 'GOVERSION', 'GOMODCACHE', 'GOCACHE'], env)['stdout'])
    env.update(GOMODCACHE=info['GOMODCACHE'], GOCACHE=info['GOCACHE'], GOPATH=str(owned / 'gopath'))
    suffix = '.exe' if info['GOHOSTOS'] == 'windows' else ''
    tool_pins = {name: observed_file(Path(info['GOTOOLDIR']) / (name + suffix))
                 for name in ('compile', 'link', 'asm')}
    compiler = {'executable': executable_pin, 'tools': tool_pins,
                'environment': info, 'version': command([go, 'version'], env)}
    observation['compiler'] = compiler
    expected = {r['module']: r for r in graph['modules'] + graph.get('dependencies', [])}
    graph_files = {r['path']: r for r in graph['files']}
    # A published library module does not establish that a new command exists
    # in that version. Admit each roster package before any install/build call.
    for name, module_version, package, _, subsystem in rows:
        module, version = module_version.rsplit('@', 1)
        tags = program_tags(name, module, package, subsystem)
        if tags and tags != ['-tags', _windows_build_owner().GO_TAGS['tools/' + name]]:
            raise ValueError('Presenter build tag differs from existing monitor owner')
        if module not in expected or expected[module]['version'] != version:
            raise ValueError('program module differs from prepared graph')
        member = escape_module(module) + '/@v/' + version + '.zip'
        # The prepared proxy is complete before the first build. Go fills its
        # download cache on demand; that cache is observed independently below.
        raw, pin = observed_input(prepared_proxy / member)
        wanted = graph_files['proxy/' + member]
        if any(pin[key] != wanted[key] for key in ('sha256', 'bytes')):
            raise ValueError('program module archive differs from prepared graph')
        require_program_package(raw, module, version, package)
    programs = []
    observation['programs'] = programs
    for pass_name in ('a', 'b'):
        for arch in ('amd64', 'arm64'):
            selected = dict(env, GOARCH=arch)
            for name, module_version, package, feature, subsystem in platform_tools(rows, 'windows', arch):
                module, version = module_version.rsplit('@', 1)
                if module not in expected or expected[module]['version'] != version:
                    raise ValueError('program module differs from prepared graph')
                target = module + ('' if package == '.' else '/' + package) + '@' + version
                flags = '-s -w -buildid=' + (' -H=windowsgui' if subsystem == 'windows' else '')
                if phase == 'runtime' and records[arch]:
                    flags += ' -X main.shippedProviderImages=' + records[arch]
                destination = output / pass_name / arch / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                projected = module == PANEL_MODULE and arch == 'amd64' and name == 'Abstraction Panel.exe'
                projection = None
                if projected:
                    source = owned / (pass_name + '-panel-source')
                    source.parent.mkdir(parents=True,exist_ok=True)
                    arguments = dict(panel_source)
                    module_zip, catalogue_path = arguments.pop('module_zip'), arguments.pop('catalogue_path')
                    if arguments['module_row'] != expected[module] or arguments['producer'] != producer:
                        raise ValueError('Panel source selection differs from prepared producer')
                    archive_row = graph_files['proxy/'+escape_module(module) + '/@v/' + version + '.zip']
                    if arguments['expected_archive'] != {key:archive_row[key] for key in ('bytes','sha256')}:
                        raise ValueError('Panel original module archive differs from prepared graph')
                    projection = prepare_panel_source(module_zip,catalogue_path,source,**arguments,resource_environment=dict(selected,GOROOT=info['GOROOT']))
                    link = command([go,'-C',str(source),'build','-ldflags',flags,'-o',str(destination),'.'],selected)
                    verify_panel_source(source,projection,module_zip=module_zip,catalogue_path=catalogue_path,**arguments)
                else:
                    link = command([go, 'install', *program_tags(name, module, package, subsystem), '-ldflags', flags, target], selected)
                    binary = Path(selected['GOPATH']) / 'bin'
                    if [info['GOHOSTOS'], info['GOHOSTARCH']] != ['windows', arch]:
                        binary /= 'windows_' + arch
                    binary /= (module if package == '.' else package).rsplit('/', 1)[-1] + '.exe'
                    shutil.copyfile(binary, destination)
                    binary.unlink()  # Only the exact file in this task-owned GOPATH.
                record_sha = (_windows_build_owner().verify_shipped_runtime_record(destination, provider_images[arch])
                              if phase == 'runtime' else None)
                metadata = command([go, 'version', '-m', str(destination)], selected)
                consumed = []
                for line in metadata['stdout'].splitlines():
                    fields = line.strip().split('\t')
                    if fields[0] == '=>':
                        raise ValueError('observed program uses a replaced module')
                    if fields[0] not in ('mod', 'dep'):
                        continue
                    if projected and fields[0] == 'mod':
                        if fields != ['mod',module,'(devel)']:
                            raise ValueError('projected Panel root metadata differs')
                        # The original root remains independently pinned in the projection.
                        fields = ['mod',module,version,expected[module]['sum']]
                    if len(fields) != 4:
                        raise ValueError('observed program lacks immutable module checksum')
                    _, path, actual_version, actual_sum = fields
                    row = expected.get(path)
                    if not row or (actual_version, actual_sum) != (row['version'], row['sum']):
                        raise ValueError('linked module differs from prepared closure')
                    if projected and fields[0] == 'mod':
                        consumed.append({'module': path, 'version': actual_version, 'sum': actual_sum,
                                         'gomodsum': row['gomodsum'], 'panel_source': projection})
                        continue
                    prefix = escape_module(path) + '/@v/' + actual_version
                    cached = []
                    info_source = None
                    for extension in ('.zip', '.mod', '.info'):
                        pin = observed_file(Path(info['GOMODCACHE']) / 'cache/download' / (prefix + extension))
                        wanted = graph_files['proxy/' + prefix + extension]
                        if any(pin[k] != wanted[k] for k in ('sha256', 'bytes')):
                            if extension != '.info':
                                raise ValueError('consumed cached module differs from prepared bytes')
                            source_raw, source_pin = observed_input(prepared_proxy / (prefix + extension))
                            if any(source_pin[k] != wanted[k] for k in ('sha256', 'bytes')):
                                raise ValueError('prepared module info changed')
                            normalized = go_cached_info(source_raw)
                            if (pin['bytes'], pin['sha256']) != (len(normalized), hashlib.sha256(normalized).hexdigest()):
                                raise ValueError('consumed cached module info differs from prepared fields')
                            info_source = source_raw.decode('utf-8')
                        cached.append(pin)
                    ziphash = Path(info['GOMODCACHE']) / 'cache/download' / (prefix + '.ziphash')
                    if ziphash.read_text(encoding='utf-8').strip() != actual_sum:
                        raise ValueError('cached Go h1 differs from embedded module')
                    consumed.append({'module': path, 'version': actual_version, 'sum': actual_sum,
                                     'gomodsum': row['gomodsum'], 'cache_files': cached,
                                     'ziphash': observed_file(ziphash),
                                     **({'info_source': info_source} if info_source is not None else {})})
                if not consumed or consumed[0]['module'] != module:
                    raise ValueError('observed root module is missing or differs')
                program = {'pass': pass_name, 'arch': arch, 'name': name, 'module': module_version,
                    'package': package, 'feature': feature, 'subsystem': subsystem, 'link': link,
                    'metadata': metadata, 'artifact': observed_file(destination), 'consumed': consumed}
                if record_sha is not None and program['artifact']['sha256'] != record_sha:
                    raise ValueError('observed runtime changed after shipped record readback')
                if projected:
                    verify_panel_source(source,projection,module_zip=module_zip,catalogue_path=catalogue_path,**arguments)
                    program['panel_source'] = projection
                programs.append(program)
    for arch in ('amd64', 'arm64'):
        for name, *_ in platform_tools(rows, 'windows', arch):
            if not filecmp.cmp(output / 'a' / arch / name, output / 'b' / arch / name, shallow=False):
                raise ValueError('observed Windows builds are not byte-identical: ' + name)
    if compiler['executable'] != observed_file(Path(go)) or any(
            pin != observed_file(Path(pin['path'])) for pin in tool_pins.values()):
        raise ValueError('compiler tool inputs changed during observed builds')
    retained = [tools_pin, provenance_pin, *helpers]
    for program in programs:
        retained.append(program['artifact'])
        for module in program['consumed']:
            if 'panel_source' not in module:
                retained.extend([*module['cache_files'], module['ziphash']])
    if any(pin != observed_file(Path(pin['path'])) for pin in retained):
        raise ValueError('consumed input or output changed during observed builds')
    result = dict(evidence, observed_windows_builds={'schema': 1, 'status': 'complete', 'producer': producer,
        'provenance': provenance_pin, 'tools': tools_pin, 'helpers': helpers, 'compiler': compiler,
        'environment': {k: env[k] for k in ('GOENV', 'GOTOOLCHAIN', 'GOWORK', 'GOOS', 'CGO_ENABLED',
            'GOFLAGS', 'GOMODCACHE', 'GOCACHE', 'GOPATH', 'GOPROXY', 'GOSUMDB', 'GONOSUMDB',
            'GOPRIVATE', 'GONOPROXY', 'GOEXPERIMENT', 'GOAMD64', 'GOARM64', 'GOMAXPROCS') if k in env},
        'programs': programs, 'commands': calls, 'reproducible': True,
        'consumption_scope': 'embedded linked modules joined to actual cached zip/mod/info; not a source-file access trace'})
    if phase != 'all':
        result['observed_windows_builds']['phase'] = phase
    if phase == 'runtime':
        result['observed_windows_builds']['provider_images'] = provider_images
    return result


def admit_observed_windows_builds(original_bytes: bytes, observed_bytes: bytes, *,
        expected_graph: dict, expected_archive: dict, tools_bytes: bytes,
        expected_producer: dict, expected_helpers: list[dict], sdk_facts: dict,
        expected_panel_source=None, phase='all', expected_provider_images=None) -> list[dict]:
    """Admit hosted observations as unsigned facts; never open hosted paths.

    The caller authenticates the transport and supplies current prepared inputs
    and SDK-owner facts. Returned pins still require the signed-byte join.
    """
    def fail(message):
        raise ValueError('observed Windows admission: ' + message)

    def load(raw):
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result: fail('duplicate JSON member')
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=pairs)

    def pin(value):
        if (not isinstance(value, dict) or set(value) != {'path', 'sha256', 'bytes'} or
                not isinstance(value['path'], str) or not value['path'] or
                not re.fullmatch('[0-9a-f]{64}', str(value['sha256'])) or
                type(value['bytes']) is not int or value['bytes'] < 0):
            fail('invalid file observation')
        return {k: value[k] for k in ('sha256', 'bytes')}

    def raw_pin(raw):
        return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}

    def command(value, argv):
        if (not isinstance(value, dict) or set(value) != {'argv', 'exit_code', 'stdout', 'stderr'} or
                value['argv'] != argv or type(value['exit_code']) is not int or value['exit_code'] != 0 or
                not all(isinstance(value[k], str) for k in ('stdout', 'stderr'))):
            fail('unsuccessful or unexpected command')

    # Validate independent inputs before allowing proof rows to name expectations.
    staged_graph_rows(expected_graph)
    all_modules = expected_graph['modules'] + expected_graph.get('dependencies', [])
    modules = {row['module']: row for row in all_modules}
    graph_files = {row['path']: row for row in expected_graph['files']}
    if (set(expected_producer) != {'source', 'run_id', 'run_attempt'} or
            not re.fullmatch('[0-9a-f]{40}', str(expected_producer['source'])) or
            any(type(expected_producer[k]) is not int or expected_producer[k] <= 0
                for k in ('run_id', 'run_attempt'))):
        fail('expected producer')
    original, observed = load(original_bytes), load(observed_bytes)
    verification = {'schema': 1, 'source': expected_graph['source'], 'version': expected_graph['version'],
        'modules': [{k: row[k] for k in ('module', 'version', 'sum', 'gomodsum', 'commit') if k in row}
                    for row in all_modules]}
    if (set(original) != {'schema', 'kind', 'graph', 'verification', 'archive', 'producer', 'publication_admitted'} or
            type(original['schema']) is not int or original['schema'] != 2 or
            original['kind'] != 'prepared-module-provenance' or original['graph'] != expected_graph or
            original['verification'] != verification or original['archive'] != expected_archive or
            original['producer'] != expected_producer or original['publication_admitted'] is not False or
            set(observed) != set(original) | {'observed_windows_builds'} or
            any(observed[k] != value for k, value in original.items())):
        fail('prepared inputs or producer differ')
    build = observed['observed_windows_builds']
    phase_fields = ({'phase'} if phase != 'all' else set()) | ({'provider_images'} if phase == 'runtime' else set())
    if phase not in ('all', 'providers', 'runtime') or (phase != 'all' and build.get('phase') != phase):
        fail('build phase')
    if phase == 'runtime':
        if (not isinstance(expected_provider_images, dict) or set(expected_provider_images) != {'amd64', 'arm64'}
                or build.get('provider_images') != expected_provider_images):
            fail('final signed provider inputs')
        owner = _windows_build_owner()
        records = {arch: owner.encode_shipped_provider_images(images)
                   for arch, images in expected_provider_images.items()}
    if (set(build) != {'schema', 'status', 'producer', 'provenance', 'tools', 'helpers', 'compiler',
                      'environment', 'programs', 'commands', 'reproducible', 'consumption_scope'} | phase_fields or
            type(build['schema']) is not int or build['schema'] != 1 or build['status'] != 'complete' or
            build['reproducible'] is not True or build['producer'] != expected_producer or
            pin(build['provenance']) != raw_pin(original_bytes) or pin(build['tools']) != raw_pin(tools_bytes) or
            build['consumption_scope'] != 'embedded linked modules joined to actual cached zip/mod/info; not a source-file access trace'):
        fail('incomplete observations or consumed input pins')
    if ([pin(p) for p in build['helpers']] != [pin(p) for p in expected_helpers] or
            len(build['helpers']) != (2 if phase == 'all' else 3)):
        fail('source helper pins')
    compiler = build['compiler']; info = compiler['environment']; go = compiler['executable']['path']
    if (set(compiler) != {'executable', 'tools', 'environment', 'version'} or
            set(compiler['tools']) != {'compile', 'link', 'asm'} or
            pin(compiler['executable']) != sdk_facts['tools']['go'] or
            any(pin(compiler['tools'][k]) != sdk_facts['tools'][k] for k in ('compile', 'link', 'asm')) or
            set(info) != {'GOROOT', 'GOTOOLDIR', 'GOHOSTOS', 'GOHOSTARCH', 'GOVERSION', 'GOMODCACHE', 'GOCACHE'} or
            any(not isinstance(v, str) or not v for v in info.values()) or
            (info['GOHOSTOS'] + '/' + info['GOHOSTARCH'], info['GOVERSION']) != (sdk_facts['host'], sdk_facts['version'])):
        fail('compiler source facts')
    # Normalize separators only to compare hosted strings, never for filesystem use.
    remote = lambda p: p.replace('\\', '/').rstrip('/')
    if (remote(go) != remote(info['GOROOT']) + '/bin/go.exe' or
            remote(info['GOTOOLDIR']) != remote(info['GOROOT']) + '/pkg/tool/windows_amd64' or
            any(remote(compiler['tools'][k]['path']) != remote(info['GOTOOLDIR']) + '/' + k + '.exe'
                for k in ('compile', 'link', 'asm'))):
        fail('compiler path observations disagree')
    command(compiler['version'], [go, 'version'])
    if compiler['version']['stdout'].strip() != 'go version ' + sdk_facts['version'] + ' ' + sdk_facts['host']:
        fail('compiler version')
    env = build['environment']
    fixed = {'GOENV': 'off', 'GOTOOLCHAIN': 'local', 'GOWORK': 'off', 'GOOS': 'windows',
             'CGO_ENABLED': '0', 'GOFLAGS': '-trimpath', 'GOSUMDB': 'off', 'GOPRIVATE': '', 'GONOPROXY': ''}
    if (not set(fixed) <= set(env) or any(env[k] != v for k, v in fixed.items()) or
            set(env) - set(fixed) - {'GOMODCACHE', 'GOCACHE', 'GOPATH', 'GOPROXY', 'GONOSUMDB', 'GOEXPERIMENT', 'GOAMD64', 'GOARM64', 'GOMAXPROCS'} or
            any(not isinstance(v, str) for v in env.values()) or
            not env.get('GOPROXY', '').startswith('file:///') or any(c in env['GOPROXY'] for c in ',|\r\n') or
            any(env.get(k) != info[k] for k in ('GOMODCACHE', 'GOCACHE')) or not env.get('GOPATH') or
            any(env.get(k, '') not in ('', value) for k, value in [('GOAMD64', 'v1'), ('GOARM64', 'v8.0')]) or
            env.get('GOEXPERIMENT', '') != ''):
        fail('selected build environment')
    rows = release_rows(tools_bytes.decode('utf-8'), 'tools.tsv')
    if phase != 'all':
        rows = [row for row in rows if runtime_program(row) == (phase == 'runtime')]
    if (not rows or len({r[0].lower() for r in rows}) != len(rows) or
            any(not re.fullmatch(r'[A-Za-z0-9_. -]+\.exe', r[0]) or r[0] in ('.exe', '..exe')
                for r in rows)): fail('roster collision or invalid output')
    wanted = [(p, arch, row) for p in ('a', 'b') for arch in ('amd64', 'arm64')
              for row in platform_tools(rows, 'windows', arch)]
    if len(build['programs']) != len(wanted): fail('program inventory')
    commands = build['commands']
    if len(commands) != 2 + len(wanted) * 2: fail('command inventory')
    command(commands[0], [go, 'env', '-json', 'GOROOT', 'GOTOOLDIR', 'GOHOSTOS', 'GOHOSTARCH', 'GOVERSION', 'GOMODCACHE', 'GOCACHE'])
    if load(commands[0]['stdout']) != info or commands[1] != compiler['version']: fail('compiler command observations')
    output = {}; root_prefix = None
    for index, (program, (pass_name, arch, row)) in enumerate(zip(build['programs'], wanted)):
        name, module_version, package, feature, subsystem = row
        module, version = module_version.rsplit('@', 1)
        projected = module == PANEL_MODULE and arch == 'amd64' and name == 'Abstraction Panel.exe'
        if projected and (expected_panel_source is None or program.get('panel_source') != expected_panel_source):
            fail('missing or different generated Panel source')
        if (set(program) != {'pass', 'arch', 'name', 'module', 'package', 'feature', 'subsystem', 'link', 'metadata', 'artifact', 'consumed'} | ({'panel_source'} if projected else set()) or
                [program[k] for k in ('pass', 'arch', 'name', 'module', 'package', 'feature', 'subsystem')] !=
                [pass_name, arch, name, module_version, package, feature, subsystem] or subsystem not in ('console', 'windows') or
                module not in modules or modules[module]['version'] != version): fail('program identity')
        flags = '-s -w -buildid=' + (' -H=windowsgui' if subsystem == 'windows' else '')
        if phase == 'runtime' and records[arch]:
            flags += ' -X main.shippedProviderImages=' + records[arch]
        target = module + ('' if package == '.' else '/' + package) + '@' + version
        if projected:
            if package != '.' or expected_panel_source['module'] != modules[module] or expected_panel_source['producer'] != expected_producer:
                fail('generated Panel owner identity')
            link = program['link']['argv']
            # The owned projection is separate from the immutable module cache.
            suffix_source = '/.observed-windows-build/'+pass_name+'-panel-source'
            if len(link) != 9 or not remote(link[2]).endswith(suffix_source):fail('Panel source link path')
            command(program['link'],[go,'-C',link[2],'build','-ldflags',flags,'-o',program['artifact']['path'],'.'])
        else:
            command(program['link'], [go, 'install', *program_tags(name, module, package, subsystem), '-ldflags', flags, target])
        artifact = program['artifact']; artifact_pin = pin(artifact)
        suffix = '/' + pass_name + '/' + arch + '/' + name
        if not remote(artifact['path']).endswith(suffix): fail('output path observation')
        prefix = remote(artifact['path'])[:-len(suffix)]
        if root_prefix is None: root_prefix = prefix
        if (not prefix or prefix != root_prefix or artifact_pin['bytes'] == 0 or
                remote(env['GOPATH']) != prefix + '/.observed-windows-build/gopath'):
            fail('output roots differ')
        if projected and remote(program['link']['argv'][2]) != prefix + suffix_source:
            fail('Panel projection is outside the owned build root')
        command(program['metadata'], [go, 'version', '-m', artifact['path']])
        if commands[2+index*2:4+index*2] != [program['link'], program['metadata']]: fail('command sequence')
        embedded = []
        for line in program['metadata']['stdout'].splitlines():
            fields = line.strip().split('\t')
            if fields[0] == '=>': fail('replaced embedded module')
            if fields[0] not in ('mod', 'dep'): continue
            if projected and fields[0] == 'mod':
                if fields != ['mod',module,'(devel)']:fail('generated Panel embedded root')
                fields = ['mod',module,version,modules[module]['sum']]
            if len(fields) != 4 or fields[0] != ('mod' if not embedded else 'dep'): fail('embedded module shape')
            embedded.append(fields[1:])
        if (not embedded or embedded[0][0] != module or len({r[0] for r in embedded}) != len(embedded) or
                len(program['consumed']) != len(embedded)): fail('linked module inventory')
        for consumed, (path, actual_version, actual_sum) in zip(program['consumed'], embedded):
            selected = modules.get(path)
            if 'panel_source' in consumed:
                if (not projected or path != module or set(consumed) != {'module', 'version', 'sum', 'gomodsum', 'panel_source'} or
                        selected is None or
                        [consumed[k] for k in ('module', 'version', 'sum', 'gomodsum')] !=
                        [module, version, selected['sum'], selected['gomodsum']] or
                        consumed['panel_source'] != expected_panel_source): fail('projected root source')
                continue
            if (selected is None or (actual_version, actual_sum) != (selected['version'], selected['sum']) or
                    set(consumed) not in ({'module', 'version', 'sum', 'gomodsum', 'cache_files', 'ziphash'},
                                          {'module', 'version', 'sum', 'gomodsum', 'cache_files', 'ziphash', 'info_source'}) or
                    [consumed[k] for k in ('module', 'version', 'sum', 'gomodsum')] !=
                    [path, actual_version, actual_sum, selected['gomodsum']] or len(consumed['cache_files']) != 3): fail('consumed module')
            cache_prefix = escape_module(path) + '/@v/' + actual_version
            for cached, extension in zip(consumed['cache_files'], ('.zip', '.mod', '.info')):
                expected = graph_files.get('proxy/' + cache_prefix + extension)
                wanted = {k: expected[k] for k in ('sha256', 'bytes')} if expected else None
                if extension == '.info' and 'info_source' in consumed:
                    raw = consumed['info_source']
                    if not isinstance(raw, str) or len(raw) > 65536: fail('module info source')
                    raw = raw.encode('utf-8')
                    if wanted != {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}: fail('module info source pin')
                    normalized = go_cached_info(raw)
                    wanted = {'bytes': len(normalized), 'sha256': hashlib.sha256(normalized).hexdigest()}
                if (not expected or pin(cached) != wanted or
                        remote(cached['path']) != remote(env['GOMODCACHE']) + '/cache/download/' + cache_prefix + extension): fail('consumed cache pin')
            # The producer checks stripped text against h1. Retain the ziphash pin
            # as an observation; its bytes are not supplied by this small proof.
            pin(consumed['ziphash'])
            if remote(consumed['ziphash']['path']) != remote(env['GOMODCACHE']) + '/cache/download/' + cache_prefix + '.ziphash': fail('ziphash path')
        key = (arch, name)
        if pass_name == 'a':
            output[key] = {'arch': arch, 'name': name, 'module': module_version, 'package': package, **artifact_pin}
            if projected:output[key]['panel_source'] = expected_panel_source
        elif artifact_pin != {k: output[key][k] for k in ('sha256', 'bytes')}: fail('two-pass output differs')
    return list(output.values())


def staged_graph_rows(graph: dict) -> list[dict]:
    """Validate the public Go graph, without interpreting it as publication proof."""
    if (set(graph) != ({'schema', 'kind', 'source', 'version', 'modules', 'files'} | ({'dependencies'} if graph.get('schema') == 2 else set())) or
            type(graph['schema']) is not int or graph['schema'] not in (1, 2) or
            graph['kind'] != 'unpublished-go-graph' or
            not re.fullmatch(r'[0-9a-f]{40}', str(graph['source'])) or
            not VERSION.fullmatch(str(graph['version'])) or
            not isinstance(graph['modules'], list) or not graph['modules']):
        raise ValueError('invalid unpublished Go graph')
    rows, identities, commits = [], set(), {}
    for row in graph['modules']:
        if set(row) != {'module', 'version', 'repository', 'subdir', 'tag', 'commit', 'sum', 'gomodsum'}:
            raise ValueError('invalid staged module fields')
        if not isinstance(row['module'], str) or any(p in ('', '.', '..') or not re.fullmatch(r'[A-Za-z0-9_.-]+', p) for p in row['module'].split('/')):
            raise ValueError('invalid staged module path')
        repository, tag = repository_tag(row['module'], row['version'])
        subdir = row['module'][len(ORG):].partition('/')[2]
        if (row['version'] != graph['version'] or row['repository'] != repository or row['subdir'] != subdir or row['tag'] != tag or
                not re.fullmatch(r'[0-9a-f]{40}', str(row['commit'])) or
                any(not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', str(row[k])) for k in ('sum', 'gomodsum')) or
                row['module'] in identities):
            raise ValueError('staged module identity, tag prefix or checksum differs')
        if repository in commits and commits[repository] != row['commit']:
            raise ValueError('one prepared repository has conflicting commits')
        commits[repository] = row['commit']; identities.add(row['module']); rows.append(row)
    dependencies = graph.get('dependencies', [])
    if not isinstance(dependencies, list):
        raise ValueError('invalid qualified dependency roster')
    dependency_keys = set()
    for row in dependencies:
        if (set(row) != {'module', 'version', 'sum', 'gomodsum'} or not isinstance(row['module'], str) or
                not re.fullmatch(r'[a-z0-9.-]+\.[a-z0-9.-]+/[A-Za-z0-9_./!~-]+', row['module']) or
                any(p in ('', '.', '..', '.git') for p in row['module'].split('/')) or
                not IMMUTABLE.fullmatch(str(row['version'])) or
                (row['module'].startswith(ORG) and row['version'] == graph['version']) or
                any(not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', str(row[k])) for k in ('sum', 'gomodsum')) or
                (row['module'], row['version']) in dependency_keys or row['module'] in identities):
            raise ValueError('qualified public dependency identity/checksums differ')
        dependency_keys.add((row['module'], row['version']))
    if not isinstance(graph['files'], list) or not graph['files']:
        raise ValueError('staged graph has no exact file roster')
    expected, seen = set(), set()
    for row in rows + dependencies:
        prefix = 'proxy/' + escape_module(row['module']) + '/@v/'
        expected.update(prefix + row['version'] + suffix for suffix in ('.mod', '.info', '.zip'))
        expected.add(prefix + 'list')
    for entry in graph['files']:
        if (set(entry) != {'path', 'sha256', 'bytes'} or entry['path'] in seen or entry['path'] not in expected or
                not re.fullmatch(r'[0-9a-f]{64}', str(entry['sha256'])) or
                type(entry['bytes']) is not int or entry['bytes'] <= 0):
            raise ValueError('invalid staged graph file roster')
        seen.add(entry['path'])
    if seen != expected:
        raise ValueError('staged graph file roster is incomplete')
    return rows


def escape_module(module: str) -> str:
    """Go's module proxy escaping (repository_tag already validates identity)."""
    return ''.join('!' + ch.lower() if ch.isupper() else ch for ch in module)


def unpack_staged_graph(blob: bytes, destination: Path | None, expected: dict) -> dict:
    """Receive exact public bytes after the existing artifact owner bound them.

    expected is the source-owned prepared graph, not an admission supplied by a
    user. This function grants no trust to a manifest merely because it parses.
    """
    if len(blob) >= 80 * 1024**2:
        raise ValueError('public graph capsule exceeds its bounded transport size')
    if destination is not None and destination.exists():
        raise ValueError('staged graph destination must be new')
    staged_graph_rows(expected)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        infos = archive.infolist(); names = [i.filename for i in infos]
        if (len(names) != len(set(names)) or set(names) != {'graph.json', *(e['path'] for e in expected['files'])} or
                any(i.is_dir() or '\\' in i.filename or (i.external_attr >> 16) & 0o170000 == 0o120000 for i in infos) or
                sum(i.file_size for i in infos) >= 2 * 1024**3 or archive.getinfo('graph.json').file_size > 1024**2):
            raise ValueError('staged graph archive roster or bounds differ')
        graph = json.loads(archive.read('graph.json'))
        if graph != expected:
            raise ValueError('staged graph differs from the complete prepared graph')
        for entry in graph['files']:
            data = archive.read(entry['path'])
            if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
                raise ValueError('staged graph member changed: ' + entry['path'])
        for row in graph['modules'] + graph.get('dependencies', []):
            prefix = 'proxy/' + escape_module(row['module']) + '/@v/' + row['version']
            info = json.loads(archive.read(prefix + '.info'))
            if (info.get('Version') != row['version'] or ('commit' in row and (
                    (info.get('Origin') or {}).get('Hash') != row['commit'] or
                    (info.get('Origin') or {}).get('URL') != row['repository'] or
                    (info.get('Origin') or {}).get('Subdir', '') != row['subdir']))):
                raise ValueError('staged module prepared origin differs')
            with zipfile.ZipFile(io.BytesIO(archive.read(prefix + '.zip'))) as module_zip:
                module_infos = module_zip.infolist(); module_names = [entry.filename for entry in module_infos]; root = row['module'] + '@' + row['version'] + '/'
                if (len(module_names) != len(set(module_names)) or any((entry.external_attr >> 16) & 0o170000 == 0o120000 for entry in module_infos) or
                        any(not n.startswith(root) or '..' in n[len(root):].split('/') or '\\' in n for n in module_names)):
                    raise ValueError('invalid module ZIP entries')
                if module_zip.read(root + 'go.mod') != archive.read(prefix + '.mod'):
                    raise ValueError('staged module ZIP and go.mod disagree')
        if destination is not None:
            destination.mkdir(parents=True)
            for entry in graph['files']:
                path = destination / entry['path']; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(archive.read(entry['path']))
            (destination / 'graph.json').write_bytes(archive.read('graph.json'))
    return graph


def verify_staged_graph(graph: dict, proxy: Path, runner: Runner | None = None, *, environment=None) -> dict:
    """Let Go verify module h1 and go.mod h1 against this unpublished proxy."""
    rows = staged_graph_rows(graph) + graph.get('dependencies', [])
    runner = runner or run
    env = dict(os.environ, **(environment or {}))
    env.update(GOWORK='off', GOENV='off', GOTOOLCHAIN='local',
               GOPROXY=proxy.resolve().as_uri(), GOSUMDB='off', GOPRIVATE='', GONOPROXY='', GOFLAGS='-mod=readonly')
    records = []
    with tempfile.TemporaryDirectory(prefix='oa-staged-graph-') as tmp:
        env['GOMODCACHE'] = str(Path(tmp) / 'cache'); env['GOPATH'] = str(Path(tmp) / 'gopath')
        for row in rows:
            got = download(runner, row['module'], row['version'], tmp, env)
            if got.get('Path') != row['module'] or got.get('Version') != row['version'] or got['Sum'] != row['sum'] or got['GoModSum'] != row['gomodsum']:
                raise ValueError('staged Go checksums or selected identity differ')
            records.append({'module': row['module'], 'version': row['version'], 'sum': got['Sum'], 'gomodsum': got['GoModSum'], **({'commit': row['commit']} if 'commit' in row else {})})
    return {'schema': 1, 'source': graph['source'], 'version': graph['version'], 'modules': records}


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False, **kwargs)


def checked(runner: Runner, command: list[str], **kwargs) -> str:
    result = runner(command, **kwargs)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{' '.join(command)} failed ({result.returncode}): {detail}")
    return result.stdout


def json_values(raw: str):
    decoder = json.JSONDecoder()
    while raw.strip():
        value, end = decoder.raw_decode(raw.lstrip())
        yield value
        raw = raw.lstrip()[end:]


def read_modules(path: Path, *, text=None) -> list[tuple[str, str]]:
    modules = set()
    for fields in release_rows(path.read_text(encoding="utf-8") if text is None else text, "tools.tsv"):
        if "@" not in fields[1]:
            raise ValueError(f"invalid tools.tsv module: {fields[1]}")
        module, version = fields[1].rsplit("@", 1)
        if not module.startswith(ORG) or not VERSION.fullmatch(version):
            raise ValueError(f"module must name an OpenAbstractions semantic version: {fields[1]}")
        modules.add((module, version))
    if not modules:
        raise ValueError("tools.tsv names no program modules")
    return sorted(modules)


def repository_tag(module: str, version: str) -> tuple[str, str]:
    if not module.startswith(ORG) or not VERSION.fullmatch(version):
        raise ValueError(f"unsupported OpenAbstractions module version: {module}@{version}")
    rest = module[len(ORG):]
    repo, slash, subdir = rest.partition("/")
    if not repo or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
        raise ValueError(f"invalid repository in module path: {module}")
    return f"https://github.com/openabstractions/{repo}", f"{subdir + '/' if slash else ''}{version}"


def resolve_tag(runner: Runner, module: str, version: str) -> dict[str, str]:
    repository, tag = repository_tag(module, version)
    ref = f"refs/tags/{tag}"
    raw = checked(runner, ["git", "ls-remote", "--tags", repository, ref, ref + "^{}"])
    found = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in (ref, ref + "^{}") and re.fullmatch(r"[0-9a-f]{40}", parts[0]):
            found[parts[1]] = parts[0]
    if ref not in found:
        raise RuntimeError(f"missing public tag {repository} {tag}")
    commit = found.get(ref + "^{}", found[ref])
    return {"repository": repository, "tag": tag, "tag_object": found[ref], "commit": commit}


def download(runner: Runner, module: str, version: str, cwd: str, env: dict[str, str]) -> dict:
    raw = checked(runner, ["go", "mod", "download", "-json", f"{module}@{version}"], cwd=cwd, env=env)
    value = json.loads(raw)
    if value.get("Error") or value.get("Replace"):
        raise RuntimeError(f"download is replaced or unresolved: {module}@{version}")
    if not value.get("Sum") or not value.get("GoModSum"):
        raise RuntimeError(f"download lacks verified module and go.mod sums: {module}@{version}")
    return value


def verify(tools: Path, runner: Runner = run) -> dict:
    tools_text = tools.read_text(encoding="utf-8")
    programs = release_rows(tools_text, 'tools.tsv')
    env = dict(os.environ, GOWORK="off", GOFLAGS="-mod=readonly", GOTOOLCHAIN="local",
               GOPRIVATE="", GONOSUMDB="", GOSUMDB="sum.golang.org",
               GOPROXY="https://proxy.golang.org,direct")
    go_version = checked(runner, ["go", "version"], env=env).strip()
    records = []
    tag_cache: dict[tuple[str, str], dict[str, str]] = {}
    download_cache: dict[tuple[str, str], dict] = {}

    def cached_tag(path: str, version: str) -> dict[str, str]:
        key = (path, version)
        if key not in tag_cache:
            tag_cache[key] = resolve_tag(runner, path, version)
        return tag_cache[key]

    def cached_download(path: str, version: str, cwd: str) -> dict:
        key = (path, version)
        if key not in download_cache:
            download_cache[key] = download(runner, path, version, cwd, env)
        return download_cache[key]

    for requested, requested_version in read_modules(tools, text=tools_text):
        expected = cached_tag(requested, requested_version)
        with tempfile.TemporaryDirectory(prefix="oa-module-provenance-") as tmp:
            Path(tmp, "go.mod").write_text(
                f"module provenance.invalid/check\n\ngo 1.26\n\nrequire {requested} {requested_version}\n",
                encoding="utf-8")
            # Populate go.sum without permitting any go.mod edit, then inspect the selected graph.
            checked(runner, ["go", "mod", "download", "all"], cwd=tmp, env=env)
            selected = list(json_values(checked(runner, ["go", "list", "-m", "-json", "all"], cwd=tmp, env=env)))
            matches = [item for item in selected if item.get("Path") == requested]
            if len(matches) != 1 or matches[0].get("Version") != requested_version:
                raise RuntimeError(f"selected graph does not contain exact input {requested}@{requested_version}")
            closure = []
            for item in selected:
                if item.get("Replace") or item.get("Error"):
                    raise RuntimeError(f"selected module is replaced or unresolved: {item.get('Path')}")
                if item.get("Main"):
                    continue
                path, version = item.get("Path"), item.get("Version")
                if not path or not version or not IMMUTABLE.fullmatch(version):
                    raise RuntimeError(f"selected dependency lacks an immutable version: {path}@{version}")
                got = cached_download(path, version, tmp)
                row = {"path": path, "version": version, "sum": got["Sum"], "go_mod_sum": got["GoModSum"]}
                origin = got.get("Origin") or {}
                if path.startswith(ORG):
                    if path == APPROVED_PSEUDO_MODULE and version == APPROVED_PSEUDO_VERSION:
                        suffix = PSEUDO_VERSION.fullmatch(version).group(1)
                        repository = "https://github.com/openabstractions/websocket"
                        actual = origin.get("Hash")
                        if origin.get("VCS") != "git" or origin.get("URL") != repository:
                            raise RuntimeError(f"Origin repository mismatch for {path}@{version}: {origin}")
                        if (not isinstance(actual, str) or not re.fullmatch(r"[0-9a-f]{40}", actual)
                                or not actual.startswith(suffix) or actual != APPROVED_PSEUDO_COMMIT):
                            raise RuntimeError(f"Origin.Hash mismatch for {path}@{version}: expected {APPROVED_PSEUDO_COMMIT}, got {actual}")
                        row.update({"expected_commit": actual, "origin_hash": actual,
                                    "repository": repository, "pseudo_version_commit": suffix})
                    else:
                        tag = cached_tag(path, version)
                        actual = origin.get("Hash")
                        if actual != tag["commit"]:
                            raise RuntimeError(f"Origin.Hash mismatch for {path}@{version}: expected {tag['commit']}, got {actual}")
                        row.update({"expected_commit": tag["commit"], "origin_hash": actual,
                                    "repository": tag["repository"], "tag": tag["tag"]})
                closure.append(row)
            source = cached_download(requested, requested_version, tmp)
            archive = source.get('Zip')
            if not archive or not Path(archive).is_file():
                raise RuntimeError('selected program module lacks its verified source archive')
            raw = Path(archive).read_bytes()
            for fields in programs:
                if fields[1] == requested + '@' + requested_version:
                    require_program_package(raw, requested, requested_version, fields[2])
            records.append({"input": {"path": requested, "version": requested_version,
                                       "expected_commit": expected["commit"]}, "selected": closure})
    return {"schema": 1, "go_version": go_version, "tools": str(tools), "modules": records}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument('--prepared-graph', type=Path)
    parser.add_argument('--prepared-sidecar', type=Path)
    parser.add_argument('--release-version')
    parser.add_argument('--prepared-directory', type=Path)
    parser.add_argument('--workflow-environment', action='store_true')
    parser.add_argument('--observe-windows-builds', type=Path,
                        help='execute the fixed tools roster twice under this output root')
    parser.add_argument('--provenance', type=Path, help='existing prepared module provenance for observed builds')
    parser.add_argument('--build-phase', choices=('all', 'providers', 'runtime'), default='all')
    parser.add_argument('--provider-images', type=Path,
                        help='final signed provider SHA-256 images by architecture, for runtime linking')
    parser.add_argument('--panel-catalogue-directory',type=Path,
                        help='existing API-intake directory containing exact generated Panel build data')
    parser.add_argument('--panel-proxy',type=Path,help='verified prepared graph proxy containing the original module ZIP')
    parser.add_argument('--panel-apps',help='JSON list of independently selected current app-pin consumers')
    args = parser.parse_args()
    if args.observe_windows_builds is None and (args.build_phase != 'all' or args.provider_images is not None):
        parser.error('build phase and provider images require observed Windows builds')
    if args.observe_windows_builds is not None:
        if (args.tools is None or args.provenance is None or args.prepared_graph is not None or
                args.prepared_sidecar is not None or args.release_version is not None or
                args.prepared_directory is not None or args.workflow_environment or args.output.exists()):
            parser.error('observed Windows builds need tools, provenance and a new receipt output only')
        if (args.build_phase != 'runtime' and (Path(__file__).parent.parent/'windows/installer-prior-authorities.json').is_file()
                and any(row[1].rsplit('@',1)[0] == PANEL_MODULE for row in release_rows(args.tools.read_text(), 'tools.tsv'))
                and not (Path(__file__).parent.parent/'installer-priors.json').is_file()):
            raise ValueError('current RC Panel requires authenticated installer predecessor intake before compilation')
        panel_source=None
        panel_args=(args.panel_catalogue_directory,args.panel_proxy,args.panel_apps)
        if any(value is not None for value in panel_args):
            if any(value is None for value in panel_args):parser.error('Panel build input requires directory, proxy and selected apps together')
            original=json.loads(args.provenance.read_bytes())
            prior_path=Path(__file__).parent.parent/'installer-priors.json'
            prior_descriptor=json.loads(prior_path.read_bytes()) if prior_path.is_file() else None
            selected_wix=None
            if prior_descriptor is not None:
                selected_wix=shutil.which('wix')
                if not selected_wix:raise ValueError('pinned WiX is required before Panel predecessor extraction')
                selected_wix=str(Path(selected_wix).resolve())
            panel_source=select_panel_source(original['graph'],args.panel_proxy,args.panel_catalogue_directory,
                expected_producer=original['producer'],expected_apps=json.loads(args.panel_apps),
                expected_installer_priors=prior_descriptor,**({'history_wix':selected_wix} if selected_wix is not None else {}))
        evidence = observe_windows_builds(args.tools, args.observe_windows_builds, args.provenance,
            receipt=args.output,panel_source=panel_source,phase=args.build_phase,
            provider_images=json.loads(args.provider_images.read_bytes()) if args.provider_images else None)
    elif args.provenance is not None:
        parser.error('--provenance is only for observed Windows builds')
    elif any(value is not None for value in (args.panel_catalogue_directory,args.panel_proxy,args.panel_apps)):
        parser.error('Panel build data is only for observed Windows builds')
    elif args.prepared_graph is not None:
        if args.tools is not None or args.prepared_sidecar is None or not VERSION.fullmatch(args.release_version or ''):
            parser.error('prepared graph requires sidecar and exact release version, without --tools')
        if args.prepared_graph.stat().st_size >= 80 * 1024**2 or args.prepared_sidecar.stat().st_size > 1024**2:
            parser.error('prepared graph public input exceeds its bounds')
        graph = json.loads(args.prepared_sidecar.read_bytes())
        if graph['version'] != args.release_version:
            raise ValueError('prepared graph version differs from workflow input')
        if graph.get('schema') != 2:
            raise ValueError('workflow prepared mode requires complete offline closure schema 2')
        if args.prepared_directory is not None:
            directory = args.prepared_directory.resolve()
            unpack_staged_graph(args.prepared_graph.read_bytes(), directory, graph)
            evidence = verify_staged_graph(graph, directory / 'proxy')
        else:
            with tempfile.TemporaryDirectory(prefix='oa-staged-graph-') as tmp:
                directory = Path(tmp) / 'received'
                unpack_staged_graph(args.prepared_graph.read_bytes(), directory, graph)
                evidence = verify_staged_graph(graph, directory / 'proxy')
        evidence = {'schema': 2, 'kind': 'prepared-module-provenance', 'graph': graph, 'verification': evidence,
            'archive': {'bytes': args.prepared_graph.stat().st_size, 'sha256': hashlib.sha256(args.prepared_graph.read_bytes()).hexdigest()},
            'producer': {'source': os.environ.get('GITHUB_SHA'), 'run_id': int(os.environ.get('GITHUB_RUN_ID', '0')),
                         'run_attempt': int(os.environ.get('GITHUB_RUN_ATTEMPT', '0'))}, 'publication_admitted': False}
        if args.workflow_environment:
            if args.prepared_directory is None or not os.environ.get('GITHUB_ENV'):
                parser.error('workflow environment needs a retained prepared directory and GITHUB_ENV')
            with Path(os.environ['GITHUB_ENV']).open('a', encoding='utf-8') as stream:
                stream.write('GOPROXY=' + (directory / 'proxy').resolve().as_uri() + '\nGOSUMDB=off\nGOPRIVATE=\nGONOPROXY=\nGOENV=off\nGOTOOLCHAIN=local\n')
    else:
        if args.tools is None or args.prepared_sidecar is not None or args.release_version is not None or args.prepared_directory is not None or args.workflow_environment:
            parser.error('published provenance requires --tools')
        evidence = verify(args.tools)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
