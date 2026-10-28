#!/usr/bin/env python3
"""Inspect an unpublished OA app/source ZIP pair without executing the app.

The receipt records measured bytes, corresponding-source binding, licence
inventory, and absolute builder paths. A producer can attach this JSON beside
its two ZIPs; a reviewer can inspect local candidates before public pinning.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import zipfile


WINDOWS_BUILD_PATHS = (
    re.compile(rb"[A-Za-z]:\\(?:Users|a)\\[^\x00\r\n\"']{1,256}", re.I),
    re.compile(rb"[A-Za-z]:\\\\(?:Users|a)\\\\[^\x00\r\n\"']{1,256}", re.I),
    re.compile(rb"[A-Za-z]:/(?:Users|a)/[^\x00\r\n\"']{1,256}", re.I),
)
NOTICE = re.compile(r"(?:^|/)(?:[^/]*licen[cs]e[^/]*|[^/]*copying[^/]*|[^/]*notice[^/]*)$", re.I)
SCANNED_SUFFIXES = frozenset((".exe", ".dll", ".pyd", ".node", ".js", ".cjs", ".mjs",
                              ".json", ".ts", ".tsx", ".py", ".pth", ".cfg", ".ini",
                              ".yaml", ".yml", ".toml", ".ps1", ".bat", ".cmd"))


def digest(path: Path) -> tuple[int, str]:
    sha = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            sha.update(chunk)
            size += len(chunk)
    return size, sha.hexdigest()


ARCHIVE_PART_LIMIT = 2 << 30
ARCHIVE_PART_COUNT = 16
BACKEND_LOGICAL_LIMIT = 8 << 30
BACKEND_RUNTIME_MANIFEST_BYTES = 16 << 20
BACKEND_RUNTIME_ENTRIES = 65536
DESKTOP_CONTEXT_OTHER_BYTES = 4 << 20
DESKTOP_CONTEXT_WIRE_BYTES = BACKEND_RUNTIME_MANIFEST_BYTES + DESKTOP_CONTEXT_OTHER_BYTES
NATIVE_VARIANT = 'oa-comfyui-native'
NATIVE_HOST = 'launch-helper.exe'
NATIVE_BACKEND_ROOT = 'oa-backend'
NATIVE_CONTROL_ROOT = 'oa-control'
# Match backendlaunch.controlTree: its own manifest adds the final enginefiles row.
NATIVE_CONTROL_FILES = BACKEND_RUNTIME_ENTRIES-1
NATIVE_CONTROL_BYTES = 512<<20


def native_programs():
    """Source-owned archive members; application and service callers stay distinct."""
    return dict(application=NATIVE_HOST,
                service=NATIVE_BACKEND_ROOT+'/ComfyUI/custom_nodes/abstraction_downloads/helper/python.exe')


def native_record_terms(backend_manifest,control_manifest):
    """Logical atomic-record payload; installation adds actual final-root bytes."""
    constant=0
    for manifest in (backend_manifest,control_manifest):
        names=['manifest.json',*manifest['runtime_files']]
        constant+=121+sum(len(name.encode('utf-8'))+96 for name in names)
    return dict(record_bytes=2*constant,record_roots=[NATIVE_BACKEND_ROOT,NATIVE_CONTROL_ROOT])


def native_marker_bytes(archive,version):
    """Bound the existing format2 Go marker without its runtime cache locator."""
    files=[];directories=set()
    for entry in archive.infolist():
        if entry.is_dir():continue
        parts=entry.filename.split('/')
        directories.update('/'.join(parts[:index]) for index in range(1,len(parts)))
        files.append(dict(path=entry.filename,size=entry.file_size,sha256='0'*64))
    marker=dict(format=2,artifact_sha256='0'*64,version=version,install_identity=NATIVE_VARIANT,
        dirs=sorted(directories),files=files)
    # Go's compact Encoder HTML-escapes these characters and appends newline.
    # ASCII escaping bounds its UTF-8 encoding for every other Unicode scalar.
    raw=json.dumps(marker,ensure_ascii=True,separators=(',',':'))
    for char,escaped in (('&','\\u0026'),('<','\\u003c'),('>','\\u003e')):raw=raw.replace(char,escaped)
    return len(raw.encode('ascii'))+1


def inspect_native_delivery(root, binding, *, source, run_id, run_attempt, archive_directory=None):
    """Require the actual catalog archive when a native application has no MSI."""
    if not isinstance(binding,dict) or 'delivery' not in binding:
        raise ValueError('native application requires authenticated catalog delivery')
    delivery=binding['delivery']
    if (not isinstance(delivery,dict) or set(delivery)!={'variant','directory','binary','source','context'} or
            delivery['variant']!=NATIVE_VARIANT or not isinstance(delivery['directory'],str)):
        raise ValueError('native catalog delivery shape differs')
    root=Path(root).absolute();directory=root
    for part in delivery['directory'].split('/'):
        if (part in ('','.','..') or re.search(r'[<>:"\\|?*\x00-\x1f]',part) or
                part.endswith((' ','.')) or PureWindowsPath(part).is_reserved()):
            raise ValueError('unsafe native catalog delivery directory')
        directory=directory/part
        if archive_directory is None and (directory.is_symlink() or directory.resolve()!=directory or not directory.is_dir() or
                getattr(directory.lstat(),'st_file_attributes',0)&0x400):
            raise ValueError('native catalog delivery directory is linked or absent')
    if archive_directory is not None:
        # This owner is also loaded by filename from the signing receiver.
        # Receive its fixed sibling rather than depending on ambient PYTHONPATH.
        boundary_path=Path(__file__).with_name('file_boundary.py')
        if boundary_path.is_symlink() or boundary_path.is_junction() or not boundary_path.is_file():
            raise ValueError('native catalog boundary owner is missing or linked')
        boundary_spec=importlib.util.spec_from_file_location('native_catalog_file_boundary',boundary_path)
        boundary=importlib.util.module_from_spec(boundary_spec);boundary_spec.loader.exec_module(boundary)
        directory=Path(archive_directory)
        if not directory.is_absolute() or not boundary.same_existing_file(directory,root):
            raise ValueError('native catalog archive directory escapes its receiving root')
    producer={key:value for key,value in binding.items() if key!='delivery'}
    context=delivery['context']
    if (not isinstance(context,dict) or {'producer','backend_manifest','control_manifest'}&set(context) or
            len(json.dumps(context,sort_keys=True).encode('utf-8'))>=DESKTOP_CONTEXT_OTHER_BYTES):
        raise ValueError('native delivery context must retain bounded independent pins')
    if producer.get('source')!=source or producer.get('run_id')!=run_id or producer.get('run_attempt')!=run_attempt:
        raise ValueError('native catalog delivery producer differs')
    _archive_pin(delivery['binary'])
    binary=_ordinary_archive_file(directory,delivery['binary']['name'])
    selected=validate_backend_resource(context.get('backend'))['provenance']['manifest']
    with checked_zip(binary,bounded_members=True,expanded_limit=2<<30) as archive:
        entry=archive.getinfo(selected['name'])
        if entry.file_size!=selected['bytes']:raise ValueError('native delivery runtime metadata size differs')
        raw=archive.read(entry)
        if hashlib.sha256(raw).hexdigest()!=selected['sha256']:raise ValueError('native delivery runtime metadata pin differs')
        control=context['control_pin'];_archive_pin(dict(name='manifest.json',**control))
        if control['bytes']>BACKEND_RUNTIME_MANIFEST_BYTES:raise ValueError('native control metadata exceeds bound')
        entry=archive.getinfo(NATIVE_CONTROL_ROOT+'/manifest.json')
        if entry.file_size!=control['bytes']:raise ValueError('native control metadata size differs')
        control_raw=archive.read(entry)
        if hashlib.sha256(control_raw).hexdigest()!=control['sha256']:raise ValueError('native control metadata pin differs')
    context=dict(context,producer=producer,backend_manifest=json.loads(raw),control_manifest=json.loads(control_raw))
    actual=inspect_desktop_set(binary,directory,delivery['source'],
        desktop_context=context,require_clean_paths=True)
    if actual['binary']!=delivery['binary'] or actual['identity']['distribution']!=NATIVE_VARIANT:
        raise ValueError('native catalog delivery differs from actual selected archive')
    return actual


def native_control_inventory(expected):
    """The native controlTree's count/byte/path limits before payload effects."""
    if not isinstance(expected,dict) or set(expected)!={'runtime_files'}:
        raise ValueError('native control manifest has unexpected fields')
    files=expected['runtime_files']
    if (not isinstance(files,dict) or not 0<len(files)<=NATIVE_CONTROL_FILES
            or not {'python.exe','oa_native_host.py'}<=set(files)):
        raise ValueError('native control lacks complete runtime inventory')
    runtime_total=0
    for name,pin in files.items():
        if (not isinstance(name,str) or '\\' in name or name.startswith('/') or name=='manifest.json'
                or any(part in ('','..','.') or re.search(r'[<>:"|?*\x00-\x1f]',part)
                       or part.endswith((' ','.')) or PureWindowsPath(part).is_reserved() for part in name.split('/'))
                or not isinstance(pin,dict) or set(pin)!={'bytes','sha256'}
                or type(pin['bytes']) is not int or not 0<=pin['bytes']<=NATIVE_CONTROL_BYTES
                or not re.fullmatch('[0-9a-f]{64}',str(pin['sha256']))):raise ValueError('unsafe native control member')
        runtime_total+=pin['bytes']
        if runtime_total>NATIVE_CONTROL_BYTES:raise ValueError('native control exceeds native runtime byte bound')
    return files


def native_control_members(archive, control_pin, expected):
    """Receive the same exact small control roster at packaging and intake."""
    files=native_control_inventory(expected)
    if not isinstance(control_pin,dict) or set(control_pin)!={'bytes','sha256'}:
        raise ValueError('native control pin is incomplete')
    _archive_pin(dict(name='control-manifest.json',**control_pin))
    if control_pin['bytes']>BACKEND_RUNTIME_MANIFEST_BYTES:raise ValueError('native control manifest exceeds bound')
    name=NATIVE_CONTROL_ROOT+'/manifest.json'
    if archive.getinfo(name).file_size!=control_pin['bytes']:raise ValueError('native control manifest size differs')
    raw=archive.read(name)
    if (len(raw)!=control_pin['bytes'] or hashlib.sha256(raw).hexdigest()!=control_pin['sha256']
            or json.loads(raw)!=expected):raise ValueError('native control manifest differs from admitted resource')
    names={name}
    for name,pin in files.items():
        target=NATIVE_CONTROL_ROOT+'/'+name;entry=archive.getinfo(target)
        if entry.file_size!=pin['bytes']:raise ValueError('native control member size differs')
        digest=hashlib.sha256();size=0
        with archive.open(entry) as reader:
            for chunk in iter(lambda:reader.read(1<<20),b''):
                size+=len(chunk)
                if size>pin['bytes']:raise ValueError('native control member exceeds declared size')
                digest.update(chunk)
        if size!=pin['bytes'] or digest.hexdigest()!=pin['sha256']:raise ValueError('native control member hash/size differs')
        names.add(target)
    return names


def backend_policy_limits(policy):
    """The reviewed backend recipe budget is independent of legacy ZIP policy."""
    expected=dict(asset_bytes=2<<30,expanded_bytes=16<<30,archive_bytes=8<<30,
                  part_count=16,reserve_bytes=20<<30)
    limits=policy.get('limits') if isinstance(policy,dict) else None
    if (not isinstance(limits,dict) or set(limits)!=set(expected)
            or any(type(limits[key]) is not int or limits[key]!=value for key,value in expected.items())):
        raise ValueError('backend recipe capacity differs from reviewed policy')
    return limits


def validate_data_release(value, *, expected=None):
    """A source-selected immutable OA DATA location, independent of product tags."""
    if (not isinstance(value, dict) or set(value) != {'repository', 'tag'}
            or not isinstance(value['repository'], str)
            or not re.fullmatch(r'openabstractions/[A-Za-z0-9][A-Za-z0-9._-]*', value['repository'])
            or not isinstance(value['tag'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value['tag'])
            or value['tag'].casefold() in {'latest', 'main', 'master', 'default', 'head'}
            or expected is not None and value != expected):
        raise ValueError('backend DATA release requires an exact source-selected OA repository and tag')
    return value


def data_part_url(release, name):
    validate_data_release(release)
    _archive_pin(dict(name=name, bytes=1, sha256='0' * 64))
    return f"https://github.com/{release['repository']}/releases/download/{release['tag']}/{name}"


def validate_backend_resource(value, *, expected=None):
    fields = {'schema', 'variant', 'comfyui_ref', 'python_version', 'archive',
              'corresponding_source', 'data_release', 'provenance'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema']) is not int
            or value['schema'] != 2 or value['variant'] != 'win-amd'
            or not isinstance(value['comfyui_ref'], str) or not re.fullmatch('[0-9a-f]{40}', value['comfyui_ref'])
            or value['python_version'] != '3.13.17'):
        raise ValueError('invalid backend resource2')
    validate_data_release(value['data_release'])
    names = set()
    for key, format in (('archive', '7z'), ('corresponding_source', 'zip')):
        validate_archive_set(value[key], format=format)
        if value[key]['bytes'] > BACKEND_LOGICAL_LIMIT: raise ValueError('backend logical archive exceeds recipe budget')
        for part in value[key]['parts']:
            if part['name'].casefold() in names: raise ValueError('backend resource parts alias')
            names.add(part['name'].casefold())
    fixed = {'producer_receipt':'backend-producer.json','input_descriptor':'backend-inputs.json',
             'manifest':'backend-manifest.json','backend_policy':'backend-amd-v1.json'}
    if not isinstance(value['provenance'], dict) or set(value['provenance']) != set(fixed):
        raise ValueError('backend resource lacks its complete provenance')
    for key, name in fixed.items():
        pin = _archive_pin(value['provenance'][key])
        if pin['name'] != name or pin['bytes'] > (BACKEND_RUNTIME_MANIFEST_BYTES if key == 'manifest' else 4 << 20): raise ValueError('invalid backend provenance member')
    if expected is not None and value != expected: raise ValueError('backend resource differs from authenticated producer inputs')
    return value


def validate_corresponding_source(value):
    if not isinstance(value, dict) or set(value) != {'archive', 'data_release'}:
        raise ValueError('invalid corresponding-source offer')
    validate_archive_set(value['archive'], format='zip')
    if value['archive']['bytes'] > BACKEND_LOGICAL_LIMIT: raise ValueError('source logical archive exceeds budget')
    validate_data_release(value['data_release'])
    return value


def validate_embedded_integration(value, *, source_policy, oa_integration, backend_manifest, manifest,
                                  native=False):
    """Bind the custom Desktop's embedded wrapper to independently admitted inputs."""
    expected=dict(schema=1,distribution=NATIVE_VARIANT if native else 'oa-custom-desktop',source_policy=source_policy,
                  oa_integration=oa_integration,backend_manifest=backend_manifest)
    if (not isinstance(value,dict) or set(value)!=set(expected) or type(value.get('schema')) is not int
            or value!=expected):raise ValueError('embedded integration differs from selected Desktop inputs')
    _archive_pin(dict(name='desktop-source.json',**source_policy))
    _archive_pin(oa_integration)
    if _archive_pin(backend_manifest)['name']!='backend-manifest.json':
        raise ValueError('embedded integration lacks the fixed backend manifest')
    if (not isinstance(manifest,dict) or manifest.get('manager') is not False
            or manifest.get('python_version')!='3.13.17' or manifest.get('oa_integration')!=oa_integration):
        raise ValueError('embedded integration backend profile differs')
    prefix='ComfyUI/custom_nodes/abstraction_downloads/'
    required={'__init__.py','oa_connect.py','oa_relay.py','oa_helper.py','oa_interpreter.py',
              'oa_atomic/abstraction_cas.py','oa_nodes/__init__.py','oa_client/abstraction/ipc/__init__.py',
              'application-manifest.json','helper/python.exe','helper/python313.dll','helper/pyvenv.cfg'}
    files=manifest.get('runtime_files')
    if (not isinstance(files,dict) or not 0 < len(files) <= BACKEND_RUNTIME_ENTRIES
            or not {prefix+name for name in required}<=set(files)):
        raise ValueError('embedded integration complete wrapper is missing')
    for name in required:
        pin=files[prefix+name]
        if (not isinstance(pin,dict) or set(pin)!={'bytes','sha256'} or type(pin['bytes']) is not int
                or pin['bytes']<0 or not isinstance(pin['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',pin['sha256'])):
            raise ValueError('embedded integration wrapper file pin is invalid')
    raw=b'home = {backend}/standalone-env\ninclude-system-site-packages = false\n'
    template=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    if (manifest.get('helper_python_config')!=dict(name=prefix+'helper/pyvenv.cfg',template=template)
            or files[prefix+'helper/pyvenv.cfg']!=template
            or files[prefix+'helper/python.exe']!=files.get('standalone-env/python.exe')):
        raise ValueError('embedded integration helper derivation differs from the fixed source template')
    return value


def _archive_pin(value):
    if (not isinstance(value, dict) or set(value) != {'name', 'bytes', 'sha256'}
            or not isinstance(value['name'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', value['name'])
            or value['name'] in ('.', '..') or value['name'].endswith('.')
            or value['name'].split('.')[0].upper() in
                {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{n}' for n in range(1, 10)), *(f'LPT{n}' for n in range(1, 10))}
            or type(value['bytes']) is not int or value['bytes'] <= 0
            or not isinstance(value['sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', value['sha256'])):
        raise ValueError('invalid archive pin')
    return value


def validate_archive_set(value, *, format):
    """Closed private transport descriptor; hashes confer no producer authority."""
    if (format not in ('7z', 'zip') or not isinstance(value, dict)
            or set(value) != {'name', 'bytes', 'sha256', 'format', 'parts'}):
        raise ValueError('invalid archive set')
    logical = _archive_pin({key: value[key] for key in ('name', 'bytes', 'sha256')})
    parts = value['parts']
    if (value['format'] != format or not logical['name'].endswith('.' + format)
            or not isinstance(parts, list) or not 1 <= len(parts) <= ARCHIVE_PART_COUNT):
        raise ValueError('invalid archive format or part count')
    names = set()
    total = 0
    for index, part in enumerate(parts, 1):
        _archive_pin(part)
        expected = logical['name'] if len(parts) == 1 else logical['name'] + f'.{index:03d}'
        if (part['name'] != expected or part['name'].casefold() in names
                or part['bytes'] >= ARCHIVE_PART_LIMIT):
            raise ValueError('invalid archive part name, order or size')
        names.add(part['name'].casefold())
        total += part['bytes']
    if total != logical['bytes'] or len(parts) == 1 and parts[0] != logical:
        raise ValueError('archive logical identity differs from parts')
    return value


def _ordinary_archive_file(directory, name):
    directory = Path(directory).absolute()
    if directory.is_symlink() or directory.resolve() != directory or not directory.is_dir():
        raise ValueError('archive directory must be an ordinary absolute directory')
    path = directory / name
    if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('archive member must be an ordinary file')
    return path


def verify_archive_set(directory, value, *, format):
    """Hash ordered ordinary files before any consumer may extract them."""
    validate_archive_set(value, format=format)
    logical_hash = hashlib.sha256()
    total = 0
    for part in value['parts']:
        path = _ordinary_archive_file(directory, part['name'])
        before = path.stat()
        hashed = hashlib.sha256()
        size = 0
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b''):
                size += len(chunk)
                if size > part['bytes']:
                    raise ValueError('archive part exceeds admitted size')
                hashed.update(chunk)
                logical_hash.update(chunk)
        after = path.stat()
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or size != part['bytes'] or hashed.hexdigest() != part['sha256']):
            raise ValueError('archive part changed or hash differs')
        total += size
    if total != value['bytes'] or logical_hash.hexdigest() != value['sha256']:
        raise ValueError('logical archive hash differs')
    return value


class ArchiveSetReader(io.RawIOBase):
    """Seek over a fully verified ordered set without an aggregate disk copy."""
    def __init__(self, directory, value, *, format):
        super().__init__()
        verify_archive_set(directory, value, format=format)
        self.parts = []
        self.directory, self.value, self.format = directory, value, format
        self.complete = False
        self.length, self.position = value['bytes'], 0
        try:
            for part in value['parts']:
                stream = _ordinary_archive_file(directory, part['name']).open('rb')
                chunks = []
                self.parts.append((stream, part['bytes'], chunks))
                digest, size = hashlib.sha256(), 0
                while raw := stream.read(65536):
                    size += len(raw)
                    if size > part['bytes']: raise ValueError('archive part grew during admission')
                    digest.update(raw); chunks.append(hashlib.sha256(raw).digest())
                if size != part['bytes'] or digest.hexdigest() != part['sha256']:
                    raise ValueError('opened archive part differs from admitted bytes')
            self.complete = True
        except BaseException:
            self.close()
            raise

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position

    def seek(self, offset, whence=0):
        target = offset if whence == 0 else self.position + offset if whence == 1 else self.length + offset if whence == 2 else -1
        if target < 0: raise ValueError('invalid archive seek')
        self.position = target
        return target

    def read(self, size=-1):
        remaining = max(0, self.length - self.position)
        if size >= 0: remaining = min(remaining, size)
        result, start = [], 0
        for stream, length, chunks in self.parts:
            while remaining and self.position < start + length:
                offset = max(0, self.position - start)
                block = offset // 65536
                stream.seek(block * 65536)
                raw = stream.read(min(65536, length - block * 65536))
                if hashlib.sha256(raw).digest() != chunks[block]:
                    raise ValueError('archive part changed during consumption')
                piece = raw[offset % 65536:offset % 65536 + remaining]
                result.append(piece); self.position += len(piece); remaining -= len(piece)
            start += length
        if remaining: raise ValueError('archive part shortened during read')
        return b''.join(result)

    def close(self):
        if self.closed: return
        try:
            if getattr(self, 'complete', False):
                verify_archive_set(self.directory, self.value, format=self.format)
        finally:
            for stream, _, _ in getattr(self, 'parts', []): stream.close()
            super().close()


def copy_archive_set(source,directory,*,format,volume_bytes=1900<<20,name=None):
    """Publish bounded ordinary parts from one completed logical archive DATA file."""
    source=Path(source).absolute();directory=Path(directory).absolute()
    _ordinary_archive_file(source.parent,source.name)
    if directory.resolve()!=directory or directory.is_symlink() or not directory.is_dir():
        raise ValueError('archive-set destination must be ordinary')
    size,sha=digest(source)
    name=source.name if name is None else name
    _archive_pin(dict(name=name,bytes=size,sha256=sha))
    logical_name=name
    if not 0<size<=BACKEND_LOGICAL_LIMIT or type(volume_bytes) is not int or not 0<volume_bytes<ARCHIVE_PART_LIMIT:
        raise ValueError('archive-set size or volume bound invalid')
    count=(size+volume_bytes-1)//volume_bytes
    if not 1<=count<=ARCHIVE_PART_COUNT or not name.endswith('.'+format):
        raise ValueError('archive-set format or part count invalid')
    names=[name] if count==1 else [name+f'.{n:03d}' for n in range(1,count+1)]
    if any((directory/name).exists() or (directory/name).is_symlink() for name in names):
        raise ValueError('archive-set output already exists')
    created=[];parts=[];complete=hashlib.sha256()
    try:
        with source.open('rb') as reader:
            for name in names:
                target=directory/name;hashed=hashlib.sha256();written=0
                with target.open('xb') as writer:
                    created.append(target)
                    remaining=min(volume_bytes,size-sum(row['bytes'] for row in parts))
                    while remaining:
                        raw=reader.read(min(1<<20,remaining))
                        if not raw:raise ValueError('logical archive shortened during split')
                        writer.write(raw);complete.update(raw);hashed.update(raw);written+=len(raw);remaining-=len(raw)
                parts.append(dict(name=name,bytes=written,sha256=hashed.hexdigest()))
            if reader.read(1) or complete.hexdigest()!=sha:raise ValueError('logical archive changed during split')
        result=dict(name=logical_name,bytes=size,sha256=sha,format=format,parts=parts)
        verify_archive_set(directory,result,format=format)
        return result
    except BaseException:
        for target in reversed(created):target.unlink()
        raise


def read_backend_producer(path, *, expected_receipt, expected_input, candidate_source,
                          run_id, run_attempt):
    """Receive an independently API-pinned intermediate receipt and its data.

    This first slice verifies archive bytes; it grants no extraction, release,
    source-licence or executable qualification.
    """
    path = Path(path).absolute()
    _archive_pin(expected_receipt)
    _archive_pin(expected_input)
    if (path.name != expected_receipt['name'] or expected_receipt['bytes'] > 4 << 20
            or not isinstance(candidate_source, str) or not re.fullmatch(r'[0-9a-f]{40}', candidate_source)
            or type(run_id) is not int or run_id <= 0
            or type(run_attempt) is not int or run_attempt <= 0):
        raise ValueError('invalid independent backend context')
    actual = _ordinary_archive_file(path.parent, path.name)
    with actual.open('rb') as stream:
        raw = stream.read(expected_receipt['bytes'] + 1)
    if (len(raw), hashlib.sha256(raw).hexdigest()) != (expected_receipt['bytes'], expected_receipt['sha256']):
        raise ValueError('backend receipt differs from independent intake')
    def closed_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate backend receipt key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=closed_pairs)
    if isinstance(value, dict) and 'input_descriptor' in value:
        _archive_pin(value['input_descriptor'])
    if (not isinstance(value, dict) or set(value) != {'schema', 'input_descriptor',
            'candidate_source', 'run_id', 'run_attempt', 'archive', 'source_pair'}
            or type(value['schema']) is not int or value['schema'] not in (2, 3)
            or value['input_descriptor'] != expected_input
            or value['candidate_source'] != candidate_source
            or type(value['run_id']) is not int or value['run_id'] != run_id
            or type(value['run_attempt']) is not int or value['run_attempt'] != run_attempt):
        raise ValueError('backend receipt provenance differs')
    seen = {path.name.casefold()}
    for key, format in (('archive', '7z'), ('source_pair', 'zip')):
        archive = value[key]
        if value['schema'] == 2:
            _archive_pin(archive)
            if archive['bytes'] >= ARCHIVE_PART_LIMIT or not archive['name'].endswith('.zip'):
                raise ValueError('invalid legacy backend archive')
            archive = dict(archive, format='zip', parts=[archive])
            format = 'zip'
        validate_archive_set(archive, format=format)
        if value['schema'] == 3 and archive['bytes'] > BACKEND_LOGICAL_LIMIT:
            raise ValueError('backend logical archive exceeds recipe budget')
        for part in archive['parts']:
            if part['name'].casefold() in seen:
                raise ValueError('backend archive paths alias')
            seen.add(part['name'].casefold())
        verify_archive_set(path.parent, archive, format=format)
    return value


def checked_zip(path: Path, *, bounded_members: bool = False, expanded_limit: int = 8 << 30) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(path)
    names = archive.namelist()
    if bounded_members:
        folded = set()
        total = 0
        for member in archive.infolist():
            # ZipInfo normalizes the host separator in filename on Windows;
            # orig_filename retains the actual archive header spelling.
            name = member.orig_filename.rstrip('/')
            if (not name or '\\' in name or ':' in name or any(ord(char) < 32 for char in name)
                    or any(part in ('', '.', '..') for part in name.split('/'))
                    or name.casefold() in folded or stat.S_ISLNK(member.external_attr >> 16)):
                archive.close()
                raise ValueError('unsafe or linked app ZIP member')
            folded.add(name.casefold())
            total += member.file_size
            if type(expanded_limit) is not int or expanded_limit not in (2 << 30,8 << 30,16 << 30) or total > expanded_limit:
                archive.close()
                raise ValueError('app ZIP exceeds existing expanded-byte limit')
    if len(names) != len(set(names)) or archive.testzip() is not None:
        archive.close()
        raise ValueError(f"duplicate or corrupt ZIP member in {path}")
    return archive


def builder_paths(data: bytes) -> list[str]:
    # Bundlers emit escaped JS literals; native binaries can contain raw paths.
    # Either form may affect relative-file lookups at run time.
    return sorted({match.group().decode("utf-8", "replace")
                   for pattern in WINDOWS_BUILD_PATHS for match in pattern.finditer(data)})


def archive_builder_paths(archive: zipfile.ZipFile) -> dict[str, list[str]]:
    found = {}
    for member in archive.infolist():
        if member.is_dir() or Path(member.filename).suffix.lower() not in SCANNED_SUFFIXES:
            continue
        paths = set()
        with archive.open(member) as stream:
            previous = b""
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                paths.update(builder_paths(previous + chunk))
                previous = chunk[-512:]
        if paths:
            found[member.filename] = sorted(paths)
    return found


def _desktop_pair(manifest, binary_zip, source_zip, source_pin, context):
    """Inspect the explicit final capsule after the native/Burn owner admits it.

    Signature dictionaries here are independently verified native-owner outputs;
    the embedded JSON cannot select its own authority or replace verification.
    """
    current=type(manifest.get('schema')) is int and manifest['schema']==3
    native=manifest.get('variant')==NATIVE_VARIANT
    if native and not current:raise ValueError('native archive requires multipart schema3')
    context_fields={'producer', 'source_policy', 'backend_input_descriptor', 'oa_integration', 'signatures'}
    if current:context_fields|={'backend','backend_manifest'}
    if native:context_fields|={'control_manifest','control_pin'}
    if (not isinstance(context, dict) or set(context) != context_fields
            or set(context['signatures']) != ({'host_signing'} if native else {'host_signing','inner_signatures'} if current else {'host_signing', 'inner_signatures', 'msi_signatures'})):
        raise ValueError('custom Desktop inspection requires admitted native/Burn context')
    for key in ('source_policy', 'backend_input_descriptor'):
        pin = context[key]
        if (not isinstance(pin, dict) or set(pin) != {'bytes', 'sha256'} or type(pin['bytes']) is not int
                or not 0 < pin['bytes'] <= 4 << 20 or not re.fullmatch(r'[0-9a-f]{64}', str(pin['sha256']))):
            raise ValueError('custom Desktop requires independent immutable input pins')
    def member(pin, *, metadata=False, metadata_limit=4 << 20):
        if (not isinstance(pin, dict) or set(pin) != {'name', 'bytes', 'sha256'}
                or not (re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', str(pin['name']))
                        or native and re.fullmatch(r'archive-tool/(?:DOC/)?[A-Za-z0-9][A-Za-z0-9._-]*',str(pin['name'])))
                or type(pin['bytes']) is not int or not 0 < pin['bytes'] < (2 << 30)
                or not re.fullmatch(r'[0-9a-f]{64}', str(pin['sha256']))):
            raise ValueError('invalid Desktop capsule member pin')
        info = binary_zip.getinfo(pin['name'])
        if info.file_size != pin['bytes'] or metadata and info.file_size > metadata_limit:
            raise ValueError('Desktop capsule member size differs or metadata exceeds limit')
        digest = hashlib.sha256()
        raw = bytearray()
        with binary_zip.open(info) as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b''):
                digest.update(chunk)
                if metadata: raw.extend(chunk)
        if digest.hexdigest() != pin['sha256']:
            raise ValueError('Desktop capsule member differs from its proof')
        return bytes(raw) if metadata else None
    expected_fields = {'schema', 'variant', 'version', 'desktop_source_commit', 'comfyui_source_commit',
        'corresponding_comfyui_source_zip', 'corresponding_comfyui_source_zip_sha256', 'source_policy',
        'backend_input_descriptor', 'oa_integration', 'bundle_app', 'roles', 'proofs',
        'preserved_notice_paths', 'added_notice_paths'}
    if current:
        expected_fields-= {'corresponding_comfyui_source_zip','corresponding_comfyui_source_zip_sha256'}
        expected_fields|={'corresponding_source','backend','embedded_integration'}
        offer=validate_corresponding_source(manifest.get('corresponding_source'))
        validate_backend_resource(manifest.get('backend'),expected=context['backend'])
        if offer['archive']!=source_pin or offer['data_release']!=manifest['backend']['data_release']:
            raise ValueError('Desktop source offer differs from authenticated source set/policy locator')
    source_commit_field='producer_source_commit' if native else 'desktop_source_commit'
    if native:expected_fields=(expected_fields-{'desktop_source_commit'})|{'producer_source_commit','control','archive_tool','programs'}
    if (set(manifest) != expected_fields or type(manifest['schema']) is not int or manifest['schema'] != (3 if current else 2)
            or manifest['source_policy'] != context['source_policy']
            or manifest['backend_input_descriptor'] != context['backend_input_descriptor']
            or manifest['oa_integration'] != context['oa_integration']
            or not re.fullmatch(r'[0-9a-f]{40}', str(manifest[source_commit_field]))
            or not re.fullmatch(r'[0-9a-f]{40}', str(manifest['comfyui_source_commit']))
            or set(manifest['roles']) != ({'host'} if native else {'host','preparation'} if current else {'host', 'preparation', 'integration'})
            or set(manifest['proofs']) != ({'host_signing','producer_binding','source'} if native else {'host_signing','inner_signatures','producer_binding','source'} if current else {'host_signing', 'inner_signatures', 'msi_signatures', 'producer_binding', 'source'})):
        raise ValueError('custom Desktop source/role/proof schema differs')
    roles = manifest['roles']
    if native and manifest['programs']!=native_programs():
        raise ValueError('native archive application/service program facts differ from source layout')
    if (not roles['host']['name'].endswith('.exe') or not native and not roles['preparation']['name'].endswith('.exe')
            or not current and not roles['integration']['name'].endswith('.msi')
            or len({row['name'] for row in roles.values()}) != (1 if native else 2 if current else 3)
            or native and roles['host']['name']!=NATIVE_HOST):
        raise ValueError('custom Desktop integrated installer roles differ')
    for pin in roles.values(): member(pin)
    control_names=set()
    if native:
        control=manifest['control']
        if control!=context['control_pin']:
            raise ValueError('native control pin differs from admitted own-image resource')
        control_names=native_control_members(binary_zip,control,context['control_manifest'])
    bundle = json.loads(member(manifest['bundle_app'], metadata=True))
    if bundle.get('id') != 'comfyui' or not current and any(bundle.get(key) != roles['integration'][alias]
            for key, alias in (('file', 'name'), ('bytes', 'bytes'), ('sha256', 'sha256'))):
        raise ValueError('custom Desktop extension MSI differs from Burn role')
    if current:
        raw=member(manifest['backend']['provenance']['manifest'],metadata=True,metadata_limit=BACKEND_RUNTIME_MANIFEST_BYTES)
        observed=json.loads(raw)
        if observed!=context['backend_manifest']:raise ValueError('embedded runtime manifest differs from authenticated intake')
        validate_embedded_integration(manifest['embedded_integration'],source_policy=context['source_policy'],
            oa_integration=context['oa_integration'],backend_manifest=manifest['backend']['provenance']['manifest'],manifest=observed,native=native)
        if (set(bundle)!={'id','title','host','embedded_integration'}
                or bundle['embedded_integration']!=manifest['embedded_integration']):
            raise ValueError('custom Desktop embedded wrapper differs from Burn role')
    host = bundle.get('host', {})
    for role, observed in ([('host',host)] if native else [('host', host), ('preparation', host.get('preparation', {}))]):
        if any(observed.get(key) != roles[role][alias] for key, alias in (('file', 'name'), ('bytes', 'bytes'), ('sha256', 'sha256'))):
            raise ValueError('custom Desktop host/preparation differs from Burn role')
    if native and set(host)!={'file','bytes','sha256'}:
        raise ValueError('native archive host cannot carry an Electron/preparation recipe')
    proofs = {key: json.loads(member(pin, metadata=True)) for key, pin in manifest['proofs'].items()}
    if proofs['producer_binding'] != context['producer']:
        raise ValueError('custom Desktop producer differs from authenticated source/run/attempt')
    producer = context['producer']
    if native and manifest['producer_source_commit']!=producer.get('source'):
        raise ValueError('native archive source differs from authenticated producer')
    if (not re.fullmatch(r'[0-9a-f]{40}', str(producer.get('source')))
            or type(producer.get('run_id')) is not int or producer['run_id'] <= 0
            or type(producer.get('run_attempt')) is not int or producer['run_attempt'] <= 0
            or producer.get('intake', {}).get('source') != producer['source']
            or producer['intake'].get('run_id') != producer['run_id']
            or producer['intake'].get('run_attempt') != producer['run_attempt']
            or producer['intake'].get('artifact') != producer.get('artifact')):
        raise ValueError('custom Desktop producer lacks actual API identity')
    artifact = producer.get('artifact', {})
    if (producer['intake'].get('schema') != 1 or producer['intake'].get('kind') != 'windows-artifact-intake'
            or set(artifact) != {'id', 'name', 'sha256'} or type(artifact['id']) is not int or artifact['id'] <= 0
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', str(artifact['name']))
            or not re.fullmatch(r'[0-9a-f]{64}', str(artifact['sha256']))):
        raise ValueError('custom Desktop producer lacks actual immutable API artifact')
    for role, selected in (('host', producer.get('host', {})),):
        if (Path(str(selected.get('name'))).name != roles[role]['name']
                or any(selected.get(key) != roles[role][key] for key in ('sha256', 'bytes'))):
            raise ValueError('custom Desktop role differs from source-owned producer binding')
    # The API producer binds the original unsigned MSI. Its final signed
    # container is admitted below through the independent MSI signer output.
    # Retain that raw provenance instead of relabelling it as the signed bytes.
    raw_msi = producer.get('expected_payload', {}).get('msi', {})
    if current:
        if (set(producer)!={'source','run_id','run_attempt','artifact','intake','host','embedded_integration'}
                or producer['embedded_integration']!=manifest['embedded_integration']):
            raise ValueError('custom Desktop embedded integration lacks original API provenance')
    elif (Path(str(raw_msi.get('name'))).name != roles['integration']['name']
            or type(raw_msi.get('bytes')) is not int or not 0 < raw_msi['bytes'] < (2 << 30)
            or not re.fullmatch(r'[0-9a-f]{64}', str(raw_msi.get('sha256')))):
        raise ValueError('custom Desktop integration lacks its original API MSI provenance')
    for key, expected in context['signatures'].items():
        if proofs[key] != expected or expected.get('schema') != 1 or expected.get('result') != 'pass':
            raise ValueError('custom Desktop signature proof differs from admitted signer output')
    signature_roles=[('host_signing','host')] if native else [('host_signing','host'),('inner_signatures','preparation')]
    if not current:signature_roles.append(('msi_signatures','integration'))
    for proof, role in signature_roles:
        if not any(row.get('sha256') == roles[role]['sha256'] and row.get('bytes') == roles[role]['bytes']
                   and Path(str(row.get('name'))).name == roles[role]['name']
                   for row in proofs[proof].get('files', [])):
            raise ValueError('custom Desktop role lacks matching admitted signature proof')
    source_proof = proofs['source']
    if set(source_proof) != {'schema', 'source_pair', 'files'} or type(source_proof['schema']) is not int or source_proof['schema'] != (2 if current else 1) or source_proof['source_pair'] != source_pin:
        raise ValueError('custom Desktop corresponding source proof differs from exact source ZIP')
    source_files = {row['name']: row for row in source_proof['files']}
    if (len(source_files) != len(source_proof['files']) or not source_files
            or set(source_files) != {entry.filename for entry in source_zip.infolist() if not entry.is_dir()}):
        raise ValueError('custom Desktop corresponding source roster is incomplete')
    for name, pin in source_files.items():
        info = source_zip.getinfo(name)
        digest = hashlib.sha256()
        with source_zip.open(info) as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b''): digest.update(chunk)
        if set(pin) != {'name', 'bytes', 'sha256'} or info.file_size != pin['bytes'] or digest.hexdigest() != pin['sha256']:
            raise ValueError('custom Desktop corresponding source member differs')
    def source_metadata(expected):
        matches = [row for row in source_files.values() if all(row.get(key) == expected[key] for key in ('bytes', 'sha256'))]
        if not matches:
            raise ValueError('custom Desktop source ZIP omits an independently selected input descriptor')
        return json.loads(source_zip.read(matches[0]['name']))
    desktop_source = source_metadata(context['source_policy'])
    backend_source = source_metadata(context['backend_input_descriptor'])
    if current:
        resource=manifest['backend']
        recipe=source_metadata(resource['provenance']['backend_policy'])
        backend_policy_limits(recipe)
        if native:
            tool=recipe.get('archive_tool',{})
            selected={key:tool.get(key) for key in ('bytes','sha256')}
            if manifest['archive_tool']!=dict(name='archive-tool/7zr.exe',**selected):
                raise ValueError('native archive tool differs from selected backend source policy')
            member(manifest['archive_tool'])
            source=tool.get('source',{})
            if not any(all(row.get(key)==source.get(key) for key in ('bytes','sha256')) for row in source_files.values()):
                raise ValueError('native archive omits selected archiver corresponding source')
            for notice in tool.get('notices',[]):
                pin=dict(notice,name='archive-tool/'+notice['name'])
                member(pin)
                if pin['name'] not in manifest['preserved_notice_paths']+manifest['added_notice_paths']:
                    raise ValueError('native archive omits selected archiver notice')
        if validate_data_release(recipe.get('data_release'))!=resource['data_release']:
            raise ValueError('Desktop DATA locator differs from corresponding source policy')
        backend_receipt=source_metadata(resource['provenance']['producer_receipt'])
        expected_input=resource['provenance']['input_descriptor']
        if (backend_receipt.get('schema')!=3 or backend_receipt.get('candidate_source')!=producer['source']
                or backend_receipt.get('run_id')!=producer['run_id'] or type(backend_receipt.get('run_attempt')) is not int
                or backend_receipt['run_attempt']<=0 or backend_receipt.get('input_descriptor')!=expected_input
                or backend_receipt.get('archive')!=resource['archive']
                or backend_receipt.get('source_pair')!=resource['corresponding_source']
                or {key:expected_input[key] for key in ('bytes','sha256')}!=context['backend_input_descriptor']):
            raise ValueError('Desktop runtime resource differs from original backend producer/input')
        runtime_manifest=source_metadata(resource['provenance']['manifest'])
        if (runtime_manifest.get('comfyui_ref')!=resource['comfyui_ref']
                or runtime_manifest.get('python_version')!=resource['python_version']
                or runtime_manifest.get('input_descriptor_sha256')!=expected_input['sha256']
                or runtime_manifest.get('oa_integration')!=context['oa_integration']
                or runtime_manifest!=context['backend_manifest']):
            raise ValueError('Desktop runtime manifest differs from admitted resource')
    if ((not native and desktop_source.get('upstream', {}).get('commit') != manifest['desktop_source_commit'])
            or backend_source.get('comfyui_commit') != manifest['comfyui_source_commit']):
        raise ValueError('custom Desktop source identity differs from selected input descriptors')
    licensing = desktop_source.get('licensing')
    if native:
        if (desktop_source.get('name')!='comfyui' or desktop_source.get('host',{}).get('arguments')!=['owned-host']):
            raise ValueError('native archive source policy lacks its actual owned host entrypoint')
        # The selected Comfy source owns the application licence. The native
        # carrier retains OA and supplier notices as separate complete terms.
        license_name=backend_source.get('runtime_provenance',{}).get('comfyui',{}).get('license')
        license_rows=[row for row in backend_source.get('files',[]) if isinstance(row,dict) and row.get('name')==license_name]
        license_pin=license_rows[0] if len(license_rows)==1 else None
        if (not isinstance(license_pin,dict) or set(license_pin)!={'name','bytes','sha256'} or
                type(license_pin['bytes']) is not int or not 0<license_pin['bytes']<4<<20 or
                not re.fullmatch(r'[0-9a-f]{64}',str(license_pin['sha256'])) or
                not any(all(row[key]==license_pin[key] for key in ('bytes','sha256')) for row in source_files.values())):
            raise ValueError('native archive omits the selected Comfy source licence')
    elif (not isinstance(licensing, dict) or set(licensing) != {'expression', 'file', 'bytes', 'sha256'}
            or licensing['expression'] != 'AGPL-3.0-or-later' or licensing['file'] != 'LICENSE'
            or type(licensing['bytes']) is not int or not 0 < licensing['bytes'] < 4 << 20
            or not re.fullmatch(r'[0-9a-f]{64}', str(licensing['sha256']))
            or not any(Path(row['name']).name == licensing['file']
                       and all(row[key] == licensing[key] for key in ('bytes', 'sha256'))
                       for row in source_files.values())):
        raise ValueError('custom Desktop source licence differs from selected open-source policy')
    allowed = {'OA-PROVENANCE.json', manifest['bundle_app']['name'], *(row['name'] for row in roles.values()),
        *(row['name'] for row in manifest['proofs'].values()), *manifest['preserved_notice_paths'], *manifest['added_notice_paths']}
    if current:allowed.add(manifest['backend']['provenance']['manifest']['name'])
    if native:allowed.add(manifest['archive_tool']['name'])
    allowed.update(control_names)
    if {entry.filename for entry in binary_zip.infolist() if not entry.is_dir()} != allowed:
        raise ValueError('custom Desktop capsule contains unexplained or missing members')
    return {'version': manifest['version'], 'upstream_commit': manifest['comfyui_source_commit'],
            source_commit_field: manifest[source_commit_field], 'distribution': NATIVE_VARIANT if native else 'oa-custom-desktop',
            'license':'GPL-3.0' if native else licensing['expression'],
            **({'programs':manifest['programs']} if native else {}),
            **({'archive_tool_program':manifest['archive_tool']['name']} if native else {}),
            **({'backend':manifest['backend']} if native else {}),
            **(dict(native_record_terms(context['backend_manifest'],context['control_manifest']),
                    marker_bytes=native_marker_bytes(binary_zip,manifest['version']),
                    host_expanded_bytes=sum(entry.file_size for entry in binary_zip.infolist()),
                    backend_expanded_bytes=sum(row['bytes'] for row in context['backend_manifest']['runtime_files'].values())+
                        context['backend']['provenance']['manifest']['bytes']) if native else {}),
            'producer': {key: producer[key] for key in ('source', 'run_id', 'run_attempt')},
            **({'embedded_integration':manifest['embedded_integration']} if current else {})}


def inspect_desktop_set(binary,source_directory,source,*,desktop_context,require_clean_paths=False):
    """Authenticate all corresponding-source parts through the shared held reader."""
    validate_archive_set(source,format='zip')
    if source['bytes']>BACKEND_LOGICAL_LIMIT:raise ValueError('corresponding source exceeds logical limit')
    binary=Path(binary);size,sha=digest(binary)
    if not 0<size<2<<30:raise ValueError('Desktop capsule exceeds asset limit')
    with ArchiveSetReader(source_directory,source,format='zip') as stream:
        with checked_zip(stream,bounded_members=True,expanded_limit=16<<30) as source_zip,checked_zip(binary,bounded_members=True) as binary_zip:
            entry=binary_zip.getinfo('OA-PROVENANCE.json')
            if entry.file_size>4<<20:raise ValueError('Desktop provenance exceeds metadata limit')
            manifest=json.loads(binary_zip.read(entry))
            if manifest.get('schema')!=3 or manifest.get('variant') not in ('oa-comfyui-desktop',NATIVE_VARIANT):
                raise ValueError('multipart corresponding source requires Desktop capsule3')
            identity=_desktop_pair(manifest,binary_zip,source_zip,source,desktop_context)
            paths=archive_builder_paths(binary_zip)
            if require_clean_paths and paths:raise ValueError('Desktop payload embeds unreviewed absolute builder paths')
            notices=sorted(name for name in binary_zip.namelist() if NOTICE.search(name) and not name.endswith('/'))
            if not notices:raise ValueError('Desktop capsule omits licence/notice files')
            result={'schema':3,'status':'unpublished-candidate','app':'comfyui',
                'binary':{'name':binary.name,'bytes':size,'sha256':sha},'source':source,'identity':identity,
                'binary_member_count':len(binary_zip.infolist()),'source_member_count':len(source_zip.infolist()),
                'license_and_notice_paths':notices,'embedded_builder_paths':paths,'unreviewed_builder_paths':paths}
    return result


def inspect(app: str, binary: Path, source: Path, *, require_clean_paths: bool = False,
            desktop_context: dict | None = None) -> dict[str, object]:
    binary_bytes, binary_sha = digest(binary)
    source_bytes, source_sha = digest(source)
    if not 0 < binary_bytes < (2 << 30) or not 0 < source_bytes < (2 << 30):
        raise ValueError("both app and source ZIPs must fit the release asset limit")
    with checked_zip(source, bounded_members=True) as source_zip, checked_zip(binary, bounded_members=True) as binary_zip:
        source_members = source_zip.namelist()
        names = binary_zip.namelist()
        notices = sorted(name for name in names if NOTICE.search(name) and not name.endswith("/"))
        if not notices:
            raise ValueError("app ZIP contains no licence or notice files")
        if app != "comfyui":
            raise ValueError("app must be comfyui")
        if binary_zip.getinfo('OA-PROVENANCE.json').file_size > 4 << 20:
            raise ValueError('app provenance exceeds bounded metadata limit')
        manifest = json.loads(binary_zip.read("OA-PROVENANCE.json"))
        if (manifest.get("corresponding_comfyui_source_zip") != source.name
                or manifest.get("corresponding_comfyui_source_zip_sha256") != source_sha):
            raise ValueError("ComfyUI provenance does not bind this source ZIP")
        if manifest.get('schema') == 2 and manifest.get('variant') == 'oa-comfyui-desktop':
            identity = _desktop_pair(manifest, binary_zip, source_zip,
                {'name': source.name, 'bytes': source_bytes, 'sha256': source_sha}, desktop_context)
            paths = archive_builder_paths(binary_zip)
            if require_clean_paths and paths:
                raise ValueError('app payload embeds unreviewed absolute builder paths')
            return {'schema': 2, 'status': 'unpublished-candidate', 'app': app,
                'binary': {'name': binary.name, 'bytes': binary_bytes, 'sha256': binary_sha},
                'source': {'name': source.name, 'bytes': source_bytes, 'sha256': source_sha},
                'identity': identity, 'binary_member_count': len(names), 'source_member_count': len(source_members),
                'license_and_notice_paths': notices, 'embedded_builder_paths': paths, 'unreviewed_builder_paths': paths}
        if manifest.get("variant") != "oa-comfyui-cpu-frontend":
            raise ValueError("ComfyUI app is not the reviewed CPU frontend variant")
        if "OA-LICENSES/OpenAbstractions-LICENSE" not in names or not any(
                name.startswith("ComfyUI-" + manifest["comfyui_source_commit"] + "/")
                for name in source_members):
            raise ValueError("ComfyUI source or OA node licence is missing")
        for name in manifest.get("preserved_notice_paths", []) + manifest.get("added_notice_paths", []):
            if name not in names:
                raise ValueError("ComfyUI recorded license or notice is missing: " + name)
        for path in manifest.get("oa_integration_corresponding_source_paths", []):
            if path.endswith("/"):
                if not any(name.startswith(path) for name in source_members):
                    raise ValueError("OA integration source tree is missing: " + path)
            elif path not in source_members:
                raise ValueError("OA integration source file is missing: " + path)
        if manifest.get("oa_integration") and not {
                "OA-Integration-Source/node/abstraction_downloads/__init__.py",
                "OA-Integration-Source/LICENSE", "OA-Integration-Source/manifest.json"}.issubset(
                    set(manifest.get("oa_integration_corresponding_source_paths", []))):
            raise ValueError("OA integration corresponding source is not recorded in the pair")
        paths = archive_builder_paths(binary_zip)
        identity = {"version": "0.35.0-oa.0.4.0", "upstream_commit": manifest["comfyui_source_commit"],
                    "records_sha256": manifest["private_python_records_sha256"],
                    "integration_sha256": manifest["oa_integration"]["sha256"]}
        if require_clean_paths and paths:
            raise ValueError("app payload embeds unreviewed absolute builder paths: " + ", ".join(paths))
        return {"schema": 1, "status": "unpublished-candidate", "app": app,
                "binary": {"name": binary.name, "bytes": binary_bytes, "sha256": binary_sha},
                "source": {"name": source.name, "bytes": source_bytes, "sha256": source_sha},
                "identity": identity, "binary_member_count": len(names),
                "source_member_count": len(source_members), "license_and_notice_paths": notices,
                "embedded_builder_paths": paths, "unreviewed_builder_paths": paths}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=("comfyui",), required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--require-clean-paths", action="store_true",
                        help="release gate: refuse any embedded absolute builder path")
    parser.add_argument("--output", type=Path, help="write JSON receipt instead of printing it")
    args = parser.parse_args()
    receipt = inspect(args.app, args.binary, args.source, require_clean_paths=args.require_clean_paths)
    serialized = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
