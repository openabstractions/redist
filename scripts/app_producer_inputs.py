"""Exact public source and bounded download inputs for optional app producers.

This tool only prepares inputs. It cannot authorize a release or turn a local
qualification receipt into a hosted producer receipt.
"""

import argparse
import csv
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
import urllib.error
import urllib.request
import zipfile
import types

from app_assets import (optional_app_sources, roster, select_windows_addon_artifact,
                        select_windows_wheel_artifact)


COMMIT = re.compile(r'[0-9a-f]{40}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
DOWNLOAD_USER_AGENT = 'OpenAbstractions-release (+https://openabstractions.github.io)'
CHARTER = 'openabstractions/abstractions'


def github_asset_input(repository, asset_id, expected, destination):
    """Resolve one source-pinned official asset, then use bounded hash intake."""
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository) or
            type(asset_id) is not int or asset_id<=0):
        raise ValueError('official input requires a source-selected repository and asset ID')
    url=f'https://api.github.com/repos/{repository}/releases/assets/{asset_id}'
    request=urllib.request.Request(url,headers={'User-Agent':DOWNLOAD_USER_AGENT,'Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(request,timeout=60) as response:
        raw=response.read((128<<10)+1)
    if len(raw)>128<<10:
        raise ValueError('official asset metadata exceeds bounded input policy')
    asset=json.loads(raw)
    download=asset.get('browser_download_url','')
    if (asset.get('id')!=asset_id or asset.get('size')!=expected['bytes'] or
            not download.startswith('https://github.com/'+repository+'/releases/download/')):
        raise ValueError('official asset metadata differs from selected source input')
    checked_download(download,destination,expected['sha256'],expected['bytes'])
    return {'asset_id':asset_id,'source_url':download,'sha256':expected['sha256'],'bytes':expected['bytes']}


def prime_native_npm_cache(source, lock_relative, lock_sha256, npm, cache, workspace, evidence):
    """Acquire the exact reconstructed web lock before sealing build inputs.

    This explicit acquisition owner may fetch lock-selected dependencies. The
    native materializer and consumer remain offline. No immutable source file
    is changed, and the receipt records the actual selected command and exit.
    """
    source,cache,workspace,evidence=map(Path,(source,cache,workspace,evidence))
    relative=Path(lock_relative)
    if (relative.is_absolute() or relative.drive or relative.as_posix()!=lock_relative or '..' in relative.parts or
            relative.name!='package-lock.json' or not SHA.fullmatch(str(lock_sha256))):
        raise ValueError('native npm acquisition requires the source-selected lock')
    selected=[source/relative,source/relative.parent/'package.json']
    for path in selected:
        if (not path.is_file() or any(parent.is_symlink() or parent.is_junction()
                for parent in (path,*path.parents) if parent!=source.parent)):
            raise ValueError('native npm source input is missing or linked')
    before={path.name:{'sha256':sha_file(path),'bytes':path.stat().st_size} for path in selected}
    if before['package-lock.json']['sha256']!=lock_sha256:
        raise ValueError('native npm source lock differs from selected source')
    if (workspace.exists() or evidence.exists() or not cache.is_dir() or
            cache.is_symlink() or cache.is_junction()):
        raise ValueError('native npm acquisition needs a fresh workspace/receipt and owned cache')
    workspace.mkdir(parents=True)
    for path in selected:
        shutil.copyfile(path,workspace/path.name)
    command=[str(Path(npm).resolve()),'ci','--ignore-scripts','--no-audit','--no-fund','--cache',str(cache.resolve())]
    npm_pin={'sha256':sha_file(npm),'bytes':Path(npm).stat().st_size}
    result=subprocess.run(command,cwd=workspace,check=False)
    after={path.name:{'sha256':sha_file(path),'bytes':path.stat().st_size} for path in selected}
    copied={path.name:{'sha256':sha_file(workspace/path.name),'bytes':(workspace/path.name).stat().st_size} for path in selected}
    receipt={'schema':1,'command':command,'exit':result.returncode,'source_inputs':before,
             'npm':npm_pin}
    evidence.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    if (result.returncode or before!=after or before!=copied or
            npm_pin!={'sha256':sha_file(npm),'bytes':Path(npm).stat().st_size}):
        raise ValueError('native npm acquisition failed or changed selected source/lock')
    return receipt


def merge_native_signature_receipts(target_root, native_names, received, policy, policy_sha256, relay):
    """Rebind independently received proofs to source-selected native members.

    Each received pair is an existing receipt and its independently admitted
    artifact root. The caller stages only source-selected bytes; this function
    verifies both roots and never signs or accepts a producer role declaration.
    """
    names = list(native_names)
    if len(names)!=len(set(names)):
        raise ValueError('duplicate source-selected native signature member')
    proofs = []
    for receipt,root in received:
        proofs.extend(relay.verify_receipt(receipt,policy,root,policy_sha256=policy_sha256)['files'])
    files = []
    for name in names:
        path=relay.member(target_root,name)
        data=path.read_bytes()
        pin=(hashlib.sha256(data).hexdigest(),len(data))
        matches=[proof for proof in proofs if (proof['sha256'],proof['bytes'])==pin]
        if not matches or any({key:value for key,value in proof.items() if key!='name'} !=
                              {key:value for key,value in matches[0].items() if key!='name'} for proof in matches[1:]):
            raise ValueError('source-selected native member has missing or ambiguous OA proof: '+name)
        files.append(dict(matches[0],name=name))
    merged={'schema':1,'result':'pass','policy_sha256':policy_sha256,'files':files}
    return relay.verify_receipt(merged,policy,target_root,policy_sha256=policy_sha256)


def enrich_installer_payload(payload, source_roles, signature_receipt, policy, policy_sha256,
                             native_root, relay):
    """Bind source-derived roles to existing OA proofs and compiled row pins.

    The caller loads source_roles from the exact authenticated producer source,
    and receives its native artifact through the existing immutable intake.
    A producer JSON role label cannot replace that Python source owner. The
    existing MSI readback subsequently checks the entire actual PE roster.
    """
    if not callable(source_roles):
        raise ValueError('installer roles require the authenticated source owner')
    own_roles, supplier_roles, external_names = source_roles(payload)
    verified = relay.verify_receipt(signature_receipt,policy,native_root,policy_sha256=policy_sha256)
    proofs = {row['name']:row for row in verified['files']}
    result = dict(payload,own_pe=[],supplier_pe=[])
    tables = {'File':payload['files'],'Binary':payload['binaries']}
    seen = set()
    for table, identifier, native in own_roles:
        key = table,identifier
        if key in seen or table not in tables:
            raise ValueError('duplicate or foreign source-owned PE role')
        seen.add(key)
        rows = [row for row in tables[table] if row['id']==identifier]
        proof = proofs.get(native)
        if len(rows)!=1 or proof is None or any(rows[0][name]!=proof[name] for name in ('sha256','bytes')):
            raise ValueError('source-owned PE differs from signed native bytes: '+identifier)
        result['own_pe'].append({'table':table,'id':identifier,'signature':proof})
    for table, identifier, pin in supplier_roles:
        key = table,identifier
        if key in seen or table not in tables or set(pin) not in ({'sha256','bytes'},{'sha256','bytes','source'}):
            raise ValueError('duplicate or foreign source-selected supplier PE role')
        seen.add(key)
        rows = [row for row in tables[table] if row['id']==identifier]
        if len(rows)!=1 or any(rows[0][name]!=pin[name] for name in ('sha256','bytes')):
            raise ValueError('supplier PE differs from source-selected bytes: '+identifier)
        if 'source' in pin:
            result['schema']=2
            result.setdefault('supplier_content_pe',[]).append({'table':table,'id':identifier,'pin':pin})
        else:
            result['supplier_pe'].append({'table':table,'id':identifier,'pin':pin})
    external = {}
    for name in external_names:
        if name in external or name not in proofs:
            raise ValueError('external app native member lacks exact OA proof: '+name)
        external[name] = proofs[name]
    if set(proofs) != {native for _,_,native in own_roles} | set(external):
        raise ValueError('native signature receipt has unexplained signed members')
    return relay.validate_expected_payload(result),external


def exact_rows(path, header):
    lines = [line for line in Path(path).read_text(encoding='utf-8').splitlines()
             if line and not line.startswith('>')]
    parsed = list(csv.reader(lines, delimiter='\t'))
    if not parsed or tuple(parsed[0]) != header:
        raise ValueError('invalid public source roster: ' + str(path))
    rows = [dict(zip(header, fields)) for fields in parsed[1:]]
    if any(len(fields) != len(header) for fields in parsed[1:]):
        raise ValueError('malformed public source roster: ' + str(path))
    return rows


def source_pins(app, npm_pins, pypi_pins, app_pins, app_roster, *, producer_only=False,
                adopter_commit=None):
    enabled = {row['id'] for row in roster(app_roster)}
    if producer_only and enabled:
        raise ValueError('producer-only requires an empty Setup catalog')
    if app not in enabled and not producer_only:
        raise ValueError('optional app is not enabled by apps.json: ' + app)
    if app != 'comfyui':
        raise ValueError('unknown optional app producer')
    npm = exact_rows(npm_pins, ('package', 'repository', 'commit', 'directory'))
    charter = [row for row in npm if row['repository'] == CHARTER]
    if len(charter) != 1 or charter[0]['package'] != '@openabstractions/opencode':
        raise ValueError('npm.tsv must name one exact public charter source')
    selected = exact_rows(pypi_pins, ('package', 'repository', 'commit', 'directory'))
    if producer_only:
        if not isinstance(adopter_commit, str) or not COMMIT.fullmatch(adopter_commit):
            raise ValueError('producer-only requires the reviewed exact ComfyUI adopter commit')
        extra = {'repository': 'openabstractions/adopter-comfyui', 'commit': adopter_commit}
    else:
        if adopter_commit is not None:
            raise ValueError('enabled app must use the authored app source roster')
        extra = optional_app_sources(app_pins, roster(app_roster))['comfyui']
    selected = [*selected, {'repository': extra['repository'], 'commit': extra['commit']}]
    selected.append(charter[0])
    by_repo = {}
    for row in selected:
        repo, commit = row['repository'], row['commit']
        if not re.fullmatch(r'[A-Za-z0-9._-]+/[A-Za-z0-9._-]+', repo) or not COMMIT.fullmatch(commit):
            raise ValueError('invalid exact public source pin: ' + repo)
        if repo in by_repo and by_repo[repo] != commit:
            raise ValueError('conflicting source pins: ' + repo)
        by_repo[repo] = commit
    if by_repo.get(CHARTER) != charter[0]['commit']:
        raise ValueError('charter public source pin differs')
    return by_repo


def installer_source_pins(app, npm_pins, pypi_pins, app_pins, app_roster, version, *, producer_source, validate=None):
    """Read installer source obligations from the existing PLAN projection.

    This returns source-owned pins, not execution/signing authority. Existing
    checkout and pinned_input_receipt still bind actual clean source inputs.
    """
    if validate is None:
        from release_facts import validate_public_admission
        validate = validate_public_admission
    document = json.loads(Path(app_roster).read_text(encoding='utf-8'))
    capsule = document.get('release_admission')
    validate(capsule, version, document['apps'], require_delivery=False)
    required = {row['id'] for row in capsule['outcomes']['adopters'] if row['target'] == 'windows-x64'}
    supported = {'opencode', 'comfyui', 'lemonade'}
    if not required <= supported or app not in required:
        raise ValueError('installer producer is absent or foreign to accepted scope')
    if not isinstance(producer_source,str) or not COMMIT.fullmatch(producer_source):
        raise ValueError('installer inputs require the independently selected public redist source')
    npm = exact_rows(npm_pins, ('package', 'repository', 'commit', 'directory'))
    charter = [row for row in npm if row['package'] == '@openabstractions/opencode']
    if len(charter) != 1 or charter[0]['repository'] != CHARTER or charter[0]['directory'] != 'adopters/opencode':
        raise ValueError('installer inputs require the exact charter OpenCode source')
    selected = [*npm, *exact_rows(pypi_pins, ('package', 'repository', 'commit', 'directory'))]
    if app == 'comfyui':
        adopters = exact_rows(app_pins, ('app', 'repository', 'commit'))
        if len(adopters) != 1 or adopters[0]['app'] != 'comfyui' or adopters[0]['repository'] != 'openabstractions/adopter-comfyui':
            raise ValueError('Comfy installer lacks its exact public functional adopter source')
        selected += adopters
    pins = {'openabstractions/redist':producer_source}
    for row in selected:
        repo, commit = row['repository'], row['commit']
        if not re.fullmatch(r'openabstractions/[A-Za-z0-9._-]+', repo) or not COMMIT.fullmatch(commit):
            raise ValueError('invalid exact installer source pin')
        if repo in pins and pins[repo] != commit:
            raise ValueError('conflicting installer SDK/source pin: ' + repo)
        pins[repo] = commit
    if CHARTER not in pins or 'openabstractions/abstraction-identity' not in pins:
        raise ValueError('installer source closure lacks charter or native SDK identity')
    return pins


# Exact split.manifest destinations. The HTML outputs belong to the website,
# not the charter: they are declared evidence, never charter diff exceptions.
CATALOG_PATH = 'monitor/internal/setup/adopter_assets.json'
J_RECORD_PATH = 'docs/results/focused/shared-javascript-capabilities-windows.json'
MATRIX_PATH = 'docs/results/MATRIX.txt'
CHARTER_DERIVED_PATHS = frozenset((CATALOG_PATH, J_RECORD_PATH, MATRIX_PATH))


def pinned_input_receipt(pins, source_root, input_root):
    """Keep actual producer inputs outside its immutable shipped source pair."""
    for repo, commit in pins.items():
        root = Path(source_root) / repo.split('/', 1)[1]
        head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
        dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain=v1',
                                         '--untracked-files=all'], text=True).strip()
        if head != commit or dirty:
            raise ValueError('producer source checkout differs: ' + repo)
    files = {}
    for path in sorted(Path(input_root).rglob('*')):
        relative = path.relative_to(input_root)
        if relative.parts[0] in ('upstream', 'build'):
            continue  # exact upstream pins/build recipe live in the unchanged source
        if path.is_symlink():
            raise ValueError('symlinked app producer input')
        if path.is_file():
            files[relative.as_posix()] = {'bytes': path.stat().st_size, 'sha256': sha_file(path)}
    if not files:
        raise ValueError('producer input receipt has no measured build inputs')
    return {'schema': 1, 'sources': dict(pins), 'build_inputs': files}


def compare_consumer_sources(producer, current, source_root, derivation):
    """Refuse functional drift; permit only reviewed catalog/derived exports."""
    if (not isinstance(producer, dict) or set(producer) != {'schema', 'sources', 'build_inputs'}
            or producer['schema'] != 1 or not isinstance(producer['sources'], dict)
            or not isinstance(producer['build_inputs'], dict) or not producer['build_inputs']):
        raise ValueError('invalid pinned producer input receipt')
    old = producer['sources']
    if set(old) != set(current) or CHARTER not in old:
        raise ValueError('producer source roster differs from consumer')
    for repo, commit in old.items():
        if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
            raise ValueError('producer input has an invalid source commit')
        if repo != CHARTER and commit != current[repo]:
            raise ValueError('functional producer source changed: ' + repo)
    for name, item in producer['build_inputs'].items():
        if (not isinstance(name, str) or name.startswith('/') or '\\' in name
                or any(part in ('', '.', '..') for part in name.split('/'))
                or not isinstance(item, dict) or set(item) != {'bytes', 'sha256'}
                or type(item['bytes']) is not int or item['bytes'] < 0
                or not isinstance(item['sha256'], str) or not SHA.fullmatch(item['sha256'])):
            raise ValueError('invalid immutable producer build input')
    charter = Path(source_root) / 'abstractions'
    head = subprocess.check_output(['git', '-C', str(charter), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(charter), 'status', '--porcelain=v1',
                                     '--untracked-files=all'], text=True).strip()
    if head != current[CHARTER] or dirty:
        raise ValueError('consumer charter source differs')
    # This exact immutable dependency may not be in the current shallow clone.
    if subprocess.run(['git', '-C', str(charter), 'cat-file', '-e', old[CHARTER] + '^{commit}'],
                      capture_output=True).returncode:
        subprocess.run(['git', '-C', str(charter), 'fetch', '--quiet', '--depth=1',
                        'origin', old[CHARTER]], check=True)
    changed = set(subprocess.check_output(['git', '-C', str(charter), 'diff', '--name-only',
                                           old[CHARTER], head, '--'], text=True).splitlines())
    if not changed <= CHARTER_DERIVED_PATHS:
        raise ValueError('functional charter producer input changed: ' + ', '.join(sorted(changed - CHARTER_DERIVED_PATHS)))
    if changed:
        expected = {CATALOG_PATH, J_RECORD_PATH, MATRIX_PATH, 'coverage.html', 'languages.html',
                    'record_input_digest', 'record_digest', 'generator_receipt_sha256'}
        if (not isinstance(derivation, dict) or set(derivation) != expected
                or any(not isinstance(value, str) or not SHA.fullmatch(value) for value in derivation.values())):
            raise ValueError('catalog change lacks exact current recorder/generator evidence')
        for path in (CATALOG_PATH, J_RECORD_PATH, MATRIX_PATH):
            if sha_file(charter / path) != derivation[path]:
                raise ValueError('current derived output differs: ' + path)
        record = json.loads((charter / J_RECORD_PATH).read_text(encoding='utf-8'))
        checksum = record.pop('record_digest', None)
        canonical = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        if (checksum != hashlib.sha256(canonical).hexdigest() or checksum != derivation['record_digest']
                or record.get('inputs_digest') != derivation['record_input_digest']
                or record.get('schema') != 2 or record.get('result', {}).get('exit') != 0
                or record.get('definition', {}).get('id') != 'shared-javascript-capabilities-windows'):
            raise ValueError('current J recorder evidence differs')
    return {'producer_charter': old[CHARTER], 'consumer_charter': head,
            'changed_paths': sorted(changed), 'derivation': derivation,
            'sources': dict(current), 'build_inputs': producer['build_inputs']}


def checkout(repo, commit, root, *, remote_url=None, env=None):
    dest = Path(root) / repo.split('/', 1)[1]
    if dest.exists():
        raise FileExistsError('source destination already exists: ' + str(dest))
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'init', '--quiet', str(dest)], check=True,env=env)
    subprocess.run(['git', '-C', str(dest), 'remote', 'add', 'origin',
                    remote_url or 'https://github.com/' + repo + '.git'], check=True,env=env)
    subprocess.run(['git', '-C', str(dest), 'fetch', '--quiet', '--depth=1', 'origin', commit], check=True,env=env)
    subprocess.run(['git', '-C', str(dest), 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], check=True,env=env)
    head = subprocess.check_output(['git', '-C', str(dest), 'rev-parse', 'HEAD'], text=True,env=env).strip()
    status = subprocess.check_output(['git', '-C', str(dest), 'status', '--porcelain=v1',
                                      '--untracked-files=all'], text=True,env=env).strip()
    if head != commit or status:
        raise ValueError('public source checkout differs: ' + repo)
    return dest


def _download_http_error(error):
    """Keep actionable status markers without reflected text or private URLs."""
    body = b''
    try:
        body = error.read(512)
    except OSError:
        pass
    finally:
        error.close()
    headers = {}
    patterns = {'CF-Ray': r'[0-9a-f]{16,32}-[A-Z]{3}',
                'CF-Mitigated': r'challenge',
                'Content-Length': r'[0-9]{1,20}',
                'Content-Type': r'(?:text/plain|text/html|application/json|application/octet-stream|binary/octet-stream)(?:; charset=UTF-8)?'}
    for name, pattern in patterns.items():
        value = (error.headers or {}).get(name, '')
        if re.fullmatch(pattern, value):
            headers[name] = value
    message = 'download HTTP ' + str(error.code)
    marker = re.fullmatch(rb'error code: ([0-9]{4})\s*', body)
    if marker:
        message += '; Cloudflare error ' + marker[1].decode('ascii')
    if 'CF-Ray' in headers:
        message += '; CF-Ray ' + headers['CF-Ray']
    return urllib.error.HTTPError('', error.code, message, headers, None)


def checked_download(url, destination, expected_sha256=None, expected_bytes=None, max_bytes=2 << 30,
                     *, expected_sha512=None):
    if (expected_sha256 is None) == (expected_sha512 is None):
        raise ValueError('download requires exactly one reviewed hash')
    expected = expected_sha256 if expected_sha256 is not None else expected_sha512
    pattern = SHA if expected_sha256 is not None else re.compile(r'[0-9a-f]{128}\Z')
    if not url.startswith('https://') or not isinstance(expected, str) or not pattern.fullmatch(expected):
        raise ValueError('download lacks a reviewed HTTPS URL and valid SHA-256 or SHA-512')
    if (type(max_bytes) is not int or max_bytes <= 0
            or expected_bytes is not None and expected_bytes > max_bytes):
        raise ValueError('download exceeds bounded input policy')
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError('download destination already exists: ' + str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + '.partial')
    if partial.exists():
        raise FileExistsError('partial download already exists: ' + str(partial))
    digest = hashlib.sha256()
    verification = digest if expected_sha256 is not None else hashlib.sha512()
    size = 0
    try:
        request = urllib.request.Request(url, headers={'User-Agent': DOWNLOAD_USER_AGENT})
        with urllib.request.urlopen(request, timeout=120) as response, partial.open('xb') as output:
            while block := response.read(1 << 20):
                size += len(block)
                if size > max_bytes or expected_bytes is not None and size > expected_bytes:
                    raise ValueError('download exceeds reviewed byte size: ' + url)
                digest.update(block)
                if verification is not digest:
                    verification.update(block)
                output.write(block)
        if verification.hexdigest() != expected or expected_bytes is not None and size != expected_bytes:
            raise ValueError('download differs from reviewed digest/size: ' + url)
        partial.replace(destination)
    except urllib.error.HTTPError as error:
        raise _download_http_error(error) from None
    finally:
        partial.unlink(missing_ok=True)
    return {'name': destination.name, 'sha256': digest.hexdigest(), 'bytes': size}


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def imported(path):
    path = Path(path)
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location('oa_exact_app_package', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _go_source_owner(path, raw, rows=None):
    """Execute captured selected source without bytecode or a second file read."""
    module = types.ModuleType('oa_selected_go_owner')
    module.__file__ = str(path)
    if rows is not None:
        import builtins
        def selected_import(name, *args, **kwargs):
            if name == 'release_tsv_rows':return rows
            return builtins.__import__(name, *args, **kwargs)
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=selected_import)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def materialize_desktop_go(pins, source_root, input_root, sdk_receipt):
    """Produce the existing role from source-owned public graph and canonical SDK.

    The returned digest is measured input DATA, awaiting independent policy
    admission. Neither caller JSON nor an ambient module cache supplies a graph.
    """
    from git_env import source_git_environment
    source_root, input_root, sdk_receipt = (Path(p).absolute() for p in (source_root,input_root,sdk_receipt))
    def ordinary(path, *, file=False):
        for parent in (path, *path.parents):
            if parent.is_symlink() or parent.is_junction(): raise ValueError('linked Go input')
        if file and (not path.is_file() or path.stat().st_nlink != 1):
            raise ValueError('Go input must be an ordinary single-link file')
    def sources():
        for repo, commit in pins.items():
            if not re.fullmatch(r'openabstractions/[A-Za-z0-9._-]+', repo) or not COMMIT.fullmatch(commit):
                raise ValueError('invalid selected Go source identity')
            root = source_root / repo.split('/', 1)[1]; ordinary(root)
            env = source_git_environment()
            head = subprocess.check_output(['git','--no-replace-objects','-C',str(root),'rev-parse','HEAD'],text=True,env=env,timeout=30).strip()
            dirty = subprocess.check_output(['git','--no-replace-objects','-C',str(root),'status','--porcelain=v1','--untracked-files=all'],text=True,env=env,timeout=30).strip()
            if head != commit or dirty: raise ValueError('selected Go source checkout differs: ' + repo)
    if not {'openabstractions/redist', CHARTER, 'openabstractions/adopter-comfyui'} <= set(pins):
        raise ValueError('Go materialization requires selected installer sources')
    sources()
    redist = source_root / 'redist'
    owned = {'tools/windows_go_sdk.py','tools/windows_go_sdk.patch','scripts/module_provenance.py',
             'scripts/file_boundary.py','scripts/release_tsv_rows.py','public-go-graph.json','public-go-graph.zip'}
    raw = subprocess.check_output(['git','--no-replace-objects','-C',str(redist),'ls-tree','-z',pins['openabstractions/redist'],'--',*sorted(owned)],
                                  env=source_git_environment(),timeout=30)
    tracked = {}
    for record in raw.split(b'\0'):
        if not record:continue
        header,name=record.split(b'\t',1);mode,kind,oid=header.split()
        if mode not in (b'100644',b'100755') or kind!=b'blob':raise ValueError('Go source owner mode differs')
        tracked[name.decode('utf-8')]=oid.decode('ascii')
    if set(tracked)!=owned:raise ValueError('Go graph or owner is not committed in selected redist source')
    captured = {}
    for name,oid in sorted(tracked.items()):
        path=redist/name;ordinary(path,file=True)
        limit=((80<<20)-1 if name.endswith('.zip') else
               1<<20 if name=='public-go-graph.json' else 4<<20)
        command=['git','--no-replace-objects','-C',str(redist),'cat-file']
        size=int(subprocess.check_output([*command,'-s',oid],env=source_git_environment(),timeout=30))
        if not 0<=size<=limit:raise ValueError('selected Go source exceeds bound')
        value=subprocess.check_output([*command,'blob',oid],env=source_git_environment(),timeout=30)
        if len(value)!=size or hashlib.sha1(b'blob '+str(size).encode()+b'\0'+value).hexdigest()!=oid:
            raise ValueError('selected Go blob differs')
        with path.open('rb') as reader:current=reader.read(limit+1)
        if current!=value:raise ValueError('Go source bytes differ from selected commit: '+name)
        captured[name]=value
    sdk = _go_source_owner(redist/'tools/windows_go_sdk.py',captured['tools/windows_go_sdk.py'])
    if hashlib.sha256(captured['tools/windows_go_sdk.patch'].replace(b'\r\n',b'\n')).hexdigest()!=sdk.PATCH_SHA256:
        raise ValueError('selected SDK patch differs from source owner')
    rows = _go_source_owner(redist/'scripts/release_tsv_rows.py',captured['scripts/release_tsv_rows.py'])
    graph_owner = _go_source_owner(redist/'scripts/module_provenance.py',captured['scripts/module_provenance.py'],rows)
    boundary = _go_source_owner(redist/'scripts/file_boundary.py',captured['scripts/file_boundary.py'])
    ordinary(sdk_receipt,file=True)
    if sdk_receipt.stat().st_size > 1 << 20: raise ValueError('Go SDK receipt exceeds bound')
    receipt_raw = sdk_receipt.read_bytes();receipt = json.loads(receipt_raw)
    sdk.validate_sdk_receipt(receipt)
    if not boundary.same_existing_file(sdk_receipt,Path(receipt['receipt_path'])):
        raise ValueError('Go SDK receipt moved from its canonical owner')
    sdk_root = Path(receipt['goroot']); archive = sdk_root.parent/'archive.zip'
    ordinary(archive,file=True)
    if sha_file(archive) != sdk.ARCHIVE_SHA256: raise ValueError('Go SDK archive differs')
    # Reuse the SDK owner's authenticated archive+patch derivation for every
    # copied SDK byte, rather than trusting a second filesystem traversal.
    sdk_files = sdk._archive_files(archive)
    if sdk._identity(sdk_files) != receipt['source_identity']:raise ValueError('Go SDK derivation differs')
    sidecar, capsule = redist/'public-go-graph.json',redist/'public-go-graph.zip'
    for path in (sidecar,capsule): ordinary(path,file=True)
    if sidecar.stat().st_size > 1 << 20 or capsule.stat().st_size >= 80 << 20:
        raise ValueError('prepared Go graph exceeds public owner bounds')
    graph = json.loads(captured['public-go-graph.json']); payload = captured['public-go-graph.zip']
    if graph.get('schema') != 2: raise ValueError('Go role requires complete prepared graph')
    graph_owner.unpack_staged_graph(payload,None,graph)
    module = 'github.com/openabstractions/abstraction-provider-kit/go'
    selected = [row for row in graph['modules'] if row['module'] == module]
    if len(selected) != 1: raise ValueError('prepared provider-kit module missing')
    row = selected[0]
    prefix = 'proxy/' + graph_owner.escape_module(module) + '/@v/' + row['version']
    desktop = input_root/'desktop-inputs'; ordinary(desktop)
    target, descriptor = desktop/'go',desktop/'go.json'
    if target.exists() or target.is_symlink() or descriptor.exists() or descriptor.is_symlink():
        raise ValueError('Go role requires fresh output paths')
    desktop.mkdir(parents=True,exist_ok=True)
    created = False; descriptor_created = False; files = {}; seen = set(); directories = {}
    def member(name):
        parts = name.split('/')
        if (not name or '\\' in name or ':' in name or any(ord(c)<32 for c in name)
                or any(p in ('','.','..') or p.endswith(('.', ' ')) for p in parts)
                or any(p.split('.')[0].casefold() in {'con','prn','aux','nul',*(f'com{i}' for i in range(1,10)),*(f'lpt{i}' for i in range(1,10))} for p in parts)
                or name.casefold() in seen or len(files) >= 100000):
            raise ValueError('unsafe or aliased Go role member')
        seen.add(name.casefold())
        for count in range(1,len(parts)):
            prefix='/'.join(parts[:count]);previous=directories.setdefault(prefix.casefold(),prefix)
            if previous!=prefix:raise ValueError('aliased Go role directory')
        return target.joinpath(*parts)
    def copy(name, reader, size):
        digest=hashlib.sha256();total=0
        with reader:
            path = member(name);path.parent.mkdir(parents=True,exist_ok=True)
            with path.open('xb') as writer:
                while True:
                    chunk=reader.read(min(1<<20,size-total+1))
                    if not chunk:break
                    total+=len(chunk)
                    if total>size:raise ValueError('Go input changed during materialization')
                    digest.update(chunk);writer.write(chunk)
        if total!=size:raise ValueError('Go input truncated during materialization')
        files[name]={'bytes':total,'sha256':digest.hexdigest()}
    try:
        target.mkdir();created=True
        with zipfile.ZipFile(io.BytesIO(payload)) as capsule:
            with zipfile.ZipFile(io.BytesIO(capsule.read(prefix+'.zip'))) as module_zip:
                module_prefix=module+'@'+row['version']+'/'
                if sum(i.file_size for i in module_zip.infolist()) >= 2 << 30:
                    raise ValueError('prepared module exceeds public graph expansion bound')
                for entry in module_zip.infolist():
                    if entry.is_dir():continue
                    if not entry.filename.startswith(module_prefix):raise ValueError('prepared module prefix differs')
                    copy('module/'+entry.filename[len(module_prefix):],module_zip.open(entry),entry.file_size)
            mod=(target/'module/go.mod').read_text(encoding='utf-8')
            if (not re.search(r'(?m)^module '+re.escape(module)+r'\s*$',mod)
                    or re.search(r'(?m)^\s*replace\b',mod) or not (target/'module/go.sum').is_file()):
                raise ValueError('prepared provider-kit module differs or has replacements')
            for entry in graph['files']:
                copy(entry['path'],capsule.open(entry['path']),entry['bytes'])
                if files[entry['path']] != {key:entry[key] for key in ('bytes','sha256')}:
                    raise ValueError('prepared proxy changed during materialization')
        for name,raw in sdk_files.items():copy('go/'+name,io.BytesIO(raw),len(raw))
        copy('archive.zip',archive.open('rb'),archive.stat().st_size)
        if files['archive.zip']['sha256'] != sdk.ARCHIVE_SHA256:raise ValueError('Go SDK archive changed during copy')
        copy('sdk-receipt.json',io.BytesIO(receipt_raw),len(receipt_raw))
        sdk.validate_sdk_receipt(receipt);sources()
        if files['go/bin/go.exe']['sha256'] != receipt['source_identity']['go_exe_sha256']:
            raise ValueError('materialized Go compiler differs from canonical SDK')
        value={'schema':1,'entry':'go/bin/go.exe','files':files}
        raw=(json.dumps(value,sort_keys=True)+'\n').encode('utf-8')
        if len(raw)>4<<20:raise ValueError('Go role descriptor exceeds consumer bound')
        with descriptor.open('xb') as writer:descriptor_created=True;writer.write(raw)
        return {'name':'desktop-inputs/go.json','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    except BaseException:
        if descriptor_created:descriptor.unlink()
        if created:boundary.remove_tree(target)
        raise


def preflight(app, charter, destination, minimum_free_gib):
    if minimum_free_gib < 1:
        raise ValueError('disposable runner must retain at least one GiB free')
    Path(destination).mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(destination).free
    if app != 'comfyui':
        raise ValueError('unknown optional app producer')
    package = imported(Path(charter) / 'scripts/package_comfyui_app.py')
    backend = selected_comfy_backend(Path(charter).parent, destination, package)
    if backend is not None:
        descriptor = Path(destination) / 'backend-inputs.json'
        raw = descriptor.read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (backend['bytes'], backend['sha256']):
            raise ValueError('backend descriptor changed after input admission')
        selected = json.loads(raw)
        pins = {row['name']: row['bytes'] for row in selected['files']}
        extra_wheels = (0 if package._backend_reuses_snapshot_wheels(selected, pins) else
                        sum(pins[row['file']] for row in selected['wheels']))
        required = package._backend_capacity(sum(pins.values()) + len(raw), extra_wheels, None, 0, 0, 0,
            max(minimum_free_gib << 30, package.backend_limits()['reserve_bytes']), phase='inputs')
        if free < required:
            raise OSError('AMD backend needs bounded snapshot/build/output space')
        print(json.dumps({'app': app, 'mode': 'manager-free-amd-backend', 'free_bytes': free,
                          'required_free_bytes': required, 'input_descriptor': backend,
                          'capacity_scope': 'input lower bound; exact source/integration/tool phases admitted by producer'}, sort_keys=True))
        return
    # Downloaded inputs still have to fit *before* repack's own preflight.
    input_bytes = package.SOURCE_BYTES + sum(row[0] for row in package.CPU_WHEELS.values())
    required = package.required_free_bytes(minimum_free_after_build_bytes=minimum_free_gib << 30)
    required += input_bytes + (2 << 30)  # source checkouts and input artifacts
    if free < required:
        raise OSError(f'{app} producer needs {required:,} free bytes before downloads; has {free:,}')
    print(json.dumps({'app': app, 'free_bytes': free, 'required_free_bytes': required,
                      'minimum_free_after_build_gib': minimum_free_gib}, sort_keys=True))


def comfy_source_checkouts(source_root, input_root):
    package = imported(Path(source_root) / 'abstractions/scripts/package_comfyui_app.py')
    upstream = Path(input_root) / 'upstream'
    checkout('Comfy-Org/ComfyUI_frontend', package.FRONTEND_COMMIT, upstream)
    for name, (commit, _) in package.ADDITIONAL_SOURCES.items():
        repo = {'embedded-docs': 'Comfy-Org/embedded-docs',
                'pygit2': 'libgit2/pygit2', 'libgit2': 'libgit2/libgit2'}[name]
        checkout(repo, commit, upstream)


def _selected_comfy_backend_policy(policy):
    policy=Path(policy)
    if policy.is_symlink() or policy.is_junction():raise ValueError('linked selected ComfyUI application policy')
    host=json.loads(policy.read_bytes())
    if host.get('schema')==1:return None
    if host.get('schema')!=2 or host.get('distribution') not in ('oa-custom-desktop','oa-comfyui-native'):
        raise ValueError('unsupported selected ComfyUI application source policy')
    return host


def selected_comfy_backend(source_root, input_root, package):
    """Use the exact selected adopter policy; absent staged hashes never select CPU.

    Acquisition of a newly reviewed full closure is a separate admitted step.
    This existing input owner verifies it before the backend builder can run.
    """
    policy = Path(source_root) / 'adopter-comfyui/.installer/desktop-host.json'
    if not policy.exists():
        return None  # old source layouts predate the custom Desktop producer
    host=_selected_comfy_backend_policy(policy)
    if host is None:return None
    expected = host.get('build_inputs', {}).get('backend')
    if (not isinstance(expected, dict) or set(expected) != {'bytes', 'sha256'}
            or type(expected['bytes']) is not int or not 0 < expected['bytes'] <= (4 << 20)
            or not SHA.fullmatch(str(expected['sha256']))):
        raise ValueError('Manager-free AMD backend input closure is not admitted in selected source')
    descriptor = Path(input_root) / 'backend-inputs.json'
    if not descriptor.is_file() or descriptor.stat().st_size != expected['bytes']:
        raise ValueError('selected AMD backend descriptor is not staged')
    package.backend_inputs(descriptor, expected['sha256'])
    return dict(expected)


def comfy_archive_tool(input_root, package, *, acquire=False):
    """Materialize only the selected private build tool, source and notices."""
    root = Path(input_root).absolute() / 'archive-tool'
    if root.parent.resolve() != root.parent or not root.parent.is_dir():
        raise ValueError('archive tool inputs require an ordinary staged directory')
    if root.exists() and (root.is_symlink() or root.resolve() != root or not root.is_dir()):
        raise ValueError('linked archive tool input root')
    if acquire:
        import tarfile
        policy = json.loads(package.BACKEND_POLICY.read_bytes())['archive_tool']
        if policy.get('version') != '26.05' or policy.get('name') != '7zr.exe':
            raise ValueError('unsupported source-selected archive tool')
        root.mkdir(parents=True, exist_ok=True)
        for row in (policy, policy['source']):
            package._safe_name(row['name'])
            target = root / row['name']
            if not target.exists():
                checked_download(row['url'], target, expected_sha256=row['sha256'],
                    expected_bytes=row['bytes'], max_bytes=row['bytes'])
            package._backend_file(root, row['name'])
            if package._sha256(target) != (row['bytes'], row['sha256']):
                raise ValueError('archive tool/source differs before notice inspection')
        # Read fixed notice members as DATA; no tar extraction or source execution.
        with tarfile.open(root / policy['source']['name'], 'r:xz') as archive:
            for row in policy['notices']:
                if not isinstance(row['name'],str) or '\\' in row['name']:
                    raise ValueError('unsafe archive notice path')
                for component in row['name'].split('/'): package._safe_name(component)
                member = archive.getmember(row['name'])
                if not member.isfile() or member.size != row['bytes']:
                    raise ValueError('archive tool notice differs from selected source')
                raw = archive.extractfile(member).read(row['bytes'] + 1)
                if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                    raise ValueError('archive tool notice hash differs')
                target = root / 'notices' / row['name']
                parent = root
                for component in target.relative_to(root).parts[:-1]:
                    parent = parent / component
                    parent.mkdir(exist_ok=True)
                    if parent.is_symlink() or parent.resolve() != parent or not parent.is_dir():
                        raise ValueError('linked archive tool notice directory')
                if not target.exists():
                    with target.open('xb') as stream: stream.write(raw)
    tool = root / '7zr.exe'
    package._archive_tool_inputs(tool)
    return tool


def verify_backend_output(directory, expected_input, candidate_source, run_id, run_attempt):
    """Producer readback only; the later receiver independently authenticates API bytes."""
    from app_pair_receipt import read_backend_producer
    directory = Path(directory).absolute()
    path = directory / 'backend-producer.json'
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError('backend output receipt is not ordinary')
    pin = {'name':path.name,'bytes':path.stat().st_size,'sha256':sha_file(path)}
    receipt = read_backend_producer(path,expected_receipt=pin,
        expected_input=dict(expected_input,name='backend-inputs.json'),
        candidate_source=candidate_source,run_id=run_id,run_attempt=run_attempt)
    names = {path.name}
    for key in ('archive','source_pair'):
        names.update(part['name'] for part in (receipt[key]['parts'] if receipt['schema']==3 else [receipt[key]]))
    if {member.name for member in directory.iterdir()} != names:
        raise ValueError('backend producer output has unpinned extras')
    return receipt


def successful_hosted_input(run_id, source, select, prefix, *, descriptor=False):
    """Select an unexpired artifact from one successful job of this exact run."""
    token, repo = os.environ.get('GH_TOKEN'), os.environ.get('GH_REPO')
    if (not token or not repo or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)
            or type(run_id) is not int or run_id <= 0 or not COMMIT.fullmatch(source)):
        raise ValueError('GitHub artifact selection requires trusted run and source')
    def pages(kind):
        found = []
        for page in range(1, 101):
            query = 'filter=all&' if kind == 'jobs' else ''
            url = f'https://api.github.com/repos/{repo}/actions/runs/{run_id}/{kind}?{query}per_page=100&page={page}'
            request = urllib.request.Request(url, headers={
                'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'})
            with urllib.request.urlopen(request, timeout=60) as response:
                batch = json.load(response)[kind]
            if not isinstance(batch, list):
                raise ValueError('malformed GitHub run ' + kind)
            found.extend(batch)
            if len(batch) < 100:
                return found
        raise ValueError('GitHub run ' + kind + ' exceeds bounded pagination')
    selected = select(pages('jobs'), pages('artifacts'), run_id, source)
    match = re.fullmatch(re.escape(prefix) + r'-([1-9][0-9]*)', selected['name'])
    result = {'artifact': selected['name'], 'run_attempt': int(match[1])}
    if descriptor:
        if (type(selected.get('id')) is not int or selected['id']<=0 or
                not re.fullmatch(r'sha256:[0-9a-f]{64}',str(selected.get('digest')))):
            raise ValueError('selected installer SDK artifact lacks immutable API identity/digest')
        result.update(artifact_id=selected['id'],artifact_digest=selected['digest'])
    return result


def successful_wheel_input(run_id, source, *, descriptor=False):
    return successful_hosted_input(run_id, source, select_windows_wheel_artifact,
                                   'abstraction-pypi-win32-x64',descriptor=descriptor)


def successful_addon_input(run_id, source, *, descriptor=False):
    return successful_hosted_input(run_id, source, select_windows_addon_artifact,
                                   'abstraction-npm-win32-x64',descriptor=descriptor)


def verified_addon_tarball(artifact_dir, version):
    """Bind the Windows addon tarball to every checksum from its selected JS artifact."""
    artifact_dir = Path(artifact_dir)
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', version):
        raise ValueError('invalid candidate npm version')
    checksums = artifact_dir / 'SHA256SUMS.npm.win32-x64'
    rows = {}
    for line in checksums.read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ?([A-Za-z0-9_.-]+\.tgz)', line)
        if not match or match[2] in rows:
            raise ValueError('malformed or duplicate Windows npm checksum')
        rows[match[2]] = match[1]
    actual = {path.name for path in artifact_dir.glob('*.tgz')}
    if len(rows) != 10 or actual != set(rows):
        raise ValueError('Windows npm artifact differs from exact package roster')
    for name, expected in rows.items():
        if sha_file(artifact_dir / name) != expected:
            raise ValueError('Windows npm artifact has a mismatched tarball: ' + name)
    target = artifact_dir / f'openabstractions-ipc-win32-x64-{version}.tgz'
    if target.name not in rows:
        raise ValueError('Windows npm artifact lacks the pinned IPC platform addon')
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('pins', 'checkout', 'receipt', 'preflight', 'download-comfy',
                                             'select-wheels', 'select-addon', 'verify-addon-artifact', 'verify-backend-output',
                                             'materialize-desktop-go'))
    parser.add_argument('--app', choices=('comfyui', 'opencode', 'lemonade'), required=True)
    parser.add_argument('--npm-pins', default='npm.tsv')
    parser.add_argument('--pypi-pins', default='pypi.tsv')
    parser.add_argument('--app-pins', default='app-sources.tsv')
    parser.add_argument('--roster', default='apps.json')
    parser.add_argument('--source-root', default='sources')
    parser.add_argument('--input-root', default='app-build-inputs')
    parser.add_argument('--minimum-free-gib', type=int, default=1)
    parser.add_argument('--candidate-source')
    parser.add_argument('--run-id', type=int)
    parser.add_argument('--run-attempt', type=int)
    parser.add_argument('--output-root', default='app-output')
    parser.add_argument('--candidate-version')
    parser.add_argument('--producer-only', action='store_true')
    parser.add_argument('--adopter-commit', default=None)
    parser.add_argument('--sdk-receipt',type=Path,help='materialize-desktop-go: existing canonical validated Windows Go SDK receipt')
    parser.add_argument('--installer', action='store_true', help='Use accepted installer obligations; preserve legacy archive input semantics')
    args = parser.parse_args(argv)
    if args.operation=='materialize-desktop-go' and (not args.installer or args.app!='comfyui' or args.sdk_receipt is None):
        raise ValueError('Go role materialization requires Comfy installer source admission and canonical SDK receipt')
    if args.operation == 'verify-backend-output':
        if args.app != 'comfyui': raise ValueError('backend output belongs to ComfyUI')
        policy=Path(args.source_root)/'adopter-comfyui/.installer/desktop-host.json'
        selected=_selected_comfy_backend_policy(policy)
        if selected is None:raise ValueError('backend output requires selected custom AMD application policy')
        expected=selected['build_inputs']['backend']
        if not isinstance(expected,dict) or set(expected)!={'bytes','sha256'}:
            raise ValueError('backend input pin is not admitted')
        print(json.dumps(verify_backend_output(args.output_root,expected,args.candidate_source,args.run_id,args.run_attempt),sort_keys=True))
        return 0
    if args.operation == 'select-wheels':
        print(json.dumps(successful_wheel_input(args.run_id, args.candidate_source,descriptor=args.installer), sort_keys=True))
        return
    if args.operation == 'select-addon':
        print(json.dumps(successful_addon_input(args.run_id, args.candidate_source,descriptor=args.installer), sort_keys=True))
        return
    if args.operation == 'verify-addon-artifact':
        print(verified_addon_tarball(args.input_root, args.candidate_version))
        return
    if args.installer:
        if args.operation not in ('pins', 'checkout', 'receipt','materialize-desktop-go') or args.producer_only or args.adopter_commit is not None:
            raise ValueError('installer source intake supports only exact pins/checkout/receipt; legacy downloads are separate')
        if not args.candidate_version:
            raise ValueError('installer source intake requires the exact release version')
        pins = installer_source_pins(args.app, args.npm_pins, args.pypi_pins, args.app_pins,
                                     args.roster, args.candidate_version, producer_source=args.candidate_source)
    else:
        pins = source_pins(args.app, args.npm_pins, args.pypi_pins, args.app_pins, args.roster,
                           producer_only=args.producer_only, adopter_commit=args.adopter_commit)
    if args.operation == 'materialize-desktop-go':
        if not args.installer or args.app!='comfyui' or args.sdk_receipt is None:
            raise ValueError('Go role materialization requires Comfy installer source admission and canonical SDK receipt')
        print(json.dumps(materialize_desktop_go(pins,args.source_root,args.input_root,args.sdk_receipt),sort_keys=True))
        return 0
    if args.operation == 'pins':
        print(json.dumps(pins, sort_keys=True))
    elif args.operation == 'checkout':
        for repo, commit in pins.items():
            checkout(repo, commit, args.source_root)
    elif args.operation == 'receipt':
        if not args.installer:
            raise ValueError('receipt operation is for source-declared installers')
        print(json.dumps(pinned_input_receipt(pins,args.source_root,args.input_root),sort_keys=True))
    elif args.operation == 'preflight':
        preflight(args.app, Path(args.source_root) / 'abstractions', Path(args.input_root),
                  args.minimum_free_gib)
    else:
        package = imported(Path(args.source_root) / 'abstractions/scripts/package_comfyui_app.py')
        dest = Path(args.input_root)
        if selected_comfy_backend(args.source_root, dest, package) is not None:
            return 0
        comfy_source_checkouts(args.source_root, dest)
        checked_download(package.SOURCE_URL, dest / 'ComfyUI_windows_portable_amd.7z',
                         package.SOURCE_SHA256, package.SOURCE_BYTES)
        for name, (size, sha256, _) in package.CPU_WHEELS.items():
            family = name.split('-', 1)[0]
            checked_download(package.CPU_WHEEL_PROVENANCE[family][0], dest / 'cpu-wheels' / name,
                             sha256, size)


if __name__ == '__main__':
    main()
