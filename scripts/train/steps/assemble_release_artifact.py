import hashlib, json, os, pathlib, re, shutil, sys


def fact_owner():
    import types
    target = pathlib.Path(__file__).resolve().parents[2] / 'release_facts.py'
    if not target.is_file():
        target = pathlib.Path(__file__).resolve().parents[3] / 'release/facts.py'
    module = types.ModuleType('oa_assembled_release_facts'); module.__file__ = str(target)
    exec(compile(target.read_bytes(), str(target), 'exec'), module.__dict__)
    return module


def producer_facts(candidate, directory):
    """Read the existing checksum roster and measured signed package bytes."""
    import re
    directory = pathlib.Path(directory); assets = []; seen = set()
    for line in (directory / 'SHA256SUMS').read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *](\S+)', line)
        if not match or match[2] in seen or pathlib.PurePosixPath(match[2]).name != match[2] or '\\' in match[2]:
            raise ValueError('invalid producer checksum roster')
        seen.add(match[2]); target = directory / match[2]
        if target.is_symlink() or not target.is_file(): raise ValueError('producer asset is not an ordinary file')
        checksum = hashlib.sha256(); size = 0
        with target.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                checksum.update(chunk); size += len(chunk)
        if checksum.hexdigest() != match[1]: raise ValueError('producer asset changed: ' + match[2])
        if (tuple(map(int, candidate['version'].removeprefix('v').split('-')[0].split('.'))) >= (0, 8, 0)
                and target.suffix == '.msi'):
            proofs = [row for row in candidate['windows_signing']['files'] if row['name'] == 'core/' + match[2]]
            if len(proofs) != 1 or (proofs[0]['sha256'], proofs[0]['bytes']) != (match[1], size):
                raise ValueError('final MSI asset differs from its authenticated signing proof')
            fact_owner().public_msi_members(proofs[0].get('msi_members'))
        assets.append({'name': match[2], 'artifact': {'sha256': match[1], 'bytes': size}})
    return fact_owner().producer_record(candidate, assets, unsigned_platforms=['linux'])


def received_windows_proofs(directory, *, source, run_id, attempt, artifact):
    """Consume the existing API inventory before parsing carried metadata."""
    directory = pathlib.Path(directory)
    def read(name, pin=None):
        path = directory / name
        if path.is_symlink() or path.is_junction() or not path.is_file():
            raise ValueError('Windows proof is not an ordinary admitted member')
        with path.open('rb') as stream:
            stat = os.fstat(stream.fileno())
            if stat.st_nlink != 1 or stat.st_size > 8 << 20:
                raise ValueError('Windows proof has linked or oversized metadata')
            raw = stream.read((8 << 20) + 1)
        after = path.stat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_nlink) != (stat.st_dev, stat.st_ino, len(raw), 1):
            raise ValueError('Windows proof identity changed during consumption')
        if (pin is not None and (len(raw), hashlib.sha256(raw).hexdigest()) != (pin['bytes'], pin['sha256'])):
            raise ValueError('Windows proof differs from authenticated member inventory')
        return raw
    intake = json.loads(read('windows-artifact-intake.json'))
    if (not isinstance(intake, dict) or set(intake) != {'schema','kind','source','run_id','run_attempt','artifact','files'}
            or type(intake['schema']) is not int or intake['schema'] != 1 or intake['kind'] != 'windows-artifact-intake'
            or any(type(intake[key]) is not int for key in ('run_id','run_attempt'))
            or intake['source'] != source or intake['run_id'] != run_id or intake['run_attempt'] != attempt
            or intake['artifact'] != artifact or not isinstance(intake['files'], list)):
        raise ValueError('Windows artifact differs from independent source/run/API identity')
    pins = {}
    for row in intake['files']:
        if (not isinstance(row, dict) or set(row) != {'name','sha256','bytes'}
                or not isinstance(row['name'], str) or row['name'] in pins or row['name'] in ('', '.', '..')
                or pathlib.PurePosixPath(row['name']).name != row['name']
                or '\\' in row['name'] or ':' in row['name'] or type(row['bytes']) is not int or row['bytes'] < 0
                or not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256'])):
            raise ValueError('invalid Windows artifact member inventory')
        pins[row['name']] = row
    names = ('windows-signatures.json', 'windows-installer-chain.json', 'windows-app-chain-context.json')
    if any(name not in pins for name in names):
        raise ValueError('missing Windows installer proof member')
    return tuple(json.loads(read(name, pins[name])) for name in names)


def required_signed_installers(document, version, verified_signatures, validate, source, *, chain=None, owner=None,catalog=None):
    """Project an independently verified same-run receipt; grant no authority.

    The existing artifact intake and signing receiver authenticate the input.
    This receiving check preserves installer obligations in candidate metadata
    even when the separate legacy Panel archive catalogue is empty.
    """
    validate(document.get('release_admission'),version,document['apps'],source,require_delivery=False)
    required = {row['id'] for row in document['release_admission']['outcomes']['adopters']
                if row['target'] == 'windows-x64'}
    if chain is None:
        raise ValueError('missing authenticated installer chain: ' + ', '.join(sorted(required)))
    if owner is None:
        import types
        target = pathlib.Path('windows/apps/build_bundle.py')
        if not target.is_file():
            target = pathlib.Path(__file__).resolve().parents[3] / 'installer/apps/build_bundle.py'
        owner = types.ModuleType('oa_candidate_chain_roles'); owner.__file__ = str(target)
        exec(compile(target.read_bytes(), str(target), 'exec'), owner.__dict__)
    if not isinstance(chain, dict) or set(chain) != {'version', 'apps'} or chain['version'] != version:
        raise ValueError('signed installer chain version/shape differs')
    signatures = {row['name']: row for row in verified_signatures['files']}
    if len(signatures) != len(verified_signatures['files']):
        raise ValueError('duplicate signed installer proof')
    core = signatures.get('core/abstraction-x64.msi')
    if core is None:
        raise ValueError('missing final signed core proof')
    for arch in ('x64', 'arm64'):
        proof = signatures.get('core/abstraction-' + arch + '.msi')
        if proof is None:
            raise ValueError('missing final signed core proof')
        fact_owner().public_msi_members(proof.get('msi_members'))
    selected = owner.validate_chain(dict(chain, core={
        'file': core['name'], 'sha256': core['sha256'], 'bytes': core['bytes']}), pathlib.Path('.'))
    catalog=catalog or {}
    chain_ids={app['id'] for app in selected['apps']}
    if (not isinstance(catalog,dict) or chain_ids&set(catalog) or chain_ids|set(catalog)!=required):
        raise ValueError('signed installer chain differs from selected adopter scope')
    found, errors, names = [], [], set()
    for app_id,admitted in catalog.items():
        actual=admitted.get('delivery',{});identity=actual.get('identity',{});host=admitted.get('host',{})
        if (actual.get('app')!=app_id or identity.get('distribution')!='oa-comfyui-native' or
                identity.get('version')!=version or admitted.get('source')!=source or
                identity.get('producer')!={key:admitted.get(key) for key in ('source','run_id','run_attempt')}):
            raise ValueError('required catalog application lacks actual native delivery')
        name='apps/'+str(host.get('name',''))
        proof=signatures.get(name)
        if (name!='apps/apps/'+app_id+'/'+str(identity.get('programs',{}).get('application','')) or proof is None or
                any(proof.get(key)!=host.get(key) for key in ('bytes','sha256')) or
                any(host.get('signature',{}).get(key)!=proof.get(key) for key in ('bytes','sha256'))):
            raise ValueError('catalog application lacks its exact verified native host signature')
        names.add(name)
    for role, kind, package, app in owner.chain_packages(selected):
        if app is None:
            continue
        name = 'apps/apps/' + app['id'] + '/' + pathlib.Path(package['file']).name
        if name in names:
            raise ValueError('duplicate selected installer role')
        names.add(name)
        proof = signatures.get(name)
        # Official supplier hosts retain their independent source pin. Modern
        # custom Desktop host/preparation roles have OA final signing proofs.
        if proof is None and package is app.get('host') and 'embedded_integration' not in app:
            found.append({'id': app['id'], 'name': role, 'kind': kind,
                'artifact': {key: package[key] for key in ('sha256', 'bytes')},
                'verification': 'source-owned supplier pin; no OA signing observation'})
            continue
        if proof is None:
            errors.append('missing signed installer role: ' + role)
            continue
        if package is not app and any(proof.get(key) != package[key] for key in ('sha256', 'bytes')):
            errors.append('signed installer role differs from chain pin: ' + role)
        if kind == 'MsiPackage':
            fact_owner().public_msi_members(proof.get('msi_members'))
        found.append({'id': app['id'], 'name': role, 'kind': kind, 'signature': proof})
    extras = {name for name in signatures if name.startswith('apps/apps/')} - names
    errors += ['foreign signed installer: ' + name for name in sorted(extras)]
    if errors:
        raise ValueError('; '.join(errors))
    return sorted(found, key=lambda row: (row['id'], row['name']))


def copy_app_assets(apps,directory,destination):
    """Copy the existing flat binary and ordered corresponding-source carrier."""
    sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]))
    from app_pair_receipt import validate_archive_set,_ordinary_archive_file,_archive_pin
    directory=pathlib.Path(directory).absolute();destination=pathlib.Path(destination).absolute()
    for root in (directory,destination):
        if (root.resolve(strict=True)!=root or root.is_symlink() or root.is_junction() or not root.is_dir() or
                getattr(root.lstat(),'st_file_attributes',0)&0x400):
            raise ValueError('release application copy root is linked or noncanonical')
    selected=[];names=set()
    for app in apps:
        source=app['source']
        parts=(validate_archive_set(source,format='zip')['parts'] if 'parts' in source else [source])
        binary=app['binary']
        if 'parts' not in source:
            if (set(binary)!={'name','bytes','sha256','source_name','source_sha256'} or
                    binary['source_name']!=source.get('name') or binary['source_sha256']!=source.get('sha256')):
                raise ValueError('legacy application binary source linkage differs')
            binary={key:binary[key] for key in ('name','bytes','sha256')}
        for pin in (binary,*parts):
            _archive_pin(pin)
            name=pin['name']
            if (not isinstance(name,str) or pathlib.PurePosixPath(name).name!=name or '\\' in name or ':' in name or
                    name.casefold() in names or (destination/name).exists()):
                raise ValueError('release application asset name collides or escapes')
            names.add(name.casefold());selected.append((_ordinary_archive_file(directory,name),pin))
    created=[]
    try:
        for source,pin in selected:
            before=source.lstat();digest=hashlib.sha256();size=0;target=destination/pin['name']
            with source.open('rb') as reader,target.open('xb') as writer:
                created.append(target)
                opened=os.fstat(reader.fileno())
                if (opened.st_dev,opened.st_ino,opened.st_nlink)!=(before.st_dev,before.st_ino,1):
                    raise ValueError('release application asset identity changed before copy')
                for block in iter(lambda:reader.read(1<<20),b''):
                    size+=len(block)
                    if size>pin['bytes']:raise ValueError('release application asset exceeds pin')
                    digest.update(block);writer.write(block)
            _ordinary_archive_file(directory,pin['name'])
            after=source.lstat()
            if ((size,digest.hexdigest())!=(pin['bytes'],pin['sha256']) or
                    after.st_nlink!=1 or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)):
                raise ValueError('release application asset changed')
    except BaseException:
        for target in created:target.unlink()
        raise


def main():
    preview = os.environ['PREVIEW'].lower()
    if preview not in ('true', 'false'):
        raise SystemExit('preview must be a boolean')
    apps = json.loads((pathlib.Path(os.environ['RUNNER_TEMP']) / 'apps.json').read_text(encoding='utf-8'))
    copy_app_assets(apps,'dist','verified-release')
    candidate = {'schema': 1, 'source': os.environ['CANDIDATE_SHA'],
        'version': os.environ['RELEASE_VERSION'], 'run_id': int(os.environ['GITHUB_RUN_ID']),
        'run_attempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'preview': preview == 'true',
        'kind': 'release-candidate', 'windows_signing': None,
        'macos': os.environ['MACOS_STATE'], 'apps': apps}
    if tuple(map(int, candidate['version'].removeprefix('v').split('-')[0].split('.'))) >= (0, 8, 0):
        sys.path.insert(0, str(pathlib.Path('scripts').resolve()))
        from app_assets import roster
        from release_facts import validate_public_admission
        rows = roster('apps.json')
        candidate['release_admission'] = validate_public_admission(rows.admission,
            candidate['version'].removeprefix('v'), rows, candidate['source'])
        candidate['app_roster_sha256'] = hashlib.sha256(pathlib.Path('apps.json').read_bytes()).hexdigest()
        document = json.loads(pathlib.Path('apps.json').read_text(encoding='utf-8'))
        proof, chain, context = received_windows_proofs(os.environ['RUNNER_TEMP'], source=candidate['source'],
            run_id=candidate['run_id'], attempt=int(os.environ['WINDOWS_ARTIFACT_ATTEMPT']),
            artifact={'id':int(os.environ['WINDOWS_ARTIFACT_ID']), 'name':os.environ['WINDOWS_ARTIFACT'],
                      'sha256':os.environ['WINDOWS_ARTIFACT_DIGEST'].removeprefix('sha256:')})
        import types
        relay_path = pathlib.Path('windows/windows_signing.py')
        relay = types.ModuleType('oa_candidate_signing'); relay.__file__ = str(relay_path.resolve())
        exec(compile(relay_path.read_bytes(), str(relay_path), 'exec'), relay.__dict__)
        policy_raw = pathlib.Path('windows/certum_simplysign.json').read_bytes()
        relay.verify_receipt(proof, json.loads(policy_raw), policy_sha256=hashlib.sha256(policy_raw).hexdigest())
        if (context.get('version') != candidate['version'].removeprefix('v') or context.get('source') != candidate['source']
                or context.get('run_id') != candidate['run_id'] or context.get('run_attempt') != int(os.environ['APP_PRODUCER_ATTEMPT'])):
            raise ValueError('Windows chain context differs from independent producer source/run')
        catalog_ids=set(context['expected_producers'])-{row['id'] for row in chain['apps']}
        admitted=relay.producer_hosts(chain, context['expected_producers'], source=candidate['source'],
                             run_id=candidate['run_id'], run_attempt=int(os.environ['APP_PRODUCER_ATTEMPT']),
                             delivery_root=pathlib.Path('dist').resolve(),
                             delivery_directories={app:pathlib.Path('dist').resolve() for app in catalog_ids})
        catalog={app:admitted[app] for app in catalog_ids}
        for app,delivery in catalog.items():
            rows=[row for row in apps if row.get('id')==app]
            if (len(rows)!=1 or any(rows[0].get(key)!=delivery['delivery'].get(key) for key in ('binary','source'))):
                raise ValueError('final catalog application differs from authenticated native delivery')
        candidate['windows_signing'] = proof
        candidate['installers'] = required_signed_installers(document,candidate['version'].removeprefix('v'),
            candidate['windows_signing'],validate_public_admission,candidate['source'],
            chain=chain,catalog=catalog)
    else:
        candidate['windows_signing'] = json.loads((pathlib.Path(os.environ['RUNNER_TEMP']) / 'windows-signatures.json').read_bytes())
    candidate['release_facts'] = producer_facts(candidate, pathlib.Path('verified-release'))
    notes = pathlib.Path('verified-release/NOTES.md')
    notes.write_text(fact_owner().render_notes(notes.read_text(encoding='utf-8'), candidate['release_facts']), encoding='utf-8')
    pathlib.Path('verified-release/candidate.json').write_text(json.dumps(candidate, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
