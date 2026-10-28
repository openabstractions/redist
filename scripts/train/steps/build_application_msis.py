import hashlib, json, os, pathlib, re, shutil, stat, subprocess, sys, tempfile
import importlib.util
import argparse
import base64
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from file_boundary import plain_path, extended_path, remove_tree


def release_completed_stage(parent,name):
    """Release the caller's two fixed disposable stages after their last reader."""
    if name not in ('backend-launch-build','app-control-stage'):
        raise ValueError('unselected completed stage')
    parent=pathlib.Path(parent)
    if not parent.is_absolute() or parent.resolve(strict=True)!=parent:
        raise ValueError('completed stage parent is not canonical')
    target=parent/name
    for path in (target,*target.parents):
        info=path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or path.is_junction()
                or getattr(info,'st_file_attributes',0)&stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError('completed stage is linked or foreign')
    before=target.stat()
    for directory,dirs,files in os.walk(extended_path(target),followlinks=False):
        for member in dirs+files:
            path=pathlib.Path(directory)/member;info=path.lstat()
            if (path.is_symlink() or path.is_junction() or getattr(info,'st_file_attributes',0)&stat.FILE_ATTRIBUTE_REPARSE_POINT
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                    or (stat.S_ISREG(info.st_mode) and info.st_nlink!=1)):
                raise ValueError('completed stage contains linked or foreign content')
    after=target.stat()
    if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):
        raise ValueError('completed stage identity changed')
    remove_tree(target)


def load_owner(path, name, *, source_bytes=None, admitted_boundary_pin=None):
    path=pathlib.Path(path)
    spec=importlib.util.spec_from_file_location(name,path)
    owner=importlib.util.module_from_spec(spec)
    if admitted_boundary_pin is not None:owner._admitted_boundary_pin=admitted_boundary_pin
    exec(compile(path.read_bytes() if source_bytes is None else source_bytes,str(path),'exec'),owner.__dict__)
    return owner


def installer_scope(version):
    sys.path.insert(0,str(pathlib.Path('scripts').resolve()))
    from release_facts import validate_public_admission
    document=json.loads(pathlib.Path('apps.json').read_bytes())
    capsule=validate_public_admission(document.get('release_admission'),version,document['apps'],require_delivery=False)
    return {row['id'] for row in capsule['outcomes']['adopters'] if row['target']=='windows-x64'}


def selected_sources(required, version, *, checkout=False, producer_source=None):
    helper=load_owner('scripts/app_producer_inputs.py','application_input_owner')
    pins,errors={},[]
    for app in sorted(required):
        try:
            selected=helper.installer_source_pins(app,'npm.tsv','pypi.tsv','app-sources.tsv','apps.json',version,
                                                producer_source=producer_source or os.environ['CANDIDATE_SHA'])
            for repo,commit in selected.items():
                if repo in pins and pins[repo]!=commit:
                    raise ValueError('conflicting selected source: '+repo)
                pins[repo]=commit
        except (OSError,ValueError,KeyError,TypeError) as error:
            errors.append(app+': '+str(error))
    if errors:
        raise ValueError('required installer source inputs: '+'; '.join(errors))
    if checkout:
        environment=load_owner('scripts/git_env.py','application_source_git_environment').source_git_environment()
        for repo,commit in pins.items():
            destination=pathlib.Path('sources')/repo.split('/',1)[1]
            if destination.exists():
                if destination.is_symlink() or destination.is_junction():raise ValueError('linked selected source checkout')
                command=['git','-C',str(destination)]
                head=subprocess.check_output([*command,'rev-parse','HEAD'],text=True,env=environment).strip()
                dirty=subprocess.check_output([*command,'status','--porcelain=v1','--untracked-files=all'],text=True,env=environment).strip()
                if head!=commit or dirty:raise ValueError('existing selected source checkout differs: '+repo)
            else:helper.checkout(repo,commit,'sources',env=environment)
    return helper,pins


def producer_owners(required,*,sources_root=pathlib.Path('sources'),shared_root=pathlib.Path('.')):
    """Load the same producers from caller-authenticated selected roots.

    The caller owns source/HEAD/tree/mode/import-closure authentication.
    Explicit roots are authoritative locations; missing files never fall back.
    """
    paths={'opencode':'abstractions/adopters/opencode/installer/build_installer.py',
           'lemonade':'abstractions/adopters/lemonade/build_native.py',
           'comfyui':'adopter-comfyui/.installer/build_installer.py'}
    owners,errors={},[]
    for app in sorted(required):
        try:
            owner=load_owner(pathlib.Path(sources_root)/paths[app],'selected_producer_'+app)
            if not callable(getattr(owner,'source_roles',None)):
                raise ValueError('selected producer lacks source role policy')
            if app=='opencode':
                owner.app_builder((pathlib.Path(shared_root)/'windows/apps/build_app.py').resolve())
            owners[app]=owner
        except (OSError,ValueError,KeyError,TypeError,ImportError,SyntaxError) as error:
            errors.append(app+': '+str(error))
    if errors:
        raise ValueError('required installer producer source closure: '+'; '.join(errors))
    return owners


def application_backend_inputs(required,version):
    if 'comfyui' not in required:raise ValueError('backend producer requires the accepted Comfy installer obligation')
    helper,_=selected_sources({'comfyui'},version,checkout=True)
    owner=producer_owners({'comfyui'})['comfyui']
    expected=(owner.native_input_pins()['backend'] if native_archive_selected(owner) else
              owner.custom_desktop_policy(require_admitted=False)['build_inputs'].get('backend'))
    if not isinstance(expected,dict) or set(expected)!={'sha256','bytes'}:
        raise ValueError('source-selected custom Desktop backend input is not admitted')
    inputs=pathlib.Path('app-build-inputs');inputs.mkdir(exist_ok=True)
    # The source recipe is not the full admitted file/wheel/tool descriptor.
    # Its fixed-role acquisition owner must stage these exact bytes first.
    closure_file(inputs,'backend-inputs.json',expected)
    shutil.copyfile(pathlib.Path(owner.__file__).parent/'desktop-host.json',inputs/'desktop-host.json')
    helper.preflight('comfyui',pathlib.Path('sources/abstractions'),inputs,1)
    package=load_owner('sources/abstractions/scripts/package_comfyui_app.py','application_backend_input_policy')
    if helper.selected_comfy_backend('sources',inputs,package)!=expected:
        raise ValueError('required custom Desktop cannot fall through to portable/CPU inputs')
    helper.comfy_archive_tool(inputs,package,acquire=True)


def native_archive_selected(owner):
    """Select the explicit source-owned route before acquiring tool roles."""
    source=getattr(owner,'__file__',None)
    if not isinstance(source,(str,os.PathLike)):raise ValueError('source-selected Comfy producer policy is unavailable')
    path=pathlib.Path(source).with_name('desktop-host.json')
    if path.is_symlink() or path.is_junction() or not path.is_file() or path.stat().st_size>4<<20:
        raise ValueError('Comfy application route requires ordinary source policy')
    value=json.loads(path.read_bytes())
    distribution=value.get('distribution')
    if distribution not in ('oa-custom-desktop','oa-comfyui-native'):
        raise ValueError('unknown source-selected Comfy application route')
    return distribution=='oa-comfyui-native'


def installer_chain_scope(required,owners):
    """Selected archive delivery is authenticated separately from Burn packages."""
    return set(required)-({'comfyui'} if 'comfyui' in owners and native_archive_selected(owners['comfyui']) else set())


def application_control_inputs(required,version):
    """Use the same backend Job's complete PBS and public SDK inputs once."""
    if 'comfyui' not in required:raise ValueError('native control needs selected Comfy delivery')
    owner=producer_owners({'comfyui'})['comfyui']
    if not native_archive_selected(owner):
        with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as stream:stream.write('selected=false\n')
        return
    selected=owner.native_input_pins()
    inputs=pathlib.Path('app-build-inputs');output=pathlib.Path('app-control-output')
    if output.exists():raise ValueError('native control artifact output must be fresh')
    descriptor=closure_file(inputs,'backend-inputs.json',selected['backend'])
    receipt=closure_file(inputs,'integration-producer.json')
    integration=json.loads(receipt.read_bytes())['integration']
    archive=closure_file(inputs,'integration.zip',integration)
    package=load_owner('sources/abstractions/scripts/package_comfyui_app.py','native_control_packager')
    with package.app_pair_receipt.checked_zip(archive,bounded_members=True) as content:
        manifest=json.loads(content.read('manifest.json'))
    repositories=[manifest['adopter_source'],manifest['packager_source'],*manifest['wheels']]
    sources={row['repository']:pathlib.Path('sources')/row['repository'].split('/',1)[1] for row in repositories}
    stage=pathlib.Path('app-control-stage')
    if stage.exists():raise ValueError('native control stage must be fresh')
    stage.mkdir();output.mkdir()
    control=stage/'oa-control'
    control_pin=package.build_native_control(descriptor,selected['backend']['sha256'],archive,
        integration['bytes'],integration['sha256'],control,candidate_source=os.environ['CANDIDATE_SHA'],
        run_id=int(os.environ['GITHUB_RUN_ID']),run_attempt=int(os.environ['WHEEL_ATTEMPT']),
        integration_options=dict(producer_receipt_path=receipt,
            wheel_receipt_path=closure_file(inputs,'wheels/wheel-inputs.json'),
            expected_redist_source_commit=os.environ['CANDIDATE_SHA'],
            expected_run_id=int(os.environ['GITHUB_RUN_ID']),expected_run_attempt=int(os.environ['WHEEL_ATTEMPT'])),
        adapter=pathlib.Path(owner.__file__).with_name('oa_native_host.py'),public_sources=sources)
    files,_,_,_=package._scan_tree(stage,'oa-control',package.MAX_RELEASE_ASSET_BYTES)
    target=output/'control.zip'
    with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED) as content:
        for name,path in files:package._write_zip_file(content,name,path)
    if target.stat().st_size>=package.MAX_RELEASE_ASSET_BYTES:raise ValueError('native control ZIP exceeds asset bound')
    shutil.copyfile(control/'manifest.json',output/'control-manifest.json')
    copied=closure_file(output,'control-manifest.json',control_pin)
    with package.app_pair_receipt.checked_zip(target,bounded_members=True,expanded_limit=package.MAX_RELEASE_ASSET_BYTES) as content:
        package.app_pair_receipt.native_control_members(content,control_pin,json.loads(copied.read_bytes()))
    result=dict(archive=pin(target),manifest=pin(copied))
    release_completed_stage(stage.resolve().parent,stage.name)
    with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as stream:stream.write('selected=true\n')
    return result


def receive_native_control(inputs,relay):
    """Receive the exact same-source backend Job's small standard API artifact."""
    attempt=int(os.environ['COMFY_CONTROL_ARTIFACT_ATTEMPT'])
    directory=inputs/'control-intake'
    intake=relay.consume_artifact(int(os.environ['COMFY_CONTROL_ARTIFACT_ID']),
        os.environ['COMFY_CONTROL_ARTIFACT_DIGEST'].removeprefix('sha256:'),'oa-control-comfyui-'+str(attempt),
        os.environ['CANDIDATE_SHA'],int(os.environ['GITHUB_RUN_ID']),attempt,directory)
    pins={row['name']:row for row in intake['files']}
    if len(pins)!=2 or set(pins)!={'control.zip','control-manifest.json'}:
        raise ValueError('native control artifact has unexpected members')
    archive=closure_file(directory,'control.zip',pins['control.zip'])
    metadata=closure_file(directory,'control-manifest.json',pins['control-manifest.json'])
    pair=load_owner('scripts/app_pair_receipt.py','native_control_receiving')
    if metadata.stat().st_size>pair.BACKEND_RUNTIME_MANIFEST_BYTES:
        raise ValueError('native control metadata exceeds runtime bound')
    expected=json.loads(metadata.read_bytes());measured={key:pins['control-manifest.json'][key] for key in ('bytes','sha256')}
    stage=inputs/'control-stage'
    if stage.exists():raise ValueError('native control receiving stage must be fresh')
    with pair.checked_zip(archive,bounded_members=True,expanded_limit=2<<30) as content:
        names=pair.native_control_members(content,measured,expected)
        if {entry.filename for entry in content.infolist() if not entry.is_dir()}!=names:
            raise ValueError('native control archive contains unowned members')
        stage.mkdir()
        for name in sorted(names):
            target=stage.joinpath(*name.split('/'));target.parent.mkdir(parents=True,exist_ok=True)
            with content.open(name) as source,target.open('xb') as destination:shutil.copyfileobj(source,destination,1<<20)
    shutil.copyfile(metadata,inputs/'control-manifest.json')
    closure_file(directory,'control.zip',pins['control.zip'])
    closure_file(directory,'control-manifest.json',pins['control-manifest.json'])
    closure_file(inputs,'control-manifest.json',pins['control-manifest.json'])
    return intake


def application_inputs(required, version):
    helper,pins=selected_sources(required,version,checkout=True)
    owners=producer_owners(required)
    # Source admission precedes artifact/tool acquisition. A custom Desktop
    # cannot fall through to the historical supplier-installer receiver.
    if 'comfyui' in owners:
        owner=owners['comfyui']
        if native_archive_selected(owner):
            owner.native_host_tool_inputs(pathlib.Path('app-build-inputs'),go_descriptor_pin=owner.native_input_pins()['go'])
        else:
            owner.custom_desktop_policy()
            owner.desktop_tool_inputs(pathlib.Path('app-build-inputs'))
    base=pathlib.Path('app-native');base.mkdir()
    inputs=base/'inputs'
    selected=base/'selected-sources.json';selected.write_text(json.dumps(pins,sort_keys=True)+'\n')
    tools={name:shutil.which(name) for name in ('git','node','npm','wix')}
    if not all(tools.values()) or sys.version_info[:2]!=(3,12):
        raise ValueError('installer inputs require selected Git/Node/npm/WiX and Python3.12')
    tools={name:str(pathlib.Path(path).resolve()) for name,path in tools.items()}
    if subprocess.check_output([tools['node'],'--version'],text=True).strip()!='v22.23.3':
        raise ValueError('installer Node version differs from source-selected22.23.3')
    relay=load_owner('windows/windows_signing.py','application_sdk_intake')
    sdk=base/'sdk';sdk.mkdir()
    received={}
    for kind,select in (('npm',helper.successful_addon_input),('pypi',helper.successful_wheel_input)):
        row=select(int(os.environ['GITHUB_RUN_ID']),os.environ['CANDIDATE_SHA'],descriptor=True)
        proof=relay.consume_artifact(row['artifact_id'],row['artifact_digest'].removeprefix('sha256:'),row['artifact'],
            os.environ['CANDIDATE_SHA'],int(os.environ['GITHUB_RUN_ID']),row['run_attempt'],sdk/kind)
        received[kind]={'selection':row,'intake':proof}
    canonical=relay.consume_artifact(int(os.environ['PE_ARTIFACT_ID']),os.environ['PE_ARTIFACT_DIGEST'].removeprefix('sha256:'),
        'windows-sdk-signed-'+os.environ['PE_ARTIFACT_ATTEMPT'],os.environ['CANDIDATE_SHA'],
        int(os.environ['GITHUB_RUN_ID']),int(os.environ['PE_ARTIFACT_ATTEMPT']),sdk/'canonical')
    received['canonical']=canonical
    subprocess.run([sys.executable,'windows/windows_signing.py','verify-language','--root',str(sdk),
        '--canonical',str(sdk/'canonical/native'),'--policy','windows/certum_simplysign.json',
        '--signtool',os.environ['SIGNTOOL']],check=True)
    if 'lemonade' in owners:
        native=owners['lemonade']
        cache=pathlib.Path('app-native-git-cache')
        environment=load_owner('scripts/git_env.py','application_cache_git_environment').clean_git_environment()
        for name,url,commit in native.local_source_inputs():
            helper.checkout('native/'+name,commit,cache,remote_url=url,env=environment)
        empty=pathlib.Path('app-native-empty-cache');empty.mkdir()
        wix=load_owner('windows/wix_packages.py','application_ui_input_policy')
        package=pathlib.Path('wix-packages')/wix.PACKAGES['WixToolset.UI.wixext']['file']
        command=[sys.executable,str(pathlib.Path(native.__file__).resolve()),'materialize','--pins',str(selected.resolve()),
            '--sources-root',str(pathlib.Path('sources').resolve()),'--git-cache-root',str(cache.resolve()),
            '--inputs-root',str(inputs.resolve()),'--npm-cache',str(empty.resolve()),
            '--wix-ui-package',str(package.resolve()),'--wix-ui-extension',os.environ['WIX_UI_EXT'],
            '--python',sys.executable,*[item for name,path in tools.items() for item in ('--'+name,path)]]
        subprocess.run(command,check=True)
        manifest=json.loads((pathlib.Path(native.__file__).parent/'native-inputs.json').read_bytes())
        helper.prime_native_npm_cache(inputs/'upstream/lemonade',manifest['web']['lock_file'],manifest['web']['sha256'],
            tools['npm'],inputs/'npm-cache',pathlib.Path('app-native-npm-acquisition'),inputs/'npm-acquisition.json')
    else:
        inputs.mkdir()
        selector=load_owner('sources/redist/sdk_smokes/prepare.py','application_host_tool_selection')
        selection=selector.msvc_toolchain()
        all_tools=dict(tools,python=sys.executable,cmake=str(selection['cmake']),msbuild=str(selection['msbuild']))
        (inputs/'selected-toolchain.json').write_text(json.dumps({
            'installation_path':str(selection['installation_path']),'installation_version':selection['installation_version'],
            'generator':selection['generator'],'tools':{name:dict(pin(pathlib.Path(value)),path=value) for name,value in all_tools.items()}},sort_keys=True)+'\n')
    if 'comfyui' in owners:
        native=native_archive_selected(owners['comfyui'])
        if native:
            owners['comfyui'].stage_native_host_tools(pathlib.Path('app-build-inputs'),inputs,
                go_descriptor_pin=owners['comfyui'].native_input_pins()['go'])
        else:owners['comfyui'].stage_desktop_tools(pathlib.Path('app-build-inputs'),inputs)
        shutil.copyfile(pathlib.Path(owners['comfyui'].__file__),inputs/'producer-comfyui.py')
        shutil.copyfile(pathlib.Path(owners['comfyui'].__file__).with_name('file_boundary.py'),inputs/'file_boundary.py')
        shutil.copyfile(closure_file(pathlib.Path('sources/abstractions'),'monitor/icon/panel.ico'),inputs/'oa-comfyui.ico')
        if not native:
            desktop_policy,_=owners['comfyui'].desktop_source_policy()
            environment=load_owner('scripts/git_env.py','application_desktop_git_environment').clean_git_environment()
            helper.checkout('Comfy-Org/desktop',desktop_policy['upstream']['commit'],inputs/'upstream',
                remote_url=desktop_policy['upstream']['repository']+'.git',env=environment)
    (inputs/'sdk-selection.json').write_text(json.dumps(received,sort_keys=True)+'\n')
    if 'opencode' in owners:
        opencode=owners['opencode']
        for role,name in (('desktop','opencode-desktop.exe'),('cli','opencode-cli.zip')):
            helper.github_asset_input('anomalyco/opencode',opencode.UPSTREAM[role]['asset'],opencode.UPSTREAM[role],inputs/name)
        lock=json.loads((pathlib.Path(opencode.__file__).parent/'package-lock.json').read_bytes())['packages']['node_modules/jsonc-parser']
        algorithm,encoded=lock['integrity'].split('-',1)
        if algorithm!='sha512':raise ValueError('selected parser lock lacks exact SHA512')
        helper.checked_download(lock['resolved'],inputs/'jsonc-parser.tgz',expected_sha512=base64.b64decode(encoded,validate=True).hex(),max_bytes=1<<20)
        bootstrap=inputs/'opencode-bootstrap';bootstrap.mkdir()
        for row in opencode.bootstrap_inputs():
            helper.checked_download(row['url'],bootstrap/row['file'],expected_sha512=row['sha512'],max_bytes=64<<20)
        helper.checked_download(opencode.RIPGREP['url'],inputs/'opencode-ripgrep.zip',expected_sha256=opencode.RIPGREP['sha256'],max_bytes=16<<20)
        shutil.copyfile(sdk/'npm'/('openabstractions-opencode-'+version+'.tgz'),inputs/'opencode-plugin.tgz')
    if 'comfyui' in owners:
        source=pathlib.Path(owners['comfyui'].__file__).parent/'desktop-host.json'
        shutil.copyfile(source,inputs/'desktop-host.json')
        native=native_archive_selected(owners['comfyui'])
        policy=(dict(build_inputs=owners['comfyui'].native_input_pins()) if native else owners['comfyui'].custom_desktop_policy())
        # The backend is an intermediate producer artifact, never a final app.
        attempt=int(os.environ['COMFY_BACKEND_ARTIFACT_ATTEMPT'])
        expected={'id':int(os.environ['COMFY_BACKEND_ARTIFACT_ID']),
            'name':'oa-backend-comfyui-'+str(attempt),
            'sha256':os.environ['COMFY_BACKEND_ARTIFACT_DIGEST'].removeprefix('sha256:')}
        backend=inputs/'backend'
        intake=relay.consume_artifact(expected['id'],expected['sha256'],expected['name'],
            os.environ['CANDIDATE_SHA'],int(os.environ['GITHUB_RUN_ID']),attempt,backend)
        assets=load_owner('scripts/app_assets.py','application_backend_receiving')
        archive_owner=load_owner('sources/abstractions/scripts/package_comfyui_app.py','application_backend_archive_owner')
        archive_tool=helper.comfy_archive_tool(pathlib.Path('app-build-inputs'),archive_owner)
        metadata={}
        received_backend,resource=assets.receive_backend_resources(backend,intake,expected_artifact=expected,
            expected_input=policy['build_inputs']['backend'],candidate_source=os.environ['CANDIDATE_SHA'],
            run_id=int(os.environ['GITHUB_RUN_ID']),run_attempt=attempt,
            archive_owner=archive_owner,archive_tool=archive_tool,metadata=metadata)
        descriptor=metadata['descriptor']
        if (len(descriptor)!=policy['build_inputs']['backend']['bytes'] or
                hashlib.sha256(descriptor).hexdigest()!=policy['build_inputs']['backend']['sha256']):
            raise ValueError('received backend descriptor changed')
        (inputs/'backend-inputs.json').write_bytes(descriptor)
        (inputs/'backend-manifest.json').write_bytes(metadata['manifest'])
        if resource is not None:
            # The immutable locator and raw provenance come from authenticated
            # intake and the selected source recipe, never inferred publication.
            for name,key in (('backend-inputs.json','descriptor'),('backend-manifest.json','manifest'),
                             ('backend-producer.json','producer_receipt'),('backend-amd-v1.json','backend_policy')):
                (backend/name).write_bytes(metadata[key])
            (backend/'desktop-backend.json').write_text(json.dumps(resource,sort_keys=True)+'\n',encoding='utf-8')
            staged_tool=inputs/'archive-tool';staged_tool.mkdir()
            for name,member in archive_owner._archive_tool_inputs(archive_tool).items():
                target=staged_tool/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(member,target)
            if not native:
                bridge=pathlib.Path(owners['comfyui'].__file__).parent.parent/'desktop_backend.cjs'
                closure_file(bridge.parent,bridge.name)
                shutil.copyfile(bridge,inputs/bridge.name)
        else:
            raise ValueError('legacy backend remains readable; current custom Desktop requires an admitted multipart resource')
        # Tool acquisition remains the admitted fixed-role materializer's job.
        # Validate the complete staged trees before invoking any supplier code.
        if native:
            receive_native_control(inputs,relay)
            owners['comfyui'].native_host_tool_inputs(inputs,go_descriptor_pin=policy['build_inputs']['go'])
            application=pathlib.Path(owners['comfyui'].__file__).parent/'backendlaunch/application-manifest.json'
            closure_file(application.parent,application.name,policy['build_inputs']['application_manifest'])
            shutil.copyfile(application,inputs/'application-manifest.json')
        else:owners['comfyui'].desktop_tool_inputs(inputs)
    selection=json.loads((inputs/'selected-toolchain.json').read_bytes())
    vcvars=pathlib.Path(selection['installation_path'])/'VC/Auxiliary/Build/vcvars64.bat'
    if not vcvars.is_file():raise ValueError('selected Visual Studio developer environment is unavailable')
    with open(os.environ['GITHUB_ENV'],'a',encoding='utf-8') as output:
        output.write('OA_APP_VCVARS='+str(vcvars.resolve())+'\n')


def application_native_prepare(required,version):
    helper,pins=selected_sources(required,version)
    owners=producer_owners(required)
    base=pathlib.Path('app-native');inputs=base/'inputs'
    roles=('cl.exe','rc.exe','cvtres.exe') if ('comfyui' in owners and native_archive_selected(owners['comfyui'])) else ('cl.exe','rc.exe')
    compiler={name:shutil.which(name) for name in roles}
    if not all(compiler.values()):raise ValueError('selected Visual Studio developer environment is required')
    (inputs/'app-native-tools.json').write_text(json.dumps({
        'tools':{name:dict(pin(pathlib.Path(path)),path=str(pathlib.Path(path).resolve())) for name,path in compiler.items()},
        'runner_image':{name:os.environ.get(name) for name in ('ImageOS','ImageVersion','RUNNER_ARCH')}},sort_keys=True)+'\n')
    received=helper.pinned_input_receipt(pins,'sources',inputs)
    (base/'producer-inputs.json').write_text(json.dumps(received,sort_keys=True)+'\n')
    selected=json.loads((inputs/'selected-toolchain.json').read_bytes())
    tool_args=[item for name,row in selected['tools'].items() for item in ('--'+name,row['path'])]
    common=['--input-receipt',str((base/'producer-inputs.json').resolve()),'--inputs-root',str(inputs.resolve()),
        '--sources-root',str(pathlib.Path('sources').resolve()),'--version',version,'--host-tools',str((inputs/'host-tools.json').resolve()),
        '--npm-cache',str((inputs/'npm-cache').resolve()),'--wix-ui-package',str((inputs/'wix-ui.nupkg').resolve()),
        '--wix-ui-extension',str((inputs/'WixToolset.UI.wixext.dll').resolve()),*tool_args]
    completed_native=[]
    for app,owner in owners.items():
        out=(base/'native'/app).resolve()
        if app=='lemonade':
            arguments=['prepare-native',*common,'--out',str(out),'--source-root',str((inputs/'upstream/lemonade').resolve()),
                '--deps-root',str((inputs/'upstream/deps').resolve()),'--toolchain',str((inputs/'toolchain.cmake').resolve()),'--generator',selected['generator']]
        elif app=='opencode':
            plugin=pin(inputs/'opencode-plugin.tgz')
            arguments=['--phase','prepare-native','--app-builder',str(pathlib.Path('windows/apps/build_app.py').resolve()),
                '--plugin',plugin['file'],'--plugin-sha256',plugin['sha256'],'--plugin-bytes',str(plugin['bytes']),
                '--cli',str((inputs/'opencode-cli.zip').resolve()),'--parser-tgz',str((inputs/'jsonc-parser.tgz').resolve()),
                '--bootstrap',str((inputs/'opencode-bootstrap').resolve()),'--ripgrep',str((inputs/'opencode-ripgrep.zip').resolve()),
                '--out',str(out),'--version',version,'--cl',compiler['cl.exe']]
        elif app=='comfyui' and native_archive_selected(owner):
            tools=owner.native_host_tool_inputs(inputs,go_descriptor_pin=owner.native_input_pins()['go'])
            out.mkdir(parents=True)
            built=owner.build_native_host(tools,pathlib.Path('windows/apps').resolve(),out,
                out,backend_manifest=closure_file(inputs,'backend-manifest.json'),
                control_manifest=closure_file(inputs,'control-manifest.json'),
                rc=pathlib.Path(compiler['rc.exe']).resolve(),cvtres=pathlib.Path(compiler['cvtres.exe']).resolve())
            # These are original measured unsigned outputs. The signer preserves
            # this record and supplies its own independent signed-byte proof.
            original=dict(
                schema=1,version=version,distribution='oa-comfyui-native',
                source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
                run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT']),
                input_receipt={key:pin(base/'producer-inputs.json')[key] for key in ('bytes','sha256')},build=built)
            (out/'native-host-receipt.json').write_text(json.dumps(original,sort_keys=True)+'\n',encoding='utf-8')
            completed_native.append((out,original))
            continue
        else:
            arguments=['--phase','desktop-prepare','--desktop-binding',str((inputs/'desktop-host.json').resolve()),
                '--input-root',str(inputs.resolve()),'--shared-app-builder',str(pathlib.Path('windows/apps').resolve()),
                '--input-receipt',str((base/'producer-inputs.json').resolve()),
                '--source-root',str((inputs/'upstream/desktop').resolve()),'--git',selected['tools']['git']['path'],
                '--out',str(out),'--version',version]
        subprocess.run([sys.executable,str(pathlib.Path(owner.__file__).resolve()),*arguments],check=True)
    if helper.pinned_input_receipt(pins,'sources',inputs)!=received:
        raise ValueError('application preparation changed selected inputs')
    for out,original in completed_native:
        if (json.loads(closure_file(out,'native-host-receipt.json').read_bytes())!=original or
                any(pin(closure_file(out,'launch-helper.exe'))[key]!=original['build']['native'][key] for key in ('bytes','sha256'))):
            raise ValueError('native preparation output changed before stage release')
        # The native producer owns its private temporary compiler stage.
        # Final output and selected-input receiving above remain mandatory.
    chain_required=installer_chain_scope(required,owners)
    prepare_bundle_actions(chain_required,base,compiler['cl.exe'])


def prepare_bundle_actions(required,base,compiler):
    """Compile the same source-owned role map before final package hashes exist."""
    owner=load_owner('windows/apps/build_bundle.py','application_bundle_actions')
    facts=owner.bundle_actions_inputs(sorted(required))
    out=base/'shared-bundle';out.mkdir()
    (out/'actions_map.h').write_text(facts['header'],encoding='utf-8',newline='\n')
    subprocess.run(owner.bundle_actions_compile(sorted(required),out.resolve(),compiler),check=True)
    native=pin(closure_file(out,facts['output']))
    native=dict(name=facts['output'],sha256=native['sha256'],bytes=native['bytes'])
    (out/'bundle-actions-receipt.json').write_text(json.dumps({
        'schema':1,'inputs':facts['inputs'],'native':native},sort_keys=True)+'\n')


def sign_bundle_actions(required,base,relay):
    """Admit unsigned source/map bytes before the existing native signer runs."""
    owner=load_owner('windows/apps/build_bundle.py','application_bundle_actions_signing')
    out=base/'shared-bundle';receipt=closure_file(out,'bundle-actions-receipt.json')
    digest=pin(receipt)['sha256'];chain={'apps':[{'id':app} for app in sorted(required)]}
    owner.check_bundle_actions(chain,closure_file(out,owner.ACTIONS_NAME),receipt,digest)
    subprocess.run([sys.executable,'windows/windows_signing.py','sign',
        '--policy','windows/certum_simplysign.json','--signtool',os.environ['SIGNTOOL'],
        '--root',str(out),'--receipt',str(out/'signatures.json'),'--file',owner.ACTIONS_NAME],check=True)
    policy_raw=pathlib.Path('windows/certum_simplysign.json').read_bytes()
    proof=relay.verify_receipt(json.loads(closure_file(out,'signatures.json').read_bytes()),
        json.loads(policy_raw),out,policy_sha256=hashlib.sha256(policy_raw).hexdigest())
    if len(proof['files'])!=1 or proof['files'][0]['name']!=owner.ACTIONS_NAME:
        raise ValueError('shared bundle signing proof is not the exact source-owned DLL')
    value=json.loads(receipt.read_bytes());signed=proof['files'][0]
    value['native']={key:signed[key] for key in ('name','sha256','bytes')}
    receipt.write_text(json.dumps(value,sort_keys=True)+'\n')
    owner.check_bundle_actions(chain,closure_file(out,owner.ACTIONS_NAME),receipt,pin(receipt)['sha256'])


def native_context(required,version,*,checkout):
    helper,pins=selected_sources(required,version,checkout=checkout)
    base=pathlib.Path('app-native');inputs=base/'inputs'
    received=json.loads((base/'producer-inputs.json').read_bytes())
    if helper.pinned_input_receipt(pins,'sources',inputs)!=received:
        raise ValueError('received app native inputs differ from selected source/SDK bytes')
    return helper,producer_owners(required),base,inputs


def source_roles(app,owner,out,inputs,payload=None):
    if app=='lemonade':
        return owner.source_roles(pathlib.Path('sources'),inputs/'wix-ui.nupkg',inputs/'WixToolset.UI.wixext.dll')
    if app=='comfyui':
        return owner.source_roles(pathlib.Path('windows/apps'))
    return owner.source_roles(out if payload is not None else None,
                              inputs/'opencode-cli.zip' if payload is not None else None,payload)


def application_native_sign(required,version):
    helper,owners,base,inputs=native_context(required,version,checkout=True)
    relay=load_owner('windows/windows_signing.py','application_native_signing')
    closed,errors={},[]
    for app,owner in owners.items():
        try:
            out=base/'native'/app;root=out/'build' if app=='lemonade' else out
            native=app=='comfyui' and native_archive_selected(owner)
            if native:
                receipt=json.loads(closure_file(out,'native-host-receipt.json').read_bytes())
                if (receipt.get('schema')!=1 or receipt.get('distribution')!='oa-comfyui-native' or
                    receipt.get('version')!=version or receipt.get('source')!=os.environ['CANDIDATE_SHA'] or
                    receipt.get('run_id')!=int(os.environ['GITHUB_RUN_ID']) or
                    receipt.get('input_receipt')!={key:pin(base/'producer-inputs.json')[key] for key in ('bytes','sha256')}):
                    raise ValueError('native host original source/input receipt differs')
                unsigned={'launch-helper.exe':receipt['build']['native']};names=list(unsigned)
                for key,name in (('backend','backend-manifest.json'),('control','control-manifest.json')):
                    actual=pin(closure_file(inputs,name));expected=receipt['build']['resources'][key]
                    if any(actual[field]!=expected[field] for field in ('bytes','sha256')):
                        raise ValueError('native host embedded manifest differs: '+key)
            elif app=='comfyui':
                receipt=json.loads(closure_file(out,'desktop-native-receipt.json').read_bytes())
                unsigned=owner.desktop_signing_members(receipt)
                names=list(unsigned)
            else:
                roles,_,external=source_roles(app,owner,out,inputs)
                names=[native for _,_,native in roles]+list(external)
            if len(names)!=len(set(names)) or not names:raise ValueError('source native signing list is empty or duplicate')
            if app!='comfyui':
                receipt=json.loads((out/('native-receipt.json' if app=='lemonade' else 'payload-receipt.json')).read_bytes())
            if app=='opencode':
                if receipt['prepared_native']['version']!=version:raise ValueError('prepared native version differs')
                unsigned={pathlib.Path(row['path']).name:row for key,row in receipt['prepared_native'].items() if key in ('host','preflight')}
            elif app=='lemonade':
                if receipt['version']!=version:raise ValueError('prepared native version differs')
                unsigned=receipt['payload']
            elif not native:
                if receipt['version']!=version:raise ValueError('prepared native version differs')
                if set(receipt['native_files'])!={'desktop/'+row['name'] for row in owner.desktop_native_inventory(out/'desktop')}:
                    raise ValueError('Desktop native signing roster differs from actual closed Desktop tree')
                actual={'desktop/'+row['name']:{key:row[key] for key in ('sha256','bytes')}
                        for row in owner.desktop_native_inventory(out/'desktop',all_files=True)}
                if actual!=receipt['desktop_files']:
                    raise ValueError('Desktop complete unsigned payload differs from original build')
            for name in names:
                actual=pin(relay.member(root,name));expected=unsigned[name if app=='comfyui' else pathlib.Path(name).name]
                if any(actual[key]!=expected[key] for key in ('sha256','bytes')):
                    raise ValueError('unsigned native member differs from actual producer receipt: '+name)
            closed[app]=(root,names)
        except (OSError,ValueError,KeyError,TypeError) as error:
            errors.append(app+': '+str(error))
    if errors:raise ValueError('required native signing intake: '+'; '.join(errors))
    for app,(root,names) in closed.items():
        native=app=='comfyui' and native_archive_selected(owners[app])
        receipt_name='desktop-signatures.json' if app=='comfyui' and not native else 'signatures.json'
        subprocess.run([sys.executable,'windows/windows_signing.py','sign','--policy','windows/certum_simplysign.json',
            '--signtool',os.environ['SIGNTOOL'],'--root',str(root),'--receipt',str(root/receipt_name),
            *[item for name in names for item in ('--file',name)]],check=True)
        if native:
            policy_raw=pathlib.Path('windows/certum_simplysign.json').read_bytes()
            proof=relay.verify_receipt(json.loads(closure_file(root,receipt_name).read_bytes()),
                json.loads(policy_raw),root,policy_sha256=hashlib.sha256(policy_raw).hexdigest())
            files={row['name']:{key:row[key] for key in ('bytes','sha256')} for row in proof['files']}
            if set(files)!={'launch-helper.exe'}:raise ValueError('native application signer roster differs')
            for key in ('bytes','sha256'):
                if pin(closure_file(root,'launch-helper.exe'))[key]!=files['launch-helper.exe'][key]:
                    raise ValueError('native signed image changed')
            (root/'native-host-signed.json').write_text(json.dumps(dict(
                schema=1,distribution='oa-comfyui-native',version=version,
                source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
                run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT']),
                original=pin(closure_file(root,'native-host-receipt.json')),
                signatures=pin(closure_file(root,receipt_name)),native=files['launch-helper.exe']),sort_keys=True)+'\n',encoding='utf-8')
        elif app=='comfyui':seal_signed_desktop(root,version,relay,owners[app])
    chain_required=installer_chain_scope(required,owners)
    sign_bundle_actions(chain_required,base,relay)


def seal_signed_desktop(out,version,relay,desktop):
    original=json.loads(closure_file(out,'desktop-native-receipt.json').read_bytes())
    policy_raw=pathlib.Path('windows/certum_simplysign.json').read_bytes()
    signatures=closure_file(out,'desktop-signatures.json')
    proof=relay.verify_receipt(json.loads(signatures.read_bytes()),json.loads(policy_raw),out,
        policy_sha256=hashlib.sha256(policy_raw).hexdigest())
    files={row['name']:{key:row[key] for key in ('sha256','bytes')} for row in proof['files']}
    owned=desktop.desktop_signing_members(original)
    if set(files)!=set(owned):raise ValueError('signed Desktop native closure differs')
    supplier=original.get('supplier_preserved',{})
    actual={'desktop/'+row['name']:{key:row[key] for key in ('sha256','bytes')}
            for row in desktop.desktop_native_inventory(out/'desktop',all_files=True)}
    if actual!={**original['desktop_files'],**files}:
        raise ValueError('signed Desktop complete payload differs from original build')
    carrier=None
    if desktop.BACKEND_HELPER in files:
        target=closure_file(out,desktop.BACKEND_HELPER_CARRIER)
        if target.read_bytes()!=desktop.desktop_helper_carrier(original['native_files'][desktop.BACKEND_HELPER]):
            raise ValueError('source-built Desktop helper carrier differs before signing bind')
        before={key:pin(target)[key] for key in ('sha256','bytes')}
        target.write_bytes(desktop.desktop_helper_carrier(files[desktop.BACKEND_HELPER]))
        carrier=dict(helper_unsigned=original['native_files'][desktop.BACKEND_HELPER],helper_signed=files[desktop.BACKEND_HELPER],
            carrier_unsigned=before,carrier_signed={key:pin(target)[key] for key in ('sha256','bytes')})
    host=dict(original['host']);host['exe']=dict(host['exe'],**files[host['exe']['name']])
    value={key:original[key] for key in ('version','source_policy','build_inputs','identity','input_receipt','source_preparation','desktop_files')}
    value.update(schema=original['schema'],stage='desktop-inner-signed',source=os.environ['CANDIDATE_SHA'],
        run_id=int(os.environ['GITHUB_RUN_ID']),run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT']),
        host=host,native_files={**supplier,**files},signatures=dict(name=signatures.name,**{key:pin(signatures)[key] for key in ('sha256','bytes')}))
    if original['schema']==3:value['supplier_preserved']=supplier
    if carrier is not None:value['helper_carrier']=carrier
    current={'desktop/'+row['name']:{key:row[key] for key in ('sha256','bytes')}
        for row in desktop.desktop_native_inventory(out/'desktop',all_files=True)}
    if current!=desktop.desktop_payload_files(value):raise ValueError('signed Desktop derived carrier closure differs')
    receipt=out/'desktop-signed-receipt.json'
    receipt.write_text(json.dumps(value,sort_keys=True)+'\n')
    with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as stream:
        measured=pin(receipt)
        stream.write('desktop-receipt-sha256='+measured['sha256']+'\n')
        stream.write('desktop-receipt-bytes='+str(measured['bytes'])+'\n')


def signed_desktop_arguments(out,base,relay,expected_sources):
    """Bind the consumed descriptor to immutable signed-native artifact intake."""
    intake=json.loads(closure_file(base,relay.INTAKE_RECEIPT).read_bytes())
    artifact_attempt=int(os.environ['ARTIFACT_ATTEMPT'])
    expected={'id':int(os.environ['ARTIFACT_ID']),'name':os.environ['ARTIFACT_NAME'],
              'sha256':os.environ['ARTIFACT_DIGEST'].removeprefix('sha256:')}
    if (expected['name'] not in {prefix+'-'+str(artifact_attempt) for prefix in (
            'windows-app-native-signed','windows-app-helpers-raw','windows-app-helpers-signed')} or
            any(type(intake.get(key)) is not int for key in ('run_id','run_attempt')) or
            intake['source']!=os.environ['CANDIDATE_SHA'] or intake['run_id']!=int(os.environ['GITHUB_RUN_ID'])
            or intake['run_attempt']!=artifact_attempt or intake['artifact']!=expected):
        raise ValueError('signed Desktop enclosing artifact differs from independent producer outputs')
    receipt=closure_file(out,'desktop-signed-receipt.json');measured=pin(receipt)
    if (measured['sha256']!=os.environ['DESKTOP_SIGNED_RECEIPT_SHA256'] or
            measured['bytes']!=int(os.environ['DESKTOP_SIGNED_RECEIPT_BYTES'])):
        raise ValueError('signed Desktop descriptor differs from original signer output')
    relative=receipt.relative_to(base).as_posix()
    rows=[row for row in intake['files'] if row['name']==relative]
    if len(rows)!=1 or any(rows[0][key]!=measured[key] for key in ('sha256','bytes')):
        raise ValueError('signed Desktop descriptor differs from authenticated intake')
    value=json.loads(bound_bytes(base,relative,measured));original=json.loads(closure_file(out,'desktop-native-receipt.json').read_bytes())
    if (type(value.get('schema')) is not int or value['schema'] not in (2,3) or value['schema']!=original.get('schema') or value.get('stage')!='desktop-inner-signed' or
            any(type(value.get(key)) is not int for key in ('run_id','run_attempt')) or
            value.get('source')!=intake['source'] or value.get('run_id')!=intake['run_id']):
        raise ValueError('signed Desktop descriptor source/stage differs')
    # The original signer attempt survives helper-signed archive forwarding.
    if value.get('run_attempt')!=int(os.environ['DESKTOP_SIGNER_ATTEMPT']):
        raise ValueError('signed Desktop descriptor attempt differs from original signer')
    if any(value.get(key)!=original[key] for key in ('version','source_policy','build_inputs','identity','input_receipt','source_preparation','desktop_files')):
        raise ValueError('signed Desktop source closure differs from original owner output')
    policy_raw=pathlib.Path('windows/certum_simplysign.json').read_bytes()
    signatures=closure_file(out,value['signatures']['name'],value['signatures'])
    proof=relay.verify_receipt(json.loads(signatures.read_bytes()),json.loads(policy_raw),out,
        policy_sha256=hashlib.sha256(policy_raw).hexdigest())
    files={row['name']:{key:row[key] for key in ('sha256','bytes')} for row in proof['files']}
    desktop=received_desktop_owner(base/'inputs',base/'producer-inputs.json',value,expected_sources)
    policy_path=base/'inputs/backend/backend-amd-v1.json'
    original_owned=desktop.desktop_signing_members(original,policy_path=policy_path)
    current_owned=desktop.desktop_signing_members(value,policy_path=policy_path)
    if (files!=current_owned or set(files)!=set(original_owned)
            or value.get('supplier_preserved')!=original.get('supplier_preserved')):
        raise ValueError('signed Desktop actual native closure differs')
    actual={'desktop/'+row['name']:{key:row[key] for key in ('sha256','bytes')}
            for row in desktop.desktop_native_inventory(out/'desktop',all_files=True)}
    if actual!=desktop.desktop_payload_files(value):
        raise ValueError('signed Desktop complete payload differs from original build')
    for name,expected_pin in files.items():
        fresh=relay.verify(relay.member(out,name),json.loads(policy_raw),os.environ['SIGNTOOL'])
        if any(fresh[key]!=expected_pin[key] for key in ('sha256','bytes')):
            raise ValueError('signed Desktop native member changed during verification')
    return ['--signed-desktop-receipt',str(plain_path(receipt.resolve())),'--signed-desktop-sha256',measured['sha256'],
        '--signed-desktop-bytes',str(measured['bytes']),'--producer-source',value['source'],
        '--producer-run',str(value['run_id']),'--producer-attempt',str(value['run_attempt'])]


def application_helpers_prepare(required,version):
    if 'comfyui' not in required:return
    helper,owners,base,inputs=native_context(required,version,checkout=True)
    relay=load_owner('windows/windows_signing.py','application_helper_intake')
    out=base/'native/comfyui';owner=owners['comfyui']
    if native_archive_selected(owner):return
    admitted=signed_desktop_arguments(out,base,relay,json.loads((base/'producer-inputs.json').read_bytes())['sources'])
    compiler={name:shutil.which(name) for name in ('cl.exe','rc.exe')}
    if not all(compiler.values()):raise ValueError('selected compiler environment is required for helpers')
    recorded=json.loads(closure_file(inputs,'app-native-tools.json').read_bytes())['tools']
    if any(any(pin(pathlib.Path(path))[key]!=recorded[name][key] for key in ('sha256','bytes'))
           for name,path in compiler.items()):raise ValueError('helper compiler differs from the admitted native toolchain')
    subprocess.run([sys.executable,str(pathlib.Path(owner.__file__).resolve()),'--phase','prepare',
        '--desktop-binding',str((inputs/'desktop-host.json').resolve()),'--input-root',str(inputs.resolve()),
        '--input-receipt',str((base/'producer-inputs.json').resolve()),
        '--shared-app-builder',str(pathlib.Path('windows/apps').resolve()),'--out',str(out.resolve()),
        '--version',version,'--cl',compiler['cl.exe'],'--rc',compiler['rc.exe'],*admitted],check=True)


def application_helpers_sign(required,version):
    """Sign the fixed helper outputs using authenticated prior source observation."""
    if 'comfyui' not in required:return
    if native_archive_selected(producer_owners({'comfyui'})['comfyui']):return
    base=pathlib.Path('app-native');out=base/'native/comfyui'
    selected=selected_sources(required,version)[1]
    original=json.loads(closure_file(base,'producer-inputs.json').read_bytes())
    if original['sources']!=selected:raise ValueError('helper source observation differs from current selected source')
    if os.environ['ARTIFACT_NAME']!='windows-app-helpers-raw-'+os.environ['ARTIFACT_ATTEMPT']:
        raise ValueError('helper signer requires the actual uncredentialed helper-build artifact')
    relay=load_owner('windows/windows_signing.py','application_helper_signing')
    signed_desktop_arguments(out,base,relay,selected)
    policy=json.loads(closure_file(pathlib.Path('.'),'windows/apps/comfyui/desktop-host.json').read_bytes())
    observed=json.loads(closure_file(out,'desktop-signed-receipt.json').read_bytes())
    if policy.get('schema')!=2 or any(observed.get(key)!=policy[key] for key in ('source_policy','build_inputs','identity')):
        raise ValueError('helper signer observation differs from current source-owned Desktop policy')
    intake=json.loads(closure_file(base,relay.INTAKE_RECEIPT).read_bytes())
    receipt_path=closure_file(out,'preparation-native-receipt.json')
    receipt=json.loads(receipt_path.read_bytes())
    names={'comfyui-prepare-instance.exe','comfyui-hostfolder.dll','desktop-uninstaller.exe'}
    if receipt.get('schema')!=1 or receipt.get('version')!=version or set(receipt.get('outputs',{}))!=names:
        raise ValueError('helper signer requires the closed actual prepared output roster')
    for name in ('preparation-native-receipt.json',*sorted(names)):
        path=closure_file(out,name);measured=pin(path)
        listed=[row for row in intake['files'] if row['name']=='native/comfyui/'+name]
        if len(listed)!=1 or any(listed[0][key]!=measured[key] for key in ('sha256','bytes')):
            raise ValueError('helper signer input changed after immutable API intake')
        if name in names and any(measured[key]!=receipt['outputs'][name][key] for key in ('sha256','bytes')):
            raise ValueError('helper signer output differs from actual prepared receipt')
    subprocess.run([sys.executable,'windows/windows_signing.py','sign','--policy','windows/certum_simplysign.json',
        '--signtool',os.environ['SIGNTOOL'],'--root',str(out),'--receipt',str(out/'signatures.json'),
        *[item for name in sorted(names) for item in ('--file',name)]],check=True)


def closure_file(root,name,expected=None):
    root=pathlib.Path(root).absolute()
    parts=pathlib.PurePosixPath(name)
    if parts.is_absolute() or not parts.parts or any(p in ('.','..') or '\\' in p or ':' in p for p in parts.parts):
        raise ValueError('unsafe producer receipt path')
    path=root
    if any(parent.is_symlink() or parent.is_junction() for parent in root.parents):
        raise ValueError('linked producer receipt ancestor')
    for part in ('',*parts.parts):
        if part:path=path/part
        if path.is_symlink() or path.is_junction():raise ValueError('linked producer receipt path')
    if not path.is_file():raise ValueError('missing producer receipt: '+name)
    if path.stat().st_nlink!=1:raise ValueError('aliased producer receipt path')
    actual=pin(path)
    if expected is not None and any(actual[k]!=expected[k] for k in ('sha256','bytes')):
        raise ValueError('producer receipt bytes differ: '+name)
    return path


def bound_bytes(root,name,expected):
    """Read the exact admitted small descriptor/code bytes before consuming them."""
    if type(expected.get('bytes')) is not int or not 0 < expected['bytes'] <= 16<<20:
        raise ValueError('unsupported producer descriptor size')
    path=closure_file(root,name,expected)
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno())
        data=stream.read(expected['bytes']+1)
        after=os.fstat(stream.fileno())
    identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_nlink)
    if (identity(before)!=identity(after) or identity(after)!=identity(path.stat()) or before.st_nlink!=1 or
            len(data)!=expected['bytes'] or hashlib.sha256(data).hexdigest()!=expected['sha256']):
        raise ValueError('consumed producer descriptor bytes differ')
    closure_file(root,name,expected)
    return data


def received_desktop_owner(inputs,receipt,original,expected_sources):
    receipt=pathlib.Path(receipt)
    producer=json.loads(bound_bytes(receipt.parent,receipt.name,original['input_receipt']))
    if producer['sources']!=expected_sources or not expected_sources.get('openabstractions/adopter-comfyui'):
        raise ValueError('copied Desktop producer selected source differs')
    expected=producer['build_inputs']['producer-comfyui.py']
    code=bound_bytes(inputs,'producer-comfyui.py',expected)
    bound_bytes(inputs,'file_boundary.py',producer['build_inputs']['file_boundary.py'])
    return load_owner(pathlib.Path(inputs)/'producer-comfyui.py','received_desktop_inventory_owner',source_bytes=code,
        admitted_boundary_pin={key:producer['build_inputs']['file_boundary.py'][key] for key in ('bytes','sha256')})


def inherited_desktop_package(native,inputs,expected_sources):
    expected={'sha256':os.environ['DESKTOP_SIGNED_RECEIPT_SHA256'],
              'bytes':int(os.environ['DESKTOP_SIGNED_RECEIPT_BYTES'])}
    original=json.loads(bound_bytes(native,'desktop-signed-receipt.json',expected))
    if (type(original.get('schema')) is not int or original['schema'] not in (2,3) or original.get('stage')!='desktop-inner-signed' or
            original.get('source')!=os.environ['CANDIDATE_SHA'] or
            original.get('run_id')!=int(os.environ['GITHUB_RUN_ID']) or
            original.get('run_attempt')!=int(os.environ['DESKTOP_SIGNER_ATTEMPT'])):
        raise ValueError('original Desktop signer context differs')
    owner=received_desktop_owner(inputs,pathlib.Path(inputs)/'producer-inputs.json',original,expected_sources)
    package=json.loads(closure_file(native,'package/desktop-package-receipt.json').read_bytes())
    if any(package.get(key)!=original[key] for key in
           ('version','source_policy','build_inputs','identity','host','native_files','desktop_files','signatures')):
        raise ValueError('Desktop package replaced original signed payload closure')
    if (package.get('schema')!=original['schema'] or package.get('supplier_preserved')!=original.get('supplier_preserved')
            or package.get('helper_carrier')!=original.get('helper_carrier')):
        raise ValueError('Desktop package replaced source-owned native partition')
    owner.desktop_signing_members(original,policy_path=pathlib.Path(inputs)/'backend/backend-amd-v1.json')
    actual={'desktop/'+row['name']:{key:row[key] for key in ('sha256','bytes')}
            for row in owner.desktop_native_inventory(pathlib.Path(native)/'desktop',all_files=True)}
    if actual!=owner.desktop_payload_files(original):
        raise ValueError('Desktop payload differs from original signer descriptor')
    return package


def native_closure_files(app,out,producer,version,*,inputs,producer_receipt,desktop_signed_pin=None):
    """Original measured files, using the existing producer's fixed layout."""
    name={'lemonade':'native-receipt.json','comfyui':'preparation-native-receipt.json','opencode':'payload-receipt.json'}[app]
    receipt_path=closure_file(out,name);receipt=json.loads(receipt_path.read_bytes())
    if app!='opencode' and receipt.get('schema')!=1:raise ValueError('unsupported native receipt schema')
    if (receipt.get('plugin',{}).get('version') if app=='opencode' else receipt.get('version'))!=version:
        raise ValueError('producer receipt version differs: '+app)
    files={name:receipt_path}
    if app=='lemonade':
        if receipt['selected_inputs']!=producer:raise ValueError('native selected inputs contradict original producer inputs')
        for name,key in (('build/CMakeCache.txt','cmake_cache'),('build/wix_installer_minimal.vcxproj','package_project'),('build/installer/Product.wxs','product_source')):
            files[name]=closure_file(out,name,receipt[key])
    elif app=='comfyui':
        for name in ('desktop_inputs.h','native_version.h'):
            files[name]=closure_file(out,name,receipt['inputs']['generated:'+name])
        for name in ('desktop-native-receipt.json','desktop-signed-receipt.json','desktop-signatures.json'):
            files[name]=closure_file(out,name)
        files['source-preparation/desktop-source-receipt.json']=closure_file(out,
            'source-preparation/desktop-source-receipt.json',json.loads(files['desktop-native-receipt.json'].read_bytes())['source_preparation'])
        for name in ('nsis-recipe.json','nsis-emit-a/desktop-uninstaller-unsigned.exe',
                     'nsis-emit-b/desktop-uninstaller-unsigned.exe'):
            files[name]=closure_file(out,name)
        desktop=json.loads(bound_bytes(out,'desktop-signed-receipt.json',desktop_signed_pin)
            if desktop_signed_pin is not None else files['desktop-signed-receipt.json'].read_bytes())
        inventory=received_desktop_owner(inputs,producer_receipt,desktop,producer['sources'])
        for name,expected in inventory.desktop_payload_files(desktop).items():
            files[name]=closure_file(out,name,expected)
    else:
        files['host_inputs.h']=closure_file(out,'host_inputs.h')
        if pin(files['host_inputs.h'])['sha256']!=receipt['host_inputs_sha256']:
            raise ValueError('prepared host configuration differs')
        files['integration-payload.zip']=closure_file(out,'integration-payload.zip')
        if pin(files['integration-payload.zip'])['sha256']!=receipt['zip_sha256']:
            raise ValueError('prepared integration payload differs')
    return files


def shared_closure_files(inputs,producer):
    names=['sdk-selection.json','selected-toolchain.json','app-native-tools.json']
    names += [name for name in ('host-tools.json','toolchain.cmake','opencode-plugin.tgz','desktop-host.json',
                              'backend-inputs.json','backend-manifest.json','producer-comfyui.py','file_boundary.py',
                              'control-manifest.json','application-manifest.json') if name in producer['build_inputs']]
    names += [name for name in producer['build_inputs'] if name.startswith(('backend/','archive-tool/','desktop-inputs/','control-stage/','control-intake/')) or name=='desktop_backend.cjs']
    return {name:closure_file(inputs,name,producer['build_inputs'][name]) for name in names}


def lemonade_package_files(native, receipt):
    inputs = receipt.get('package_inputs')
    required = {'build/installer/' + name for name in
                ('Product.wxs','WebAppFragment.minimal.wxs','DocsFragment.minimal.wxs','OALicenses.wxs')}
    if not isinstance(inputs, dict) or not required <= set(inputs):
        raise ValueError('Lemonade package lacks its measured generated source closure')
    return {name:closure_file(native,name,pin) for name,pin in inputs.items()}


def local_package_only(app, owner, raw, binding, closure, destination, wix, version, run, *, sources_root):
    """Repack authenticated signed inner bytes into a fresh unsigned diagnostic MSI.

    The caller supplies the already joined API/source/SDK closure and the same
    selected producer. This function has no acquisition or signing route.
    """
    raw=pathlib.Path(raw);destination=pathlib.Path(destination)
    if destination.exists():raise ValueError('local package destination must be fresh')
    original={name:closure_file(raw,name,row) for name,row in closure.items()}
    selected=json.loads(closure_file(raw,'provenance/inputs/selected-toolchain.json',
        closure['provenance/inputs/selected-toolchain.json']).read_bytes())
    closure_file(pathlib.Path(wix).parent,pathlib.Path(wix).name,selected['tools']['wix'])
    destination.mkdir(parents=True)
    native=destination/'native';native.mkdir()
    final=json.loads(closure_file(raw,'apps/'+app+'/installer-receipt.json',
        closure['apps/'+app+'/installer-receipt.json']).read_bytes())
    def copy(name,target,expected=None):
        source=closure_file(raw,name,expected)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
        closure_file(target.parent,target.name,pin(source))
        return target
    prefix='provenance/'+app+'/'
    if app=='lemonade':
        for name,row in final['package_inputs'].items():copy(prefix+name,native/name,row)
        record=json.loads(original[prefix+'native-receipt.json'].read_bytes())
        build=native/owner.relative(record['build']);source=native/owner.relative(record['source'])
        source.mkdir(parents=True,exist_ok=True)
        ui=copy('provenance/inputs/WixToolset.UI.wixext.dll',destination/'ui.dll',record['wix_ui_extension'])
        package=copy('provenance/inputs/wix-ui.nupkg',destination/'ui.nupkg',record['wix_ui_package'])
        supplier=owner.ui_rows(pathlib.Path(sources_root),package,ui)
        payload=owner.source_payload(build/'installer/Product.wxs',owner.package_fragments(build),
            owner.package_variables(build,source),[source,build],supplier)
        if any(payload[key]!=final['expected_payload'][key] for key in ('files','binaries','icons')):
            raise ValueError('relocated local package sources differ from authenticated signed payload')
        output=destination/pathlib.PurePosixPath(final['expected_payload']['msi']['name']).name
        owner.check_package_inputs(native,final['package_inputs'])
        owner.package_wix(wix,build,source,ui,output,{},runner=lambda argv,**kw:run(argv))
        owner.check_package_inputs(native,final['package_inputs'])
    elif app=='opencode':
        for name in ('payload-receipt.json','host_inputs.h','integration-payload.zip'):
            copy(prefix+name,native/name,closure[prefix+name])
        intake={row['name']:row for row in binding['intake']['files']}
        arguments=[]
        for option,name in (('installer-host','installer_host.dll'),('preflight','desktop_preflight.exe')):
            relative=prefix+name
            path=copy(relative,native/name,intake[relative])
            arguments += ['--'+option,path,'--'+option+'-sha256',intake[relative]['sha256'],
                          '--'+option+'-bytes',str(intake[relative]['bytes'])]
        # The actual producer already retains the independently selected
        # supplier host as a chain role; it is not an extra build-input file.
        host_name='apps/opencode/'+owner.source_owned_host_policy()['name']
        desktop=copy(host_name,destination/'desktop.exe',intake[host_name])
        closure_file(desktop.parent,desktop.name,owner.UPSTREAM['desktop'])
        run([sys.executable,'-B',owner.__file__,'--phase','package','--app-builder',owner.build_app.__file__,
             '--out',native,'--version',version,'--wix',wix,'--desktop',desktop,*arguments])
        output=native/('opencode-'+version+'.msi')
    else:
        raise ValueError('selected app has no MSI package role')
    for name,path in original.items():closure_file(raw,name,closure[name])
    closure_file(output.parent,output.name)
    return output


def prepare_comfy_source_pair(owner,inputs,producer,destination):
    """Reuse the source archive owner while still in the uncredentialed job."""
    package=load_owner('scripts/package_comfyui_app.py','application_corresponding_source_owner')
    pair=load_owner('scripts/app_pair_receipt.py','application_corresponding_source_receiver')
    native=native_archive_selected(owner)
    desktop=None if native else owner.desktop_source_policy()[0]
    destination.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(destination,'x',zipfile.ZIP_DEFLATED) as combined:
        import contextlib
        with contextlib.ExitStack() as stack:
            resource_path=pathlib.Path(inputs)/'backend/desktop-backend.json'
            if resource_path.exists():
                resource=pair.validate_backend_resource(json.loads(closure_file(inputs,'backend/desktop-backend.json',producer['build_inputs']['backend/desktop-backend.json']).read_bytes()))
                for part in resource['corresponding_source']['parts']:
                    closure_file(inputs,'backend/'+part['name'],producer['build_inputs']['backend/'+part['name']])
                stream=stack.enter_context(pair.ArchiveSetReader(pathlib.Path(inputs)/'backend',resource['corresponding_source'],format='zip'))
                source=stack.enter_context(pair.checked_zip(stream,bounded_members=True,expanded_limit=package.backend_limits()['expanded_bytes']))
            else:
                backend=closure_file(inputs,'backend/backend-source.zip',producer['build_inputs']['backend/backend-source.zip'])
                source=stack.enter_context(pair.checked_zip(backend,bounded_members=True))
            for entry in source.infolist():
                if entry.is_dir():continue
                with source.open(entry) as reader,combined.open(entry,'w',force_zip64=True) as writer:
                    shutil.copyfileobj(reader,writer,1<<20)
        resource_path=pathlib.Path(inputs)/'backend/desktop-backend.json'
        if resource_path.exists():
            resource=pair.validate_backend_resource(json.loads(closure_file(inputs,'backend/desktop-backend.json',producer['build_inputs']['backend/desktop-backend.json']).read_bytes()))
            for row in resource['provenance'].values():
                member=closure_file(inputs,'backend/'+row['name'],producer['build_inputs']['backend/'+row['name']])
                if any(pin(member)[key]!=row[key] for key in ('bytes','sha256')):
                    raise ValueError('full corresponding source backend admission changed')
                combined.write(member,'OA-Desktop-Backend-Admission/'+row['name'])
        with tempfile.TemporaryDirectory(prefix='corresponding-source-',dir=destination.parent) as temporary:
            work=pathlib.Path(temporary)
            for repository,commit in sorted(producer['sources'].items()):
                package._append_git_source(combined,pathlib.Path('sources')/repository.split('/',1)[1],
                    ('Native-Producer-' if native else 'Desktop-Producer-')+repository.split('/',1)[1],commit,work)
            if native:
                role=owner.native_host_tool_inputs(inputs,go_descriptor_pin=owner.native_input_pins()['go'])['go']
                # The admitted Go SDK archive retains its complete source tree;
                # proxy module ZIPs retain the exact compiler dependency source.
                names=[name for name in role['files'] if name.endswith('.zip') or
                    any(word in pathlib.PurePosixPath(name).name.casefold() for word in ('license','copying','notice'))]
                if 'archive.zip' not in names or not any(name.startswith('proxy/') and name.endswith('.zip') for name in names):
                    raise ValueError('native compiler corresponding source closure is incomplete')
                for name in sorted(names):
                    source=closure_file(role['root'],name,role['files'][name])
                    package._write_zip_file(combined,'Native-Compiler-Source/'+name,source)
            else:
                package._append_git_source(combined,inputs/'upstream/desktop','Comfy-Desktop',desktop['upstream']['commit'],work)
    return pin(destination)


def received_producer_closure(app,raw,*,expected_sources,producer_source,run_id,version,intake_files=None):
    """Read original receipts only after the caller authenticates raw intake.

    Before archive production it measures the required originals. Credentialed
    receiving supplies the already authenticated API inventory and joins every
    original provenance member to it. The chain receipt has the existing own-host
    signing update; its semantic joins remain below and in the source receiver.
    Returns a relative-path -> {file,sha256,bytes} map. It makes
    no actor/config/source tuple and writes no metadata or files.
    """
    raw=pathlib.Path(raw);inputs=raw/'provenance/inputs';out=raw/'provenance'/app
    admitted=None
    if intake_files is not None:
        if (not isinstance(intake_files,list) or any(not isinstance(row,dict) or
                set(row)!={'name','bytes','sha256'} or not isinstance(row['name'],str) for row in intake_files)):
            raise ValueError('original producer closure requires the actual API file inventory')
        admitted={row['name']:row for row in intake_files}
        if len(admitted)!=len(intake_files):raise ValueError('original producer closure differs from authenticated API intake')
        required=['provenance/inputs/producer-inputs.json']
        if app=='comfyui':required+=['provenance/inputs/producer-comfyui.py','provenance/inputs/file_boundary.py']
        # Artifact code is executable input. Anchor its receipt/code/boundary
        # chain before any loader can consume local self-consistent replacements.
        for name in required:
            if name not in admitted:raise ValueError('original producer closure differs from authenticated API intake')
            bound_bytes(raw,name,admitted[name])
    original=closure_file(inputs,'producer-inputs.json')
    producer=json.loads(bound_bytes(raw,'provenance/inputs/producer-inputs.json',admitted['provenance/inputs/producer-inputs.json'])
        if admitted is not None else original.read_bytes())
    if set(producer)!={'schema','sources','build_inputs'} or producer['schema']!=1:
        raise ValueError('unsupported original producer input receipt')
    if producer['sources']!=expected_sources:raise ValueError('producer source selection differs')
    shared=shared_closure_files(inputs,producer)
    required_inputs={'lemonade':('host-tools.json','toolchain.cmake'),
                     'opencode':('opencode-plugin.tgz',),'comfyui':('desktop-host.json',)}[app]
    for name in required_inputs:
        if name not in producer['build_inputs']:raise ValueError('required producer input was not measured: '+name)
        closure_file(inputs,name,producer['build_inputs'][name])
    sdk=json.loads(shared['sdk-selection.json'].read_bytes())
    if set(sdk)!={'npm','pypi','canonical'}:raise ValueError('SDK selection closure differs')
    for kind in ('npm','pypi','canonical'):
        intake=sdk[kind] if kind=='canonical' else sdk[kind]['intake']
        if type(run_id) is not int or run_id<=0 or type(intake['run_id']) is not int or intake['source']!=producer_source or intake['run_id']!=run_id:
            raise ValueError('SDK intake source/run differs')
        artifact=intake.get('artifact',{})
        prefix={'npm':'abstraction-npm-win32-x64','pypi':'abstraction-pypi-win32-x64','canonical':'windows-sdk-signed'}[kind]
        names={prefix+'-'+str(intake['run_attempt'])}
        # Historical full-PE receipts keep their actual authenticated identity.
        # New acquisition above selects the independent SDK artifact exclusively.
        if kind=='canonical':names.add('windows-pe-signed-'+str(intake['run_attempt']))
        if (intake.get('schema')!=1 or intake.get('kind')!='windows-artifact-intake' or
                type(intake.get('run_attempt')) is not int or intake['run_attempt']<=0 or
                type(artifact.get('id')) is not int or artifact['id']<=0 or
                artifact.get('name') not in names or
                not re.fullmatch(r'[0-9a-f]{64}',str(artifact.get('sha256',''))) or
                not isinstance(intake.get('files'),list) or not intake['files']):
            raise ValueError('SDK intake immutable identity differs')
        if kind!='canonical':
            selected=sdk[kind]['selection']
            if (intake['run_attempt']!=selected['run_attempt'] or intake['artifact']!={
                'id':selected['artifact_id'],'name':selected['artifact'],'sha256':selected['artifact_digest'].removeprefix('sha256:')}):
                raise ValueError('SDK selection contradicts original intake')
    if app=='comfyui' and json.loads(shared['desktop-host.json'].read_bytes()).get('distribution')=='oa-comfyui-native':
        original_native=json.loads(closure_file(out,'native-host-receipt.json').read_bytes())
        signed=json.loads(closure_file(out,'native-host-signed.json').read_bytes())
        final_path=closure_file(raw,'apps/comfyui/installer-receipt.json');final=json.loads(final_path.read_bytes())
        measured=lambda path:{key:pin(path)[key] for key in ('bytes','sha256')}
        if (original_native.get('schema')!=1 or original_native.get('distribution')!='oa-comfyui-native' or
            original_native.get('version')!=version or original_native.get('source')!=producer_source or
            original_native.get('run_id')!=run_id or original_native.get('input_receipt')!=measured(original) or
            signed.get('schema')!=1 or signed.get('distribution')!='oa-comfyui-native' or
            signed.get('version')!=version or signed.get('source')!=producer_source or signed.get('run_id')!=run_id or
            any(signed.get('original',{}).get(key)!=value for key,value in measured(out/'native-host-receipt.json').items()) or
            final.get('schema')!=3 or final.get('distribution')!='oa-comfyui-native' or final.get('version')!=version or
            final.get('native_receipt')!=measured(out/'native-host-receipt.json') or
            final.get('signed_receipt')!=measured(out/'native-host-signed.json')):
            raise ValueError('native application producer/signing closure differs')
        for role,name in (('backend','backend-manifest.json'),('control','control-manifest.json')):
            closure_file(inputs,name,original_native['build']['resources'][role])
        closure_file(out,'signatures.json',signed['signatures'])
        closure_file(out,'launch-helper.exe',signed['native'])
        closure_file(raw,'apps/comfyui/launch-helper.exe',signed['native'])
        if final['host']!=dict(name='launch-helper.exe',**signed['native']):
            raise ValueError('native application final host differs from signer output')
        files={name:closure_file(out,name) for name in ('native-host-receipt.json','native-host-signed.json','signatures.json','launch-helper.exe')}
        paths={**{'provenance/inputs/'+name:path for name,path in shared.items()},
            **{'provenance/comfyui/'+name:path for name,path in files.items()},
            'provenance/inputs/producer-inputs.json':original,
            'apps/comfyui/installer-receipt.json':final_path,
            'apps/comfyui/bundle-app.json':closure_file(raw,'apps/comfyui/bundle-app.json'),
            'apps/comfyui/launch-helper.exe':closure_file(raw,'apps/comfyui/launch-helper.exe')}
        result={name:pin(path) for name,path in paths.items()}
        if admitted is not None and any(name not in admitted or any(admitted[name][key]!=row[key] for key in ('bytes','sha256')) for name,row in result.items()):
            raise ValueError('native application closure differs from authenticated API intake')
        return result
    files=native_closure_files(app,out,producer,version,inputs=inputs,producer_receipt=original,
        desktop_signed_pin=admitted['provenance/comfyui/desktop-signed-receipt.json'] if app=='comfyui' and admitted is not None else None)
    final_path=closure_file(raw,'apps/'+app+'/installer-receipt.json');final=json.loads(final_path.read_bytes())
    original_name={'lemonade':'native-receipt.json','comfyui':'preparation-native-receipt.json','opencode':'payload-receipt.json'}[app]
    native=json.loads(files[original_name].read_bytes())
    if app in ('lemonade','comfyui'):
        expected=final['native_receipt' if app=='lemonade' else 'preparation_source']
        closure_file(out,original_name,expected)
    else:
        if final.get('bootstrap')!=native.get('bootstrap'):
            raise ValueError('OpenCode final receipt contradicts prepared source: bootstrap')
        for key in ('plugin','payload','upstream','native_source_hashes','zip_sha256','host_inputs_sha256'):
            if final[key]!=native[key]:raise ValueError('OpenCode final receipt contradicts prepared source: '+key)
    if app=='lemonade':
        closure_file(inputs,'producer-inputs.json',final['received_input_receipt'])
        closure_file(inputs,'producer-inputs.json',native['received_input_receipt'])
        files.update(lemonade_package_files(out,final))
    if app=='comfyui':
        closure_file(inputs,'producer-inputs.json',final['package_inputs']['received_inputs'])
        closure_file(inputs,'desktop-host.json',native['desktop_binding'])
        if native['inputs']['desktop_binding']!=native['desktop_binding']:
            raise ValueError('preparation desktop binding contradicts measured input')
    if app=='opencode':closure_file(inputs,'opencode-plugin.tgz',native['plugin'])
    paths={**{'provenance/inputs/'+name:path for name,path in shared.items()},
           **{'provenance/'+app+'/'+name:path for name,path in files.items()},
           'provenance/inputs/producer-inputs.json':original,'apps/'+app+'/installer-receipt.json':final_path}
    measured={name:pin(path) for name,path in paths.items()}
    if admitted is not None:
        if any(name not in admitted or
                any(admitted[name][key]!=value[key] for key in ('bytes','sha256'))
                for name,value in measured.items() if name.startswith('provenance/')):
            raise ValueError('original producer closure differs from authenticated API intake')
    return measured


def application_package(required,version):
    helper,owners,base,inputs=native_context(required,version,checkout=True)
    relay=load_owner('windows/windows_signing.py','application_package_proof_owner')
    policy_bytes=pathlib.Path('windows/certum_simplysign.json').read_bytes();policy=json.loads(policy_bytes)
    selected=json.loads((inputs/'selected-toolchain.json').read_bytes())
    tool_args=[item for name,row in selected['tools'].items() for item in ('--'+name,row['path'])]
    common=['--input-receipt',str((base/'producer-inputs.json').resolve()),'--inputs-root',str(inputs.resolve()),
        '--sources-root',str(pathlib.Path('sources').resolve()),'--version',version,'--host-tools',str((inputs/'host-tools.json').resolve()),
        '--npm-cache',str((inputs/'npm-cache').resolve()),'--wix-ui-package',str((inputs/'wix-ui.nupkg').resolve()),
        '--wix-ui-extension',str((inputs/'WixToolset.UI.wixext.dll').resolve()),*tool_args]
    producer=json.loads(closure_file(base,'producer-inputs.json').read_bytes())
    shared=shared_closure_files(inputs,producer)
    admitted,errors={},[]
    for app,owner in owners.items():
        out=base/'native'/app;root=out/'build' if app=='lemonade' else out
        try:
            if app=='comfyui' and native_archive_selected(owner):
                original=json.loads(closure_file(out,'native-host-receipt.json').read_bytes())
                signed=json.loads(closure_file(out,'native-host-signed.json').read_bytes())
                expected_original={key:pin(out/'native-host-receipt.json')[key] for key in ('bytes','sha256')}
                if (signed.get('distribution')!='oa-comfyui-native' or signed.get('version')!=version or
                    signed.get('source')!=os.environ['CANDIDATE_SHA'] or signed.get('run_id')!=int(os.environ['GITHUB_RUN_ID']) or
                    any(signed.get('original',{}).get(key)!=value for key,value in expected_original.items()) or
                    original.get('input_receipt')!={key:pin(base/'producer-inputs.json')[key] for key in ('bytes','sha256')}):
                    raise ValueError('native application original signer/source closure differs')
                paths,source_pins=owner.native_host_source_inputs()
                if original['build']['source_files']!=source_pins:
                    raise ValueError('native application source roster differs from current selected source')
                for role,name in (('backend','backend-manifest.json'),('control','control-manifest.json')):
                    closure_file(inputs,name,original['build']['resources'][role])
                verified=relay.verify_receipt(json.loads(closure_file(out,'signatures.json',signed['signatures']).read_bytes()),
                    policy,out,policy_sha256=hashlib.sha256(policy_bytes).hexdigest())
                proofs={row['name']:row for row in verified['files']}
                if set(proofs)!={'launch-helper.exe'} or any(proofs['launch-helper.exe'][key]!=signed['native'][key] for key in ('bytes','sha256')):
                    raise ValueError('native application signing roster differs')
                closure_file(out,'launch-helper.exe',signed['native'])
                originals={name:closure_file(out,name) for name in ('native-host-receipt.json','native-host-signed.json','signatures.json')}
                admitted[app]=(out,out,proofs,originals)
                continue
            signatures=json.loads((root/'signatures.json').read_bytes())
            verified=relay.verify_receipt(signatures,policy,root,policy_sha256=hashlib.sha256(policy_bytes).hexdigest())
            proofs={row['name']:row for row in verified['files']}
            own,_,external=source_roles(app,owner,out,inputs)
            expected_names={name for _,_,name in own}|set(external)
            if app=='comfyui':expected_names.add('desktop-uninstaller.exe')
            if set(proofs)!=expected_names:
                raise ValueError('native signing result differs from source-selected closed members')
            originals=native_closure_files(app,out,producer,version,inputs=inputs,producer_receipt=base/'producer-inputs.json')
            admitted[app]=(out,root,proofs,originals)
        except (OSError,ValueError,KeyError,TypeError) as error:
            errors.append(app+': '+str(error))
    if errors:
        raise ValueError('required signed native inputs: '+'; '.join(errors))
    chain={'version':version,'apps':[]}
    for app,owner in owners.items():
        out,root,proofs,originals=admitted[app]
        if app=='comfyui' and native_archive_selected(owner):
            target=pathlib.Path('setup/apps/comfyui');target.mkdir(parents=True)
            signed=json.loads(closure_file(out,'native-host-signed.json').read_bytes())
            host={key:signed['native'][key] for key in ('bytes','sha256')}
            shutil.copyfile(closure_file(out,'launch-helper.exe',host),target/'launch-helper.exe')
            pair=load_owner('scripts/app_pair_receipt.py','native_application_declaration')
            resource=pair.validate_backend_resource(json.loads(closure_file(inputs,'backend/desktop-backend.json').read_bytes()))
            embedded=dict(schema=1,distribution=pair.NATIVE_VARIANT,
                source_policy={key:pin(closure_file(inputs,'application-manifest.json'))[key] for key in ('bytes','sha256')},
                oa_integration=json.loads(closure_file(inputs,'backend-manifest.json').read_bytes())['oa_integration'],
                backend_manifest=resource['provenance']['manifest'])
            bundle=dict(id='comfyui',title='ComfyUI — OA build',host=dict(file='launch-helper.exe',**host),embedded_integration=embedded)
            (target/'bundle-app.json').write_text(json.dumps(bundle,sort_keys=True)+'\n',encoding='utf-8')
            (target/'installer-receipt.json').write_text(json.dumps(dict(schema=3,distribution=pair.NATIVE_VARIANT,
                version=version,native_receipt={key:pin(out/'native-host-receipt.json')[key] for key in ('bytes','sha256')},
                signed_receipt={key:pin(out/'native-host-signed.json')[key] for key in ('bytes','sha256')},
                host=dict(name='launch-helper.exe',**host),embedded_integration=embedded,
                bundle_app_sha256=hashlib.sha256((target/'bundle-app.json').read_bytes()).hexdigest()),sort_keys=True)+'\n',encoding='utf-8')
            provenance=pathlib.Path('setup/provenance/comfyui');provenance.mkdir(parents=True)
            for name,path in dict(originals,**{'launch-helper.exe':closure_file(out,'launch-helper.exe')}).items():
                shutil.copyfile(path,provenance/name)
            continue
        if app=='lemonade':
            target=out/'package'
            arguments=['package',*common,'--native-root',str(out.resolve()),'--signatures',str((root/'signatures.json').resolve()),'--out',str(target.resolve())]
        elif app=='opencode':
            target=out
            arguments=['--phase','package','--app-builder',str(pathlib.Path('windows/apps/build_app.py').resolve()),
                '--desktop',str((inputs/'opencode-desktop.exe').resolve()),'--out',str(out.resolve()),'--version',version,
                '--wix',selected['tools']['wix']['path']]
            for option,name in (('installer-host','installer_host.dll'),('preflight','desktop_preflight.exe')):
                proof=proofs[name]
                arguments += ['--'+option,str((root/name).resolve()),'--'+option+'-sha256',proof['sha256'],'--'+option+'-bytes',str(proof['bytes'])]
        else:
            target=out/'package'
            arguments=['--phase','package','--desktop-binding',str((inputs/'desktop-host.json').resolve()),
                '--input-root',str(inputs.resolve()),'--shared-app-builder',str(pathlib.Path('windows/apps').resolve()),
                '--out',str(out.resolve()),'--version',version,'--extension',str(pathlib.Path(owner.__file__).parent/'extension.json'),
                '--include-root',str(pathlib.Path('sources').resolve()),'--input-receipt',str((base/'producer-inputs.json').resolve()),
                '--wix',selected['tools']['wix']['path'],*signed_desktop_arguments(out,base,relay,producer['sources']),
                '--package-source',os.environ['CANDIDATE_SHA'],'--package-run',os.environ['GITHUB_RUN_ID'],
                '--package-attempt',os.environ['GITHUB_RUN_ATTEMPT']]
            for option,name in (('action','comfyui-hostfolder.dll'),('preparation','comfyui-prepare-instance.exe'),
                                ('uninstaller','desktop-uninstaller.exe')):
                proof=proofs[name]
                arguments += ['--'+option,str((root/name).resolve()),'--'+option+'-sha256',proof['sha256'],'--'+option+'-bytes',str(proof['bytes'])]
        subprocess.run([sys.executable,str(pathlib.Path(owner.__file__).resolve()),*arguments],check=True)
        if app=='lemonade':
            originals.update(lemonade_package_files(out,json.loads((target/'installer-receipt.json').read_bytes())))
        if app=='comfyui':
            originals['package/desktop-package-receipt.json']=closure_file(out,'package/desktop-package-receipt.json')
        row=json.loads((target/'bundle-app.json').read_bytes())
        if 'embedded_integration' in row:
            row['host']['file']=str((target/pathlib.Path(row['host']['file']).name).resolve())
        else:
            row['file']=str((target/pathlib.Path(row['file']).name).resolve())
        chain['apps'].append(row)
        provenance=pathlib.Path('setup/provenance')/app;provenance.mkdir(parents=True)
        # Retain proof roots separately from the app package roles. Raw API
        # intake later authenticates them before source-policy enrichment.
        shutil.copyfile(root/'signatures.json',provenance/'signatures.json')
        for name in proofs:
            target_file=provenance/name;target_file.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(root/name,target_file)
        for name,path in originals.items():
            target_file=provenance/name;target_file.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(path,target_file)
        receipt=target/'installer-receipt.json'
        if not receipt.is_file():raise ValueError('producer omitted final installer receipt: '+app)
    packages=relay.bundle_owner().chain_packages
    retain_installer_chain(chain,'setup',packages=packages)
    if 'comfyui' in owners:
        prepare_comfy_source_pair(owners['comfyui'],inputs,producer,
            pathlib.Path('setup/provenance/comfyui/corresponding-source.zip'))
    shared_bundle=base/'shared-bundle';bundle_owner=relay.bundle_owner()
    actions_receipt=closure_file(shared_bundle,'bundle-actions-receipt.json')
    bundle_owner.check_bundle_actions(chain,closure_file(shared_bundle,bundle_owner.ACTIONS_NAME),
        actions_receipt,pin(actions_receipt)['sha256'])
    actions_signatures=json.loads(closure_file(shared_bundle,'signatures.json').read_bytes())
    relay.verify_receipt(actions_signatures,policy,shared_bundle,policy_sha256=hashlib.sha256(policy_bytes).hexdigest())
    if len(actions_signatures['files'])!=1 or actions_signatures['files'][0]['name']!=bundle_owner.ACTIONS_NAME:
        raise ValueError('shared bundle native signing roster differs')
    fresh=relay.verify(closure_file(shared_bundle,bundle_owner.ACTIONS_NAME),policy,os.environ['SIGNTOOL'])
    if any(fresh[key]!=actions_signatures['files'][0][key] for key in ('sha256','bytes')):
        raise ValueError('shared bundle native bytes changed after signature verification')
    destination=pathlib.Path('setup/provenance/shared-bundle');destination.mkdir()
    for name in ('actions_map.h','bundle-actions-receipt.json','signatures.json',bundle_owner.ACTIONS_NAME):
        shutil.copyfile(closure_file(shared_bundle,name),destination/name)
    proof_inputs=pathlib.Path('setup/provenance/inputs');proof_inputs.mkdir()
    for name in ('producer-inputs.json',):shutil.copyfile(base/name,proof_inputs/name)
    for name,path in shared.items():
        target=proof_inputs/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,target)
    for name in ('wix-ui.nupkg','WixToolset.UI.wixext.dll','opencode-cli.zip'):
        if (inputs/name).is_file():shutil.copyfile(inputs/name,proof_inputs/name)
    for app in owners:
        received_producer_closure(app,pathlib.Path('setup'),expected_sources=producer['sources'],
            producer_source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),version=version)
    canonical=pathlib.Path('setup/provenance/canonical');canonical.mkdir()
    source=base/'sdk/canonical'
    receipt=json.loads((source/'signatures.json').read_bytes())
    relay.verify_receipt(receipt,policy,source,policy_sha256=hashlib.sha256(policy_bytes).hexdigest())
    receipt=dict(receipt,files=[row for row in receipt['files'] if row['name'].startswith('native/')])
    for row in receipt['files']:
        destination=canonical/row['name'];destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(relay.member(source,row['name']),destination)
    (canonical/'signatures.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')


def source_host_binding(app,owner,row,directory,*,native=None,intake=None,relay=None,expected_sources=None):
    """Receive official host bytes against the selected producer's source policy."""
    if app=='opencode':
        expected=owner.source_owned_host_policy()
    elif app=='comfyui' and native_archive_selected(owner):
        original=json.loads(closure_file(native,'native-host-receipt.json').read_bytes())
        signed=json.loads(closure_file(native,'native-host-signed.json').read_bytes())
        if original['build']['source_files']!=owner.native_host_source_inputs()[1]:
            raise ValueError('native application source differs from selected producer')
        policy_raw=pathlib.Path('windows/certum_simplysign.json').read_bytes()
        proof=relay.verify_receipt(json.loads(closure_file(native,'signatures.json',signed['signatures']).read_bytes()),
            json.loads(policy_raw),native,policy_sha256=hashlib.sha256(policy_raw).hexdigest())
        if len(proof['files'])!=1 or proof['files'][0]['name']!='launch-helper.exe':
            raise ValueError('native application actual signer roster differs')
        actual=relay.verify(closure_file(directory,'launch-helper.exe',signed['native']),json.loads(policy_raw),os.environ['SIGNTOOL'])
        if any(actual[key]!=proof['files'][0][key] or actual[key]!=signed['native'][key] for key in ('bytes','sha256')):
            raise ValueError('native application signature or byte identity differs')
        if row.get('host')!=dict(file='launch-helper.exe',**signed['native']):
            raise ValueError('native application declared an installer or different host')
        return dict(name='apps/comfyui/launch-helper.exe',**signed['native'],
            unsigned={key:original['build']['native'][key] for key in ('bytes','sha256')},signature=actual)
    elif app=='comfyui':
        declared=received_desktop_package(owner,native,directory,intake,relay,expected_sources)
        host=declared['host'];unsigned=declared['installer']
        proof=json.loads(closure_file(native,'host-signing.json').read_bytes())
        policy_raw=pathlib.Path('windows/certum_simplysign.json').read_bytes();policy=json.loads(policy_raw)
        relay.verify_receipt(proof,policy,directory,policy_sha256=hashlib.sha256(policy_raw).hexdigest())
        if len(proof['files'])!=1 or proof['files'][0]['name']!=unsigned['name']:
            raise ValueError('custom Desktop host signing roster differs')
        signed=relay.verify(closure_file(directory,unsigned['name']),policy,os.environ['SIGNTOOL'])
        if any(signed[key]!=proof['files'][0][key] for key in ('sha256','bytes')):
            raise ValueError('custom Desktop host changed after signing')
        expected=dict(name=unsigned['name'],sha256=signed['sha256'],bytes=signed['bytes'],
                      arp_id=host['arp_id'],arp_version=host['version'],arp_win64=True)
    else:
        if 'host' in row:raise ValueError('hostless source producer declared an official host: '+app)
        return None
    received=row.get('host')
    if not isinstance(received,dict):raise ValueError('selected source requires official host: '+app)
    for key,value in expected.items():
        actual=pathlib.Path(received.get('file','')).name if key=='name' else received.get(key)
        if type(actual) is not type(value) or actual!=value:
            raise ValueError('official host differs from selected source policy: '+app+'/'+key)
    path=pathlib.Path(directory)/expected['name']
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError('official host bytes are missing or linked: '+app)
    if any(pin(path)[key]!=expected[key] for key in ('sha256','bytes')):
        raise ValueError('official host bytes differ from selected source policy: '+app)
    result=dict(name='apps/'+app+'/'+expected['name'],sha256=expected['sha256'],bytes=expected['bytes'])
    if app=='comfyui':result.update(unsigned={key:unsigned[key] for key in ('sha256','bytes')},signature=signed)
    return result


def received_desktop_package(owner,native,directory,intake,relay,expected_sources):
    declared=inherited_desktop_package(native,pathlib.Path(native).parent/'inputs',expected_sources)
    receipt=closure_file(native,'package/desktop-package-receipt.json')
    relative='provenance/comfyui/package/desktop-package-receipt.json'
    rows=[row for row in intake['files'] if row['name']==relative]
    measured=pin(receipt)
    if len(rows)!=1 or any(rows[0][key]!=measured[key] for key in ('sha256','bytes')):
        raise ValueError('custom Desktop package receipt differs from actual raw API intake')
    # Consume the same package bytes that the raw API inventory admitted.
    if json.loads(bound_bytes(native,'package/desktop-package-receipt.json',measured))!=declared:
        raise ValueError('Desktop package changed during original closure join')
    installer=declared['installer']
    unsigned=[row for row in intake['files'] if row['name']=='apps/comfyui/'+installer['name']]
    if len(unsigned)!=1 or any(unsigned[0][key]!=installer[key] for key in ('sha256','bytes')):
        raise ValueError('custom Desktop unsigned host differs from original raw API member')
    signed=None
    if (native/'host-signing.json').exists():
        if any(row['name']=='provenance/comfyui/host-signing.json' for row in intake['files']):
            raise ValueError('raw package cannot supply the credentialed host transformation proof')
        policy_raw=pathlib.Path('windows/certum_simplysign.json').read_bytes();policy=json.loads(policy_raw)
        proof=json.loads(closure_file(native,'host-signing.json').read_bytes())
        relay.verify_receipt(proof,policy,directory,policy_sha256=hashlib.sha256(policy_raw).hexdigest())
        if len(proof['files'])!=1 or proof['files'][0]['name']!=installer['name']:
            raise ValueError('custom Desktop transformed host proof has foreign members')
        signed=relay.verify(closure_file(directory,installer['name']),policy,os.environ['SIGNTOOL'])
        if any(signed[key]!=proof['files'][0][key] for key in ('sha256','bytes')):
            raise ValueError('custom Desktop transformed host differs from actual OA proof')
    return owner.custom_desktop_package(native,{key:measured[key] for key in ('sha256','bytes')},
        expected_source=intake['source'],expected_run=intake['run_id'],expected_attempt=intake['run_attempt'],
        signing_policy=pathlib.Path('windows/certum_simplysign.json'),installer_root=directory,signed_installer=signed)


def received_embedded_integration(owner,row,directory,native,intake,relay,expected_sources):
    """Reuse the source producer's complete, API-admitted Desktop wrapper join."""
    declared=received_desktop_package(owner,native,directory,intake,relay,expected_sources)
    if declared.get('schema')!=3:
        raise ValueError('embedded integration requires the source-selected Desktop profile 3')
    embedded=owner.desktop_embedded_integration(native,{'custom_build':declared},pathlib.Path('windows/apps').resolve())
    receipt=json.loads(closure_file(directory,'installer-receipt.json').read_bytes())
    if (receipt.get('schema')!=3 or receipt.get('embedded_integration')!=embedded
            or row.get('embedded_integration')!=embedded or 'expected_payload' in receipt):
        raise ValueError('embedded integration differs from original installer and source-owned wrapper')
    manifest=closure_file(pathlib.Path(native).parent/'inputs','backend-manifest.json',embedded['backend_manifest'])
    relative='provenance/inputs/backend-manifest.json'
    admitted=[entry for entry in intake['files'] if entry['name']==relative]
    if len(admitted)!=1 or any(admitted[0][key]!=pin(manifest)[key] for key in ('sha256','bytes')):
        raise ValueError('embedded runtime manifest differs from original API intake')
    return embedded


def raw_installer_intake(raw,relay):
    intake=json.loads(closure_file(raw,relay.INTAKE_RECEIPT).read_bytes())
    expected={'id':int(os.environ['APP_INSTALLER_ARTIFACT_ID']),
        'name':'windows-app-msi-raw-'+os.environ['APP_INSTALLER_ARTIFACT_ATTEMPT'],
        'sha256':os.environ['APP_INSTALLER_ARTIFACT_DIGEST'].removeprefix('sha256:')}
    if (any(type(intake.get(key)) is not int for key in ('run_id','run_attempt')) or
            type(intake.get('artifact',{}).get('id')) is not int or
            intake['source']!=os.environ['CANDIDATE_SHA'] or intake['run_id']!=int(os.environ['GITHUB_RUN_ID']) or
            intake['run_attempt']!=int(os.environ['APP_INSTALLER_ARTIFACT_ATTEMPT']) or intake['artifact']!=expected):
        raise ValueError('raw installer provenance differs from independently received API artifact')
    return intake,expected


def application_sign_host(required,version):
    if 'comfyui' not in required:return
    helper,pins=selected_sources(required,version,checkout=True)
    owners=producer_owners(required);relay=load_owner('windows/windows_signing.py','application_outer_host_signer')
    if native_archive_selected(owners['comfyui']):return
    raw=pathlib.Path('signed/apps');intake,_=raw_installer_intake(raw,relay)
    original=json.loads(closure_file(raw,'provenance/inputs/producer-inputs.json').read_bytes())
    if original['sources']!=pins:raise ValueError('custom Desktop package selected sources differ')
    native=raw/'provenance/comfyui';directory=raw/'apps/comfyui'
    package=received_desktop_package(owners['comfyui'],native,directory,intake,relay,pins)
    installer=package['installer'];host=closure_file(directory,installer['name'])
    row_path=closure_file(directory,'bundle-app.json');row=json.loads(row_path.read_bytes())
    # Package receiving already verified either the raw bytes or this exact
    # prior OA-signed transform. Admit the row before entering the signer.
    current=pin(host)
    if not any(all(row['host'][key]==value[key] for key in ('sha256','bytes'))
               for value in (installer,current)):
        raise ValueError('raw Burn host differs from packaged unsigned host')
    subprocess.run([sys.executable,'windows/windows_signing.py','sign','--policy','windows/certum_simplysign.json',
        '--signtool',os.environ['SIGNTOOL'],'--root',str(directory),'--receipt',str(native/'host-signing.json'),
        '--file',installer['name']],check=True)
    policy=json.loads(pathlib.Path('windows/certum_simplysign.json').read_bytes())
    signed=relay.verify(host,policy,os.environ['SIGNTOOL'])
    row['host'].update(sha256=signed['sha256'],bytes=signed['bytes'])
    raw_row=(json.dumps(row,indent=2)+'\n').encode();row_path.write_bytes(raw_row)
    receipt_path=closure_file(directory,'installer-receipt.json');receipt=json.loads(receipt_path.read_bytes())
    receipt['bundle_app_sha256']=hashlib.sha256(raw_row).hexdigest()
    receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')


def application_bind(required,version):
    helper,pins=selected_sources(required,version,checkout=True)
    owners=producer_owners(required)
    relay=load_owner('windows/windows_signing.py','application_role_receiving')
    root=pathlib.Path('signed');raw=root/'apps';inputs=raw/'provenance/inputs'
    intake,expected_artifact=raw_installer_intake(raw,relay)
    original=json.loads((inputs/'producer-inputs.json').read_bytes())
    if original['sources']!=pins:raise ValueError('app producer source/SDK selection differs from current source')
    for app in owners:
        received_producer_closure(app,raw,expected_sources=pins,producer_source=os.environ['CANDIDATE_SHA'],
                                  run_id=int(os.environ['GITHUB_RUN_ID']),version=version,intake_files=intake['files'])
    for name in ('wix-ui.nupkg','WixToolset.UI.wixext.dll','opencode-cli.zip'):
        if (inputs/name).is_file():
            if any(pin(inputs/name)[key]!=original['build_inputs'][name][key] for key in ('sha256','bytes')):
                raise ValueError('retained role-policy input differs from producer measurement: '+name)
    policy_bytes=pathlib.Path('windows/certum_simplysign.json').read_bytes();policy=json.loads(policy_bytes)
    policy_sha=hashlib.sha256(policy_bytes).hexdigest()
    hosts,errors={},[]
    for app,owner in owners.items():
        try:
            directory=raw/'apps'/app
            row=json.loads((directory/'bundle-app.json').read_bytes())
            hosts[app]=source_host_binding(app,owner,row,directory,native=raw/'provenance'/app,intake=intake,relay=relay,expected_sources=pins)
        except (OSError,ValueError,KeyError,TypeError) as error:
            errors.append(app+': '+str(error))
    if errors:raise ValueError('required official host source inputs: '+'; '.join(errors))
    bindings,external_proofs={},[]
    for app,owner in owners.items():
        directory=raw/'apps'/app;native=raw/'provenance'/app
        receipt=json.loads((directory/'installer-receipt.json').read_bytes())
        if app=='comfyui' and native_archive_selected(owner):
            pair=load_owner('scripts/app_pair_receipt.py','native_catalog_binding_owner')
            package=load_owner('scripts/package_comfyui_app.py','native_catalog_assembly_owner')
            resource=pair.validate_backend_resource(json.loads(closure_file(inputs,'backend/desktop-backend.json').read_bytes()))
            runtime=json.loads(closure_file(inputs,'backend-manifest.json').read_bytes())
            embedded=receipt['embedded_integration']
            binding=dict(source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
                run_attempt=int(os.environ['APP_INSTALLER_ARTIFACT_ATTEMPT']),artifact=expected_artifact,
                intake=intake,host=hosts[app],embedded_integration=embedded)
            context=dict(producer=binding,source_policy=embedded['source_policy'],
                backend_input_descriptor=owner.native_input_pins()['backend'],oa_integration=runtime['oa_integration'],
                backend=resource,backend_manifest=runtime,
                control_manifest=json.loads(closure_file(inputs,'control-manifest.json').read_bytes()),
                control_pin=json.loads(closure_file(native,'native-host-receipt.json').read_bytes())['build']['resources']['control'],
                signatures=dict(host_signing=relay.verify_receipt(json.loads(closure_file(native,'signatures.json').read_bytes()),
                    policy,native,policy_sha256=policy_sha)))
            destination=root/'native-app/comfyui';destination.mkdir(parents=True)
            source_path=closure_file(native,'corresponding-source.zip')
            source_set=pair.copy_archive_set(source_path,destination,format='zip')
            descriptor=json.loads(closure_file(inputs,'backend-inputs.json').read_bytes())
            license_name=descriptor.get('runtime_provenance',{}).get('comfyui',{}).get('license')
            license_rows=[row for row in descriptor['files'] if row['name']==license_name]
            if len(license_rows)!=1:raise ValueError('native application selected source licence is absent')
            license_pin=license_rows[0];license_target=destination/'LICENSE'
            with pair.checked_zip(source_path,bounded_members=True,expanded_limit=16<<30) as content:
                matches=[entry for entry in content.infolist() if not entry.is_dir() and entry.file_size==license_pin['bytes']]
                found=[]
                for entry in matches:
                    data=content.read(entry)
                    if hashlib.sha256(data).hexdigest()==license_pin['sha256']:found.append(data)
                if not found:raise ValueError('native corresponding source lacks selected Comfy licence')
                license_target.write_bytes(found[0])
            binary=destination/('ComfyUI-OA-'+version+'-windows-x64.zip')
            package.assemble_native_archive(directory/'launch-helper.exe',destination,
                dict(archive=source_set,data_release=resource['data_release']),context,binary,
                version=version,notices={'LICENSE':license_target},control=inputs/'control-stage/oa-control',
                archive_tool=inputs/'archive-tool',backend_manifest=inputs/'backend-manifest.json')
            bindings[app]=dict(binding,delivery=dict(variant=pair.NATIVE_VARIANT,directory='native-app/comfyui',
                binary=dict(name=binary.name,**{key:pin(binary)[key] for key in ('bytes','sha256')}),source=source_set,
                context={key:value for key,value in context.items() if key not in ('producer','backend_manifest','control_manifest')}))
            continue
        if app=='comfyui' and receipt.get('schema')==3:
            row=json.loads(closure_file(directory,'bundle-app.json').read_bytes())
            embedded=received_embedded_integration(owner,row,directory,native,intake,relay,pins)
            _,_,external=source_roles(app,owner,native,inputs)
            preparation=row['host']['preparation']
            if set(external)!={pathlib.Path(preparation['file']).name}:
                raise ValueError('embedded Desktop preparation differs from source-selected native role')
            received=json.loads(closure_file(native,'signatures.json').read_bytes())
            helper.merge_native_signature_receipts(native,external,[(received,native)],policy,policy_sha,relay)
            for name in external:
                proof=relay.verify(closure_file(native,name),policy,os.environ['SIGNTOOL'])
                final='apps/apps/'+app+'/'+name
                if (any(pin(relay.member(root,final))[key]!=proof[key] for key in ('sha256','bytes'))
                        or any(preparation[key]!=proof[key] for key in ('sha256','bytes'))):
                    raise ValueError('embedded Desktop preparation differs from actual signed native bytes')
                external_proofs.append(dict(proof,name=final))
            bindings[app]={'source':os.environ['CANDIDATE_SHA'],'run_id':int(os.environ['GITHUB_RUN_ID']),
                'run_attempt':int(os.environ['APP_INSTALLER_ARTIFACT_ATTEMPT']),'artifact':expected_artifact,
                'intake':intake,'host':hosts[app],'embedded_integration':embedded}
            continue
        payload=receipt['compiled_readback']['expected_payload'] if app=='opencode' else receipt['expected_payload']
        role_owner=lambda value:source_roles(app,owner,native,inputs,value)
        own,supplier,external=role_owner(payload)
        if app=='opencode':
            # check_prepared in the source getter checked this complete ZIP.
            with zipfile.ZipFile(native/'integration-payload.zip') as archive:
                for _,_,name in own:
                    if name.startswith('payload/'):
                        relative=name.removeprefix('payload/')
                        owner.build_app.member_segments(relative)
                        target=native/name
                        if target.exists():raise ValueError('source-selected SDK proof target already exists')
                        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.read(relative))
        received=[(json.loads((native/'signatures.json').read_bytes()),native)]
        if app=='opencode':
            canonical=raw/'provenance/canonical'
            received.append((json.loads((canonical/'signatures.json').read_bytes()),canonical))
        names=[name for _,_,name in own]+list(external)
        merged=helper.merge_native_signature_receipts(native,names,received,policy,policy_sha,relay)
        # Existing pinned verifier supplies actual certificate/chain evidence;
        # no JSON role declaration or self digest substitutes for verification.
        fresh=dict(merged,files=[dict(relay.verify(relay.member(native,name),policy,os.environ['SIGNTOOL']),name=name)
                                 for name in names])
        enriched,external_received=helper.enrich_installer_payload(payload,role_owner,fresh,policy,policy_sha,native,relay)
        enriched['msi']=dict(enriched['msi'],name='apps/'+app+'/'+pathlib.Path(enriched['msi']['name']).name)
        bindings[app]={'source':os.environ['CANDIDATE_SHA'],'run_id':int(os.environ['GITHUB_RUN_ID']),
            'run_attempt':int(os.environ['APP_INSTALLER_ARTIFACT_ATTEMPT']),'artifact':expected_artifact,
            'intake':intake,'expected_payload':enriched}
        if hosts[app] is not None:bindings[app]['host']=hosts[app]
        for name,proof in external_received.items():
            final='apps/apps/'+app+'/'+pathlib.Path(name).name
            if any(pin(relay.member(root,final))[key]!=proof[key] for key in ('sha256','bytes')):
                raise ValueError('external app native member differs from admitted signed producer bytes')
            external_proofs.append(dict(proof,name=final))
    def verify(chain,expected):
        relay.producer_hosts(chain,expected,source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
                             run_attempt=int(os.environ['APP_INSTALLER_ARTIFACT_ATTEMPT']),delivery_root=root)
    chain=received_installer_chain(required,raw/'apps',bindings,version,verify,packages=relay.bundle_owner().chain_packages)
    (raw/'producer-bindings.json').write_text(json.dumps(bindings,sort_keys=True)+'\n')
    if external_proofs:
        receipt={'schema':1,'result':'pass','policy_sha256':policy_sha,'files':external_proofs}
        relay.verify_receipt(receipt,policy,root,policy_sha256=policy_sha)
        (root/'app-native-signatures.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')
    return chain


def seal_external_app_proofs(required, version):
    root=pathlib.Path('signed');external=root/'app-native-signatures.json'
    helper=load_owner('scripts/app_producer_inputs.py','application_final_proof_join')
    relay=load_owner('windows/windows_signing.py','application_final_proof_validator')
    policy_bytes=pathlib.Path('windows/certum_simplysign.json').read_bytes();policy=json.loads(policy_bytes)
    bindings=json.loads((root/'apps/producer-bindings.json').read_bytes())
    host_proofs = [dict(binding['host']['signature'], name='apps/' + binding['host']['name'])
                   for binding in bindings.values() if isinstance(binding.get('host'), dict) and 'signature' in binding['host']]
    if external.exists() or host_proofs:
        receipts=[json.loads((root/'signatures.json').read_bytes())]
        if external.exists(): receipts.append(json.loads(external.read_bytes()))
        if host_proofs:
            receipts.append({'schema':1,'result':'pass','policy_sha256':hashlib.sha256(policy_bytes).hexdigest(),'files':host_proofs})
        names=[row['name'] for receipt in receipts for row in receipt['files']]
        merged=helper.merge_native_signature_receipts(root,names,[(receipt,root) for receipt in receipts],
            policy,hashlib.sha256(policy_bytes).hexdigest(),relay)
        (root/'signatures.json').write_text(json.dumps(merged,sort_keys=True)+'\n')
    source=os.environ['CANDIDATE_SHA'];run_id=int(os.environ['GITHUB_RUN_ID'])
    attempt=int(os.environ['APP_INSTALLER_ARTIFACT_ATTEMPT'])
    chain=json.loads((root/'apps/chain.json').read_bytes())
    catalog={app for app,binding in bindings.items() if binding.get('delivery',{}).get('variant')=='oa-comfyui-native'}
    if (set(bindings)!=set(required) or chain['version']!=version or
            {row['id'] for row in chain['apps']}!=set(required)-catalog):
        raise ValueError('signed app chain differs from selected version/app set')
    relay.producer_hosts(chain,bindings,source=source,run_id=run_id,run_attempt=attempt,delivery_root=root)
    context=dict(version=version,source=source,run_id=run_id,run_attempt=attempt,
                 sources=selected_sources(required,version)[1],expected_producers=bindings)
    (root/'app-chain-context.json').write_text(json.dumps(context,sort_keys=True)+'\n')


def assemble_desktop_pair(directory,native,binding,package,signatures,source,version,out,pair_owner,chain_row):
    """Write the existing final capsule schema from already admitted role proofs."""
    out.mkdir(parents=True);source_pin=pin(source);modern=package['schema']==3
    source_name='OpenAbstractions-ComfyUI-'+version+'-source.zip'
    if modern:
        source_set=pair_owner.copy_archive_set(source,out,format='zip',name=source_name)
        source_target=source
    else:
        source_target=out/source_name;shutil.copyfile(source,source_target)
        if any(pin(source_target)[key]!=source_pin[key] for key in ('sha256','bytes')):
            raise ValueError('corresponding source changed while copying')
    source_files=[];notices={}
    with pair_owner.checked_zip(source_target,bounded_members=True,expanded_limit=(16<<30 if modern else 8<<30)) as archive:
        for entry in archive.infolist():
            if entry.is_dir():continue
            digest=hashlib.sha256()
            with archive.open(entry) as reader:
                for block in iter(lambda:reader.read(1<<20),b''):digest.update(block)
            source_files.append(dict(name=entry.filename,sha256=digest.hexdigest(),bytes=entry.file_size))
            if pathlib.PurePosixPath(entry.filename).name.lower() in ('license','license.txt','license.md','notice','notice.txt'):
                if entry.file_size>1<<20:raise ValueError('corresponding notice exceeds bound')
                notices['source-notice-'+str(len(notices))+'.txt']=archive.read(entry)
    if not notices:raise ValueError('custom Desktop corresponding source omits notices')
    row=json.loads(json.dumps(chain_row))
    selected_roles=[('host',row['host']),('preparation',row['host']['preparation'])]
    if not modern:selected_roles.append(('integration',row))
    roles={key:{'name':pathlib.Path(value['file']).name,'sha256':value['sha256'],'bytes':value['bytes']}
        for key,value in selected_roles}
    if len({value['name'].casefold() for value in roles.values()})!=len(roles):raise ValueError('final Desktop role collision')
    # Final capsule row uses flat names. It preserves all other actual Burn fields.
    if not modern:row['file']=roles['integration']['name']
    row['host']['file']=roles['host']['name']
    row['host']['preparation']['file']=roles['preparation']['name']
    final={key:package[key] for key in ('version','source_policy','build_inputs','identity','source','run_id','run_attempt',
        'host','native_files','desktop_files','signatures','helper_receipt','helpers')}
    if modern:final['supplier_preserved']=package['supplier_preserved']
    if 'helper_carrier' in package:final['helper_carrier']=package['helper_carrier']
    final.update(schema=package['schema'],stage='desktop-final',installer=roles['host'],
        source_pair=source_set if modern else dict(name=source_name,**{key:source_pin[key] for key in ('sha256','bytes')}))
    final_path=out/'desktop-build-receipt.json';final_path.write_text(json.dumps(final,sort_keys=True)+'\n')
    backend_raw=closure_file(directory.parent.parent,'provenance/inputs/backend-manifest.json').read_bytes()
    backend=json.loads(backend_raw)
    descriptor=json.loads(closure_file(directory.parent.parent,'provenance/inputs/backend-inputs.json').read_bytes())
    policy=package['source_policy'];backend_pin=package['build_inputs']['backend']
    context={'producer':binding,'source_policy':policy,'backend_input_descriptor':backend_pin,
             'oa_integration':backend['oa_integration'],'signatures':signatures}
    resource=None
    if modern:
        resource=pair_owner.validate_backend_resource(json.loads(closure_file(directory.parent.parent,
            'provenance/inputs/backend/desktop-backend.json').read_bytes()))
        context['backend']=resource
        context['backend_manifest']=backend
    proofs=dict(signatures,producer_binding=binding,source={'schema':2 if modern else 1,
        'source_pair':final['source_pair'],'files':source_files})
    metadata={'bundle-app.json':(json.dumps(row,sort_keys=True)+'\n').encode()}
    if modern:metadata['backend-manifest.json']=backend_raw
    metadata.update({key+'.json':(json.dumps(value,sort_keys=True)+'\n').encode() for key,value in proofs.items()})
    def metadata_pin(name):return dict(name=name,sha256=hashlib.sha256(metadata[name]).hexdigest(),bytes=len(metadata[name]))
    manifest=dict(schema=2,variant='oa-comfyui-desktop',version=version,
        desktop_source_commit=descriptor.get('desktop_commit',package.get('desktop_source_commit')),
        comfyui_source_commit=descriptor['comfyui_commit'],corresponding_comfyui_source_zip=source_name,
        corresponding_comfyui_source_zip_sha256=source_pin['sha256'],source_policy=policy,
        backend_input_descriptor=backend_pin,oa_integration=backend['oa_integration'],
        bundle_app=metadata_pin('bundle-app.json'),roles=roles,
        proofs={key:metadata_pin(key+'.json') for key in proofs},
        preserved_notice_paths=sorted(notices),added_notice_paths=[])
    if modern:
        del manifest['corresponding_comfyui_source_zip'];del manifest['corresponding_comfyui_source_zip_sha256']
        manifest.update(schema=3,backend=resource,
            embedded_integration=row['embedded_integration'],
            corresponding_source=dict(archive=source_set,data_release=resource['data_release']))
    # Source identity is present in the exact source-selected policy, not inferred
    # from the backend or a package basename.
    with pair_owner.checked_zip(source_target,bounded_members=True,expanded_limit=(16<<30 if modern else 8<<30)) as archive:
        selected=[row['name'] for row in source_files if row['bytes']==policy['bytes'] and row['sha256']==policy['sha256']]
        if not selected:raise ValueError('custom Desktop source policy is missing')
        manifest['desktop_source_commit']=json.loads(archive.read(selected[0]))['upstream']['commit']
    binary=out/('OpenAbstractions-ComfyUI-'+version+'.zip')
    with zipfile.ZipFile(binary,'x',zipfile.ZIP_DEFLATED) as archive:
        for role in roles.values():
            source_path=closure_file(directory,role['name'],role)
            with source_path.open('rb') as reader,archive.open(role['name'],'w',force_zip64=True) as writer:
                shutil.copyfileobj(reader,writer,1<<20)
        for name,data in {**metadata,**notices,'OA-PROVENANCE.json':(json.dumps(manifest,sort_keys=True)+'\n').encode()}.items():
            archive.writestr(name,data)
    if any(pin(source)[key]!=source_pin[key] for key in ('sha256','bytes')):
        raise ValueError('admitted corresponding source changed during final assembly')
    result=(pair_owner.inspect_desktop_set(binary,out,source_set,require_clean_paths=True,desktop_context=context)
        if modern else pair_owner.inspect('comfyui',binary,source_target,require_clean_paths=True,desktop_context=context))
    (out/'pair-receipt.json').write_text(json.dumps(result,sort_keys=True)+'\n')
    return result


def application_final_capsule(required,version):
    if 'comfyui' not in required:return
    relay=load_owner('windows/windows_signing.py','application_final_capsule_receiving')
    selected=selected_sources(required,version)[1]
    root=pathlib.Path('signed-msis');context,_=relay.retained_application_context(root,root/'app-chain-context.json',
        source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
        artifact_id=int(os.environ['APP_CONTEXT_ARTIFACT_ID']),
        artifact_name='windows-app-signed-'+os.environ['APP_CONTEXT_ARTIFACT_ATTEMPT'],
        artifact_digest=os.environ['APP_CONTEXT_ARTIFACT_DIGEST'].removeprefix('sha256:'),
        artifact_attempt=int(os.environ['APP_CONTEXT_ARTIFACT_ATTEMPT']),version=version,required=required,
        sources=selected)
    if context['expected_producers'].get('comfyui',{}).get('delivery',{}).get('variant')=='oa-comfyui-native':
        return final_native_archive(root,context['expected_producers']['comfyui'],selected,version,relay)
    policy_raw=pathlib.Path('windows/certum_simplysign.json').read_bytes();policy=json.loads(policy_raw)
    policy_sha=hashlib.sha256(policy_raw).hexdigest()
    native=root/'apps/provenance/comfyui';directory=root/'apps/apps/comfyui'
    package=inherited_desktop_package(native,root/'apps/provenance/inputs',selected)
    receipts={}
    signature_inputs=[('host_signing',native/'host-signing.json',directory),
                      ('inner_signatures',native/'signatures.json',native)]
    if package['schema']!=3:signature_inputs.append(('msi_signatures',root/'signatures.json',root))
    for key,path,proof_root in signature_inputs:
        proof=relay.verify_receipt(json.loads(path.read_bytes()),policy,proof_root,policy_sha256=policy_sha)
        for row in proof['files']:
            observed=relay.verify(relay.member(proof_root,row['name']),policy,os.environ['SIGNTOOL'])
            if any(observed[name]!=row[name] for name in ('sha256','bytes')):raise ValueError('final native proof changed')
        receipts[key]=proof
    desktop=relay.verify_receipt(json.loads(closure_file(native,'desktop-signatures.json').read_bytes()),
        policy,native,policy_sha256=policy_sha)
    for row in desktop['files']:
        actual=relay.verify(relay.member(native,row['name']),policy,os.environ['SIGNTOOL'])
        if any(actual[key]!=row[key] for key in ('sha256','bytes')):raise ValueError('final signed Desktop member changed')
    combined=receipts['inner_signatures']['files']+desktop['files']
    if len({row['name'] for row in combined})!=len(combined):raise ValueError('final inner native proof aliases')
    receipts['inner_signatures']=dict(receipts['inner_signatures'],files=combined)
    # The actual signed chain has container reseals; the producer row retained in
    # the raw artifact remains immutable evidence and is copied locally here.
    chain=json.loads(closure_file(root,'apps/chain.json').read_bytes())
    rows=[row for row in chain['apps'] if row['id']=='comfyui']
    if len(rows)!=1:raise ValueError('final Desktop chain selection differs')
    pair=load_owner('scripts/app_pair_receipt.py','application_final_capsule_inspector')
    out=pathlib.Path('final-apps/comfyui')
    result=assemble_desktop_pair(directory,native,context['expected_producers']['comfyui'],package,receipts,
        closure_file(native,'corresponding-source.zip'),version,out,pair,rows[0])
    artifact='oa-app-comfyui-'+os.environ['GITHUB_RUN_ATTEMPT']
    source_commit=selected['openabstractions/adopter-comfyui']
    producer=dict(candidate_source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
                  run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT']))
    wrapper=dict(schema=1,producer_job='windows-app-delivery',candidate_source=producer['candidate_source'],
        run_id=producer['run_id'],run_attempt=producer['run_attempt'],selected_sources=selected,
        signer_artifact=dict(id=int(os.environ['APP_CONTEXT_ARTIFACT_ID']),
            name='windows-app-signed-'+os.environ['APP_CONTEXT_ARTIFACT_ATTEMPT'],
            sha256=os.environ['APP_CONTEXT_ARTIFACT_DIGEST'].removeprefix('sha256:'),
            run_attempt=int(os.environ['APP_CONTEXT_ARTIFACT_ATTEMPT'])),
        desktop_context=dict(producer=context['expected_producers']['comfyui'],source_policy=package['source_policy'],
            backend_input_descriptor=package['build_inputs']['backend'],
            oa_integration=json.loads(closure_file(root,'apps/provenance/inputs/backend-manifest.json').read_bytes())['oa_integration'],
            signatures=receipts))
    if package['schema']==3:
        wrapper['desktop_context']['backend']=pair.validate_backend_resource(json.loads(closure_file(root,
            'apps/provenance/inputs/backend/desktop-backend.json').read_bytes()))
        wrapper['desktop_context']['backend_manifest']=json.loads(closure_file(root,
            'apps/provenance/inputs/backend-manifest.json').read_bytes())
    (out/'desktop-context.json').write_text(json.dumps(wrapper,sort_keys=True)+'\n')
    with zipfile.ZipFile(out/result['binary']['name']) as archive:
        staging_peak=sum(entry.file_size for entry in archive.infolist())+result['binary']['bytes']+result['source']['bytes']
    row=dict(id='comfyui',variant='oa-comfyui-desktop',binary_zip=result['binary']['name'],
        binary_sha256=result['binary']['sha256'],binary_bytes=result['binary']['bytes'],
        source_zip=result['source']['name'],source_sha256=result['source']['sha256'],source_bytes=result['source']['bytes'],
        source_commit=source_commit,source_url='https://github.com/openabstractions/adopter-comfyui/commit/'+source_commit,
        version=version,platform='windows/amd64',peak_bytes=staging_peak,license=result['identity']['license'],
        publisher='OpenAbstractions',release_tag='v'+version)
    if result['schema']==3:
        for key in ('source_zip','source_sha256','source_bytes'):del row[key]
        row.update(corresponding_source=dict(archive=result['source'],data_release=wrapper['desktop_context']['backend']['data_release']),
            backend=wrapper['desktop_context']['backend'])
    assets=load_owner('scripts/app_assets.py','application_final_producer_metadata')
    assets.prepare_producer(row,out,producer['candidate_source'],producer['run_id'],producer['run_attempt'],
        desktop_context=wrapper['desktop_context'],producer_job='windows-app-delivery')
    with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as output:
        output.write('artifact='+artifact+'\nsource_commit='+source_commit+'\n')
    return result


def final_native_archive(root,binding,selected,version,relay):
    """Forward the already assembled catalog pair after current API admission."""
    pair=load_owner('scripts/app_pair_receipt.py','final_native_catalog_receiving')
    result=pair.inspect_native_delivery(root,binding,source=os.environ['CANDIDATE_SHA'],
        run_id=int(os.environ['GITHUB_RUN_ID']),run_attempt=binding['run_attempt'])
    delivery=binding['delivery'];source=pathlib.Path(root)/delivery['directory']
    out=pathlib.Path('final-apps/comfyui');out.mkdir(parents=True)
    for row in (delivery['binary'],*delivery['source']['parts']):
        shutil.copyfile(closure_file(source,row['name'],row),out/row['name'])
        closure_file(out,row['name'],row)
    context=dict(delivery['context'])
    context['producer']={key:value for key,value in binding.items() if key!='delivery'}
    context['backend_manifest']=json.loads(closure_file(root,'apps/provenance/inputs/backend-manifest.json',
        context['backend']['provenance']['manifest']).read_bytes())
    context['control_manifest']=json.loads(closure_file(root,'apps/provenance/inputs/control-manifest.json',context['control_pin']).read_bytes())
    policy_raw=pathlib.Path('windows/certum_simplysign.json').read_bytes()
    host=relay.verify(closure_file(root,'apps/apps/comfyui/launch-helper.exe',binding['host']),
        json.loads(policy_raw),os.environ['SIGNTOOL'])
    if any(host[key]!=binding['host'][key] for key in ('bytes','sha256')):
        raise ValueError('final native application signature differs')
    producer=dict(candidate_source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
        run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT']))
    wrapper=dict(schema=1,producer_job='windows-app-delivery',**producer,selected_sources=selected,
        signer_artifact=dict(id=int(os.environ['APP_CONTEXT_ARTIFACT_ID']),
            name='windows-app-signed-'+os.environ['APP_CONTEXT_ARTIFACT_ATTEMPT'],
            sha256=os.environ['APP_CONTEXT_ARTIFACT_DIGEST'].removeprefix('sha256:'),
            run_attempt=int(os.environ['APP_CONTEXT_ARTIFACT_ATTEMPT'])),desktop_context=context)
    (out/'desktop-context.json').write_text(json.dumps(wrapper,sort_keys=True)+'\n',encoding='utf-8')
    original_pins=[row for row in binding['intake']['files'] if row['name']=='apps/comfyui/installer-receipt.json']
    if len(original_pins)!=1:raise ValueError('native final artifact lacks its original package receipt')
    original=closure_file(root,'apps/apps/comfyui/installer-receipt.json',original_pins[0])
    original_raw=original.read_bytes();package=json.loads(original_raw)
    expected_host=dict(name=pathlib.PurePosixPath(binding['host']['name']).name,
        **{key:binding['host'][key] for key in ('bytes','sha256')})
    if (package.get('schema')!=3 or package.get('distribution')!=pair.NATIVE_VARIANT or package.get('version')!=version or
            package.get('host')!=expected_host or package.get('embedded_integration')!=binding['embedded_integration']):
        raise ValueError('native final package receipt differs from admitted application')
    (out/'desktop-build-receipt.json').write_bytes(original_raw)
    (out/'pair-receipt.json').write_text(json.dumps(result,sort_keys=True)+'\n',encoding='utf-8')
    with zipfile.ZipFile(out/result['binary']['name']) as content:
        host_expanded=sum(entry.file_size for entry in content.infolist())
    runtime=context['backend_manifest'];backend_expanded=sum(row['bytes'] for row in runtime['runtime_files'].values())+context['backend']['provenance']['manifest']['bytes']
    # Retained compressed inputs and complete extraction stages coexist. The
    # setup owner receives these exact declared byte terms before installation.
    terms=pair.native_record_terms(runtime,context['control_manifest'])
    peak=host_expanded+result['binary']['bytes']+context['backend']['archive']['bytes']+backend_expanded+terms['record_bytes']+result['identity']['marker_bytes']+(64<<10)
    commit=selected['openabstractions/adopter-comfyui']
    row=dict(id='comfyui',variant=pair.NATIVE_VARIANT,binary_zip=result['binary']['name'],
        binary_sha256=result['binary']['sha256'],binary_bytes=result['binary']['bytes'],
        corresponding_source=dict(archive=result['source'],data_release=context['backend']['data_release']),
        backend=context['backend'],source_commit=commit,
        source_url='https://github.com/openabstractions/adopter-comfyui/commit/'+commit,
        version=version,platform='windows/amd64',peak_bytes=peak,license=result['identity']['license'],
        publisher='OpenAbstractions',release_tag='v'+version,install_identity=pair.NATIVE_VARIANT,
        action='archive_per_user',application_program=result['identity']['programs']['application'],
        service_program=result['identity']['programs']['service'],archive_tool_program=result['identity']['archive_tool_program'],
        marker_bytes=result['identity']['marker_bytes'],**terms)
    assets=load_owner('scripts/app_assets.py','final_native_catalog_metadata')
    assets.prepare_producer(row,out,producer['candidate_source'],producer['run_id'],producer['run_attempt'],
        desktop_context=context,producer_job='windows-app-delivery')
    with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as stream:
        stream.write('artifact=oa-app-comfyui-'+str(producer['run_attempt'])+'\nsource_commit='+commit+'\n')
    return result


def application_bundle(required,version):
    command=[sys.executable,'windows/apps/build_bundle.py','--chain','setup/chain.json',
             '--bal-ext',os.environ['WIX_BAL_EXT'],'--out','setup/bundle']
    if required:
        relay=load_owner('windows/windows_signing.py','application_bundle_native_intake')
        root=pathlib.Path('signed-msis')
        relay.retained_application_context(root,root/'app-chain-context.json',
            source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
            artifact_id=int(os.environ['APP_CONTEXT_ARTIFACT_ID']),
            artifact_name='windows-msi-signed-'+os.environ['APP_CONTEXT_ARTIFACT_ATTEMPT'],
            artifact_digest=os.environ['APP_CONTEXT_ARTIFACT_DIGEST'].removeprefix('sha256:'),
            artifact_attempt=int(os.environ['APP_CONTEXT_ARTIFACT_ATTEMPT']),version=version,required=required,
            sources=selected_sources(required,version)[1])
        intake=json.loads(closure_file(root,relay.INTAKE_RECEIPT).read_bytes())
        name='apps/provenance/shared-bundle/bundle-actions-receipt.json'
        selected=[row for row in intake['files'] if row['name']==name]
        if len(selected)!=1:raise ValueError('signed artifact omits exact shared bundle native receipt')
        receipt=closure_file(root,name,selected[0]);directory=receipt.parent
        command+=['--actions-dll',str(closure_file(directory,'oa_bundle_actions.dll').resolve()),
            '--actions-receipt',str(receipt.resolve()),'--actions-receipt-sha256',selected[0]['sha256']]
    subprocess.run(command,check=True)


def application_stage_final(required,version):
    """Receive the successful verify job's final pair on the existing draft leg."""
    if 'comfyui' not in required:raise ValueError('final Desktop staging requires the accepted installer scope')
    relay=load_owner('windows/windows_signing.py','application_final_api_intake')
    assets=load_owner('scripts/app_assets.py','application_final_asset_receiving')
    selected=selected_sources(required,version)[1]
    host_path=closure_file(pathlib.Path('.'),'windows/apps/comfyui/desktop-host.json')
    host=json.loads(host_path.read_bytes())
    native=host.get('distribution')=='oa-comfyui-native'
    source_path=closure_file(pathlib.Path('.'),'windows/apps/comfyui/backendlaunch/application-manifest.json' if native else 'windows/apps/comfyui/desktop-source.json')
    source_policy=json.loads(source_path.read_bytes())
    measured_policy={key:pin(source_path)[key] for key in ('sha256','bytes')}
    if (host.get('schema')!=2 or host.get('distribution') not in ('oa-custom-desktop','oa-comfyui-native') or
            (not native and host['source_policy']!=measured_policy)):
        raise ValueError('draft Desktop policy differs from current source-owned projection')
    expected={'source_policy':measured_policy,'backend_input_descriptor':host['build_inputs']['backend']}
    attempt=int(os.environ['COMFY_FINAL_ARTIFACT_ATTEMPT'])
    artifact='oa-app-comfyui-'+str(attempt)
    destination=pathlib.Path('app-inputs/comfyui')
    intake=relay.consume_artifact(int(os.environ['COMFY_FINAL_ARTIFACT_ID']),
        os.environ['COMFY_FINAL_ARTIFACT_DIGEST'].removeprefix('sha256:'),artifact,
        os.environ['CANDIDATE_SHA'],int(os.environ['GITHUB_RUN_ID']),attempt,destination)
    manifest_path=closure_file(destination,'app.json')
    if manifest_path.stat().st_size>4<<20:raise ValueError('final app manifest exceeds metadata bound')
    manifest=json.loads(manifest_path.read_bytes())
    modern=assets.multipart_row(manifest)
    fields=assets.NATIVE_FIELDS if native else assets.DESKTOP_PART_FIELDS if modern else assets.DESKTOP_FIELDS
    if set(manifest)!={'schema',*fields,'binary','source'} or manifest['schema']!=(2 if modern else 1):
        raise ValueError('final app metadata is not the explicit Desktop variant')
    row={key:manifest[key] for key in fields}
    if modern:
        recipe=closure_file(pathlib.Path('.'),'windows/apps/comfyui/backend-amd-v1.json')
        expected['backend_policy']={key:pin(recipe)[key] for key in ('bytes','sha256')}
    commit=selected['openabstractions/adopter-comfyui']
    fixed=dict(id='comfyui',variant='oa-comfyui-native' if native else 'oa-comfyui-desktop',version=version,release_tag='v'+version,
        platform='windows/amd64',source_commit=commit,
        source_url='https://github.com/openabstractions/adopter-comfyui/commit/'+commit,
        publisher='OpenAbstractions',license='GPL-3.0' if native else source_policy['licensing']['expression'])
    if any(row.get(key)!=value for key,value in fixed.items()):
        raise ValueError('final app identity differs from current source-selected producer')
    document=json.loads(pathlib.Path('apps.json').read_bytes())
    # The current source catalogue can be empty. Preserve it; validate the actual
    # produced row under its unchanged source-owned candidate admission capsule.
    document['apps']=[value for value in document['apps'] if value['id']!='comfyui']+[
        {key:value for key,value in row.items() if key!='release_tag'}]
    if modern:document['schema']=2
    rows=assets.roster_text(json.dumps(document))
    produced=assets.stage(rows,'app-inputs','dist',pathlib.Path(os.environ['RUNNER_TEMP'])/'apps.json',
        candidate_source=os.environ['CANDIDATE_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
        outputs={'comfyui':{'artifact':artifact,'source_commit':commit}},
        current_sources={'comfyui':selected},repo=os.environ['GH_REPO'],
        final_intakes={'comfyui':intake},desktop_inputs={'comfyui':expected})
    catalogue,descriptor=assets.panel_pin_input(pathlib.Path('apps.json').read_bytes(),produced,
        expected_apps=assets.panel_app_ids(required),producer=dict(source=os.environ['CANDIDATE_SHA'],
            run_id=int(os.environ['GITHUB_RUN_ID']),run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT'])))
    destination=pathlib.Path(os.environ['RUNNER_TEMP'])/'panel-catalogue'
    destination.mkdir()
    (destination/'panel-catalogue.json').write_bytes(catalogue)
    (destination/'panel-catalogue-input.json').write_bytes(descriptor)
    return produced


def application_panel_inputs(required,version):
    """Create the explicit passive catalogue input for an empty app selection."""
    assets=load_owner('scripts/app_assets.py','application_empty_panel_catalogue')
    expected=assets.panel_app_ids(required)
    if expected:raise ValueError('selected Panel applications require completed delivery intake')
    catalogue,descriptor=assets.panel_pin_input(pathlib.Path('apps.json').read_bytes(),[],
        expected_apps=expected,producer=dict(source=os.environ['CANDIDATE_SHA'],
            run_id=int(os.environ['GITHUB_RUN_ID']),run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT'])))
    destination=pathlib.Path(os.environ['RUNNER_TEMP'])/'panel-catalogue'
    destination.mkdir()
    (destination/'panel-catalogue.json').write_bytes(catalogue)
    (destination/'panel-catalogue-input.json').write_bytes(descriptor)


def received_installer_chain(required, inputs, expected_producers, version, verify, *, packages=None):
    """Join owning receipts after immutable intake, before any chain effects.

    verify is the existing signer receiver with independently admitted source,
    run/attempt, artifact and policy expectations. JSON alone grants no trust.
    """
    inputs, required = pathlib.Path(inputs), set(required)
    if set(expected_producers) != required:
        raise ValueError('required installer producer bindings are missing or foreign')
    actual = {path.parent.name for path in inputs.glob('*/bundle-app.json')}
    if actual - required:
        raise ValueError('foreign installer producer output: ' + ', '.join(sorted(actual - required)))
    rows, errors = [], []
    for app in sorted(required):
        directory = inputs/app
        try:
            receipt = json.loads((directory/'installer-receipt.json').read_text(encoding='utf-8'))
            raw = (directory/'bundle-app.json').read_bytes()
            row = json.loads(raw)
            if not isinstance(row, dict) or not isinstance(receipt, dict):
                raise ValueError('installer receipt and chain row must be objects')
            received_version = receipt.get('plugin', {}).get('version') if app == 'opencode' else receipt.get('version')
            if row.get('id') != app or received_version != version or receipt.get('test_build') or 'QA' in receipt.get('status', ''):
                raise ValueError('installer identity/version/test mode differs')
            if receipt.get('bundle_app_sha256') != hashlib.sha256(raw).hexdigest():
                raise ValueError('installer chain row differs from producer receipt')
            if receipt.get('distribution')=='oa-comfyui-native':
                binding=expected_producers[app]
                if (receipt.get('schema')!=3 or binding.get('delivery',{}).get('variant')!='oa-comfyui-native' or
                        row.get('embedded_integration')!=binding.get('embedded_integration') or
                        receipt.get('embedded_integration')!=binding.get('embedded_integration') or
                        set(row.get('host',{}))!={'file','bytes','sha256'} or 'expected_payload' in receipt):
                    raise ValueError('native archive requires its actual catalog delivery; no installer role')
                continue
            def receive(package):
                path = directory/pathlib.Path(package['file']).name
                if path.is_symlink() or path.is_junction() or not path.is_file():
                    raise ValueError('installer package is missing or linked')
                data = path.read_bytes()
                if package['sha256'] != hashlib.sha256(data).hexdigest() or package['bytes'] != len(data):
                    raise ValueError('installer package differs from producer pin')
                package['file'] = str(path.resolve())
            if 'host' in row and packages is None:
                raise ValueError('hosted installer requires the owning chain package iterator')
            selected = (package for _,_,package,app in packages({'version':version,'core':None,'apps':[row]})
                        if app is not None) if packages else (row,)
            for package in selected:
                receive(package)
            if 'embedded_integration' in row:
                expected=expected_producers[app].get('embedded_integration')
                if (app!='comfyui' or receipt.get('schema')!=3 or expected is None
                        or row['embedded_integration']!=expected or receipt.get('embedded_integration')!=expected
                        or 'expected_payload' in receipt):
                    raise ValueError('installer embedded wrapper differs from admitted source producer')
                rows.append(row)
                continue
            expected = expected_producers[app]['expected_payload']
            if any(row[key] != expected['msi'][key] for key in ('sha256','bytes')):
                raise ValueError('installer container differs from admitted producer payload')
            declared = (receipt.get('compiled_readback', {}).get('expected_payload')
                        if app == 'opencode' else receipt.get('expected_payload'))
            if (not isinstance(declared, dict) or
                    any(declared.get(key) != expected.get(key) for key in ('schema','files','binaries')) or
                    not isinstance(declared.get('msi'),dict) or
                    dict(declared['msi'],name=pathlib.PurePosixPath(declared['msi'].get('name','')).name) !=
                    dict(expected['msi'],name=pathlib.PurePosixPath(expected['msi']['name']).name)):
                raise ValueError('installer File/Binary inventory differs from admitted producer')
            if declared.get('icons',[]) != expected.get('icons',[]):
                raise ValueError('installer Icon inventory differs from admitted producer')
            if declared.get('registration') != expected.get('registration'):
                raise ValueError('installer checked registration differs from admitted producer')
            rows.append(row)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            errors.append(app + ': ' + str(error))
    if errors:
        raise ValueError('required installer intake: ' + '; '.join(errors))
    chain = {'version':version, 'apps':rows}
    verify(chain, expected_producers)
    return chain


def retain_installer_chain(chain, out, *, packages=None):
    """Retain every existing chain role, including official host/preflight."""
    out = pathlib.Path(out)
    out.mkdir(parents=True,exist_ok=True)
    for row in chain['apps']:
        directory = out/'apps'/row['id']
        directory.mkdir(parents=True, exist_ok=True)
        source_directory = pathlib.Path(row['host']['file'] if 'embedded_integration' in row else row['file']).parent
        for sidecar in ('installer-receipt.json', 'bundle-app.json'):
            shutil.copyfile(source_directory/sidecar, directory/sidecar)
        if 'host' in row and packages is None:
            raise ValueError('hosted installer requires the owning chain package iterator')
        selected = (package for _,_,package,app in packages(dict(chain,core=None,apps=[row]))
                    if app is not None) if packages else (row,)
        for package in selected:
            source = pathlib.Path(package['file'])
            destination = directory/source.name
            shutil.copyfile(source,destination)
            package['file'] = destination.relative_to(out).as_posix()
    (out/'chain.json').write_text(json.dumps(chain,indent=2)+'\n',encoding='utf-8')
def pin(path):
    digest=hashlib.sha256();size=0
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''):
            digest.update(block);size+=len(block)
    return {'file': str(path.resolve()), 'sha256':digest.hexdigest(),'bytes':size}
def legacy_main():
    version = os.environ['CANDIDATE_VERSION']
    release = pathlib.Path('verified-release')
    out = pathlib.Path('setup')
    out.mkdir()
    apps = []
    for row in json.loads(pathlib.Path('apps.json').read_text(encoding='utf-8'))['apps']:
        archive = release / row['binary_zip']
        if not archive.is_file():
            raise SystemExit('FAIL  the verified release lacks ' + row['binary_zip'])
        manifest = pathlib.Path('windows/apps') / row['id'] / 'application-manifest.json'
        text = manifest.read_text(encoding='utf-8')
        names = sorted(set(re.findall(r'@([a-z][a-z0-9_]{0,63})@', text)))
        title = json.loads(re.sub(r'@[a-z][a-z0-9_]{0,63}@', '', text))['title']
        built = out / 'apps' / row['id']
        subprocess.run([sys.executable, 'windows/apps/build_app.py', '--app-id', row['id'],
                        '--title', title, '--publisher', 'OpenAbstractions', '--version', version,
                        '--zip', str(archive), '--zip-sha256', row['binary_sha256'],
                        '--zip-bytes', str(row['binary_bytes']), '--manifest', str(manifest),
                        '--out', str(built),
                        *[x for name in names for x in ('--define', f'{name}={row[name]}')]], check=True)
        apps.append(dict(id=row['id'], title=title, **pin(built / f"{row['id']}-{version}.msi")))
    chain = {'version': version, 'apps': apps}
    (out / 'chain.json').write_text(json.dumps(chain, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(chain, indent=2))


def main(argv=None):
    parser=argparse.ArgumentParser(description='Existing application producer and immutable installer intake owner')
    parser.add_argument('--phase',choices=('backend-inputs','control-inputs','inputs','prepare-native','sign-native','prepare-helpers','sign-helpers','package','sign-host','bind','seal-native','assemble-final','stage-final','panel-inputs','bundle'),default='package')
    args=parser.parse_args(argv)
    version=os.environ['CANDIDATE_VERSION'].removeprefix('v')
    if tuple(map(int,version.split('-')[0].split('.')))<(0,8,0):
        if args.phase=='bundle':return application_bundle(set(),version)
        if args.phase!='package':raise ValueError('historical producer supports its existing package route only')
        return legacy_main()
    required=installer_scope(version)
    if args.phase=='bundle':return application_bundle(required,version)
    if args.phase=='assemble-final':return application_final_capsule(required,version)
    if args.phase=='stage-final':return application_stage_final(required,version)
    if args.phase=='panel-inputs':return application_panel_inputs(required,version)
    if not required:
        if args.phase=='package':
            retain_installer_chain({'version':version,'apps':[]},'setup')
            pathlib.Path('setup/producer-bindings.json').write_text('{}\n')
        return
    operations={'backend-inputs':application_backend_inputs,'control-inputs':application_control_inputs,'inputs':application_inputs,'prepare-native':application_native_prepare,
                'sign-native':application_native_sign,'prepare-helpers':application_helpers_prepare,
                'sign-helpers':application_helpers_sign,
                'package':application_package,'sign-host':application_sign_host,'bind':application_bind}
    if args.phase=='seal-native':return seal_external_app_proofs(required,version)
    return operations[args.phase](required,version)


if __name__ == '__main__':
    main()
