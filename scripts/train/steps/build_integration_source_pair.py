import json, os, pathlib, subprocess, sys
sys.path.insert(0, 'scripts')
from app_assets import optional_app_sources, roster, app_output_names
from git_env import source_git_environment
first = os.environ['APP_PRODUCER_ONLY'] == 'comfyui'
if first:
    row = app_output_names('comfyui')
    source_pin = os.environ['COMFYUI_PRODUCER_ADOPTER_COMMIT']
else:
    document = json.loads(pathlib.Path('apps.json').read_text(encoding='utf-8'))
    required = document.get('release_admission', {}).get('outcomes', {}).get('adopters', [])
    if any(item.get('id') == 'comfyui' and item.get('target') == 'windows-x64' for item in required):
        from app_producer_inputs import installer_source_pins
        selected = installer_source_pins('comfyui', 'npm.tsv', 'pypi.tsv', 'app-sources.tsv',
            'apps.json', os.environ['CANDIDATE_VERSION'], producer_source=os.environ['CANDIDATE_SHA'])
        source_pin = selected['openabstractions/adopter-comfyui']
        row = app_output_names('comfyui')
    else:
        row = next(row for row in roster('apps.json') if row['id'] == 'comfyui')
        source_pin = optional_app_sources('app-sources.tsv', [row])['comfyui']['commit']
root = pathlib.Path('sources/abstractions')
inputs = pathlib.Path('app-build-inputs')
output = pathlib.Path('app-output')
output.mkdir()
charter = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True,
                                  env=source_git_environment()).strip()
wheels = inputs / 'wheels'
receipt = wheels / 'wheel-inputs.json'
integration = inputs / 'integration.zip'
sidecar = inputs / 'integration-producer.json'
common = ['--redist-source-root', '.', '--redist-source-commit', os.environ['CANDIDATE_SHA'],
          '--redist-version', os.environ['CANDIDATE_VERSION'],
          '--run-id', os.environ['GITHUB_RUN_ID'],
          '--run-attempt', os.environ['WHEEL_ATTEMPT']]
subprocess.run([sys.executable, str(root / 'scripts/package_comfyui_integration.py'),
                '--source-mode', 'public-split', '--wheel-receipt', str(receipt),
                '--wheel-dir', str(wheels), '--public-source-root', 'sources',
                '--adopter-source-root', 'sources/adopter-comfyui',
                '--adopter-commit', source_pin, '--packager-source-commit', charter,
                '--producer-receipt-output', str(sidecar), '--output', str(integration),
                '--native-wheel-version', os.environ['CANDIDATE_VERSION'],
                '--version', os.environ['CANDIDATE_VERSION'] + '-candidate', *common], check=True)
integration_info = json.loads(sidecar.read_text(encoding='utf-8'))['integration']
desktop = json.loads((inputs / 'desktop-host.json').read_text(encoding='utf-8'))
if desktop.get('schema') == 2:
    # Expected input pins precede the build. The variable output receipt is later
    # authenticated by the existing successful Windows artifact intake.
    backend = desktop['build_inputs']['backend']
    descriptor = inputs / 'backend-inputs.json'
    import hashlib
    if (set(backend) != {'bytes', 'sha256'} or descriptor.stat().st_size != backend['bytes']
            or hashlib.sha256(descriptor.read_bytes()).hexdigest() != backend['sha256']):
        raise ValueError('backend descriptor differs from immutable Desktop input')
    mode = ['--backend-inputs', str(descriptor), '--backend-inputs-sha256', backend['sha256'],
            '--backend-receipt-output', str(output / 'backend-producer.json')]
    from app_producer_inputs import comfy_archive_tool, imported
    package = imported(root / 'scripts/package_comfyui_app.py')
    tool = comfy_archive_tool(inputs, package)
    mode += ['--backend-archive-tool', str(tool)]
    binary_output, source_output = output / 'backend.7z', output / 'backend-source.zip'
else:
    mode = ['--archive', str(inputs / 'ComfyUI_windows_portable_amd.7z'),
            '--frontend-checkout', str(inputs / 'upstream/ComfyUI_frontend'),
            '--embedded-docs-checkout', str(inputs / 'upstream/embedded-docs'),
            '--pygit2-checkout', str(inputs / 'upstream/pygit2'),
            '--libgit2-checkout', str(inputs / 'upstream/libgit2'),
            '--cpu-wheelhouse', str(inputs / 'cpu-wheels')]
    binary_output, source_output = output / row['binary_zip'], output / row['source_zip']
subprocess.run([sys.executable, str(root / 'scripts/package_comfyui_app.py'),
                *mode,
                '--output', str(binary_output),
                '--source-output', str(source_output),
                '--integration-archive', str(integration),
                '--integration-public-source-root', 'sources',
                '--integration-producer-receipt', str(sidecar),
                '--integration-wheel-receipt', str(receipt),
                '--integration-redist-source-commit', os.environ['CANDIDATE_SHA'],
                '--integration-run-id', os.environ['GITHUB_RUN_ID'],
                '--integration-run-attempt', os.environ['WHEEL_ATTEMPT'],
                '--integration-bytes', str(integration_info['bytes']),
                '--integration-sha256', integration_info['sha256'],
                '--minimum-free-gib', '20' if desktop.get('schema')==2 else '1'], check=True)
