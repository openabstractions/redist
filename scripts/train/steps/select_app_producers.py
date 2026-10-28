"""Select source-declared installer obligations alongside legacy archives."""
import json
import os
import pathlib
import sys


def required_products(document, version, validate):
    """The source-owned PLAN projection survives an empty archive catalog."""
    if tuple(map(int, version.removeprefix('v').split('-')[0].split('.'))) < (0, 8, 0):
        return ()
    capsule = document.get('release_admission')
    validate(capsule, version.removeprefix('v'), document['apps'], require_delivery=False)
    return tuple(sorted(row['id'] for row in capsule['outcomes']['adopters']
                        if row['target'] == 'windows-x64'))


def main():
    sys.path.insert(0, 'scripts')
    from app_assets import optional_app_sources, roster, predecessor_pins
    from release_facts import validate_public_admission
    document = json.loads(pathlib.Path('apps.json').read_text(encoding='utf-8'))
    required = required_products(document, os.environ['RELEASE_VERSION'], validate_public_admission)
    rows = roster('apps.json')
    optional_app_sources('app-sources.tsv', rows)
    archives = {row['id'] for row in rows}
    selected = archives | set(required)
    predecessors = predecessor_pins(os.environ['APP_PRODUCERS'])
    mode = os.environ['APP_PRODUCER_ONLY']
    if mode not in ('none', 'comfyui'):
        raise SystemExit('unknown app producer-only mode')
    if mode != 'none':
        if selected or predecessors:
            raise SystemExit('producer-only requires no required products, empty Setup catalog and no predecessor selection')
        selected = {mode}
        archives = {mode}
    elif not set(predecessors) <= {row['id'] for row in rows}:
        raise SystemExit('app predecessor is not declared by current archive catalog')
    supported = {'comfyui', 'opencode', 'lemonade'}
    if not selected <= supported:
        raise SystemExit('no installer producer for required products: ' + ', '.join(sorted(selected - supported)))
    with pathlib.Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
        output.write('required-products=' + json.dumps(required, separators=(',', ':')) + '\n')
        for app in sorted(supported):
            # The existing Comfy flag remains the legacy archive producer's
            # input. Installer obligations get their own receiving output.
            output.write(f'{app}={str(app in (archives if app == "comfyui" else selected)).lower()}\n')
            output.write(f'installer-{app}={str(app in required).lower()}\n')
            output.write(f'{app}-predecessor={str(app in predecessors).lower()}\n')


if __name__ == '__main__':
    main()
