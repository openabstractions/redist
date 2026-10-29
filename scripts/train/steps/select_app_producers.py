"""Select source-declared installer obligations alongside legacy archives."""
import json
import os
import pathlib
import re
import sys


def required_products(document, version, validate):
    """The source-owned PLAN projection survives an empty archive catalog."""
    if tuple(map(int, version.removeprefix('v').split('-')[0].split('.'))) < (0, 8, 0):
        return ()
    capsule = document.get('release_admission')
    validate(capsule, version.removeprefix('v'), document['apps'], require_delivery=False)
    return tuple(sorted(row['id'] for row in capsule['outcomes']['adopters']
                        if row['target'] == 'windows-x64'))


def delivery_products(required, component='none', *, first='none', mode='', probe=False, diagnostic=False):
    """Select a final delivery without changing its accepted source obligation."""
    if component not in ('none', 'comfyui'):
        raise ValueError('unknown final application component')
    if component == 'none':
        return tuple(required)
    if first != 'none' or mode != 'train' or probe or diagnostic:
        raise ValueError('final Comfy delivery requires train mode without first-producer or diagnostic modes')
    if 'comfyui' not in required:
        raise ValueError('final Comfy delivery requires its accepted installer obligation')
    return ('comfyui',)


def delivery_context(environment):
    """Refuse missing hosted context before component acquisition or signing.

    These fields select the existing API receiver; they do not authenticate a
    producer. The normal final intake still checks the live jobs and artifacts.
    """
    if (environment.get('GITHUB_ACTIONS') != 'true' or
            not re.fullmatch('[0-9a-f]{40}', environment.get('CANDIDATE_SHA', '')) or
            environment.get('GITHUB_SHA') != environment.get('CANDIDATE_SHA') or
            environment.get('GITHUB_REPOSITORY') != 'openabstractions/redist' or
            environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or
            any(not re.fullmatch('[1-9][0-9]*', environment.get(key, ''))
                for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))):
        raise ValueError('final Comfy delivery requires exact hosted source/run/attempt context')


def main():
    sys.path.insert(0, 'scripts')
    from app_assets import optional_app_sources, roster, predecessor_pins
    from release_facts import validate_public_admission
    document = json.loads(pathlib.Path('apps.json').read_text(encoding='utf-8'))
    required = required_products(document, os.environ['RELEASE_VERSION'], validate_public_admission)
    rows = roster('apps.json')
    optional_app_sources('app-sources.tsv', rows, required_products=required)
    component = os.environ.get('APP_DELIVERY_ONLY', 'none')
    required = delivery_products(required, component, first=os.environ['APP_PRODUCER_ONLY'],
        mode=os.environ.get('PRODUCER_MODE', ''), probe=os.environ.get('SIGNING_PROBE_ONLY') == 'true',
        diagnostic=os.environ.get('DIAGNOSTIC_HOST_SIGN_ONLY') == 'true')
    if component != 'none':
        delivery_context(os.environ)
    archives = {row['id'] for row in rows}
    selected = archives | set(required)
    predecessors = predecessor_pins(os.environ['APP_PRODUCERS'])
    if component == 'comfyui':
        # Source policy still owns the complete capsule; this execution has a
        # single explicit effect roster and cannot build another application.
        archives &= {'comfyui'}
        selected = archives | set(required)
        predecessors = {key: value for key, value in predecessors.items() if key == 'comfyui'}
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
