import argparse, os, pathlib, subprocess, sys
sys.path.insert(0, 'scripts')
from app_assets import python_package_pins
from py_wheels import NATIVE_FAMILIES, check
parser = argparse.ArgumentParser()
parser.add_argument('--version', help='explicit train version; omitted preserves legacy wheel assembly')
args = parser.parse_args()
version_args = [] if args.version is None else ['--version', args.version]
pins = python_package_pins('pypi.tsv')
for pin in pins[1:]:
    repo = pin['repository'].split('/', 1)[1]
    root = pathlib.Path('sources') / repo
    if pin['package'] in NATIVE_FAMILIES:
        if pin['package'] != 'abstraction-facade-native' or args.version is None:
            raise SystemExit('native companion requires an explicit candidate version')
        library = os.environ.get('FACADE_APPMODEL_LIBRARY')
        platform = os.environ.get('PLATFORM')
        if not library or not platform:
            raise SystemExit('native companion lacks its selected producer library/platform')
        subprocess.run([sys.executable, 'scripts/py_wheels.py', '--family', pin['package'],
            '--version', args.version, '--platform', platform, '--library', library,
            '--package', str(root / pin['directory']), '--license', str(root / 'LICENSE'),
            '--output', 'pypi'], check=True)
        continue
    subprocess.run([sys.executable, 'scripts/py_pure_wheels.py',
                    '--source', str(root / pin['directory']),
                    '--license', str(root / 'LICENSE'), '--output', 'pypi', *version_args], check=True)
built = sorted(pathlib.Path('pypi').glob('*.whl'))
if len(built) != len(pins):
    raise SystemExit('Python wheel set differs from pypi.tsv')
for wheel in built:
    if any(wheel.name.startswith(family['wheel'] + '-') for family in NATIVE_FAMILIES.values()):
        if args.version is not None:
            version, _, _ = check(wheel)
            if version != args.version:
                raise SystemExit('native Python wheel differs from train version')
        continue
    subprocess.run([sys.executable, 'scripts/py_pure_wheels.py', '--check', str(wheel), *version_args], check=True)
