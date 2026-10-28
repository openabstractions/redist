import json, os, pathlib, sys
sys.path.insert(0, 'scripts')
from app_assets import windows_wheel_receipt
receipt = windows_wheel_receipt(
    'pypi.tsv', 'pypi', 'sources', os.environ['CANDIDATE_SHA'],
    int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT']),
    os.environ['CANDIDATE_VERSION'], os.environ['IPC_LIBRARY'],
    facade_native_library=os.environ.get('FACADE_APPMODEL_LIBRARY'))
pathlib.Path('pypi/wheel-inputs.json').write_text(
    json.dumps(receipt, sort_keys=True) + '\n', encoding='utf-8')
