import json, os, pathlib, subprocess, sys
sys.path.insert(0, 'scripts')
sys.path.insert(0, 'windows')
from app_assets import select_windows_wheel_artifact
from windows_signing import consume_artifact
repository = os.environ['GITHUB_REPOSITORY']
run = int(os.environ['GITHUB_RUN_ID'])
def pages(path, key):
    result = json.loads(subprocess.check_output(['gh', 'api', '--paginate', '--slurp', path]))
    return [item for page in result for item in page[key]]
jobs = pages(f'repos/{repository}/actions/runs/{run}/jobs?filter=all&per_page=100', 'jobs')
artifacts = pages(f'repos/{repository}/actions/runs/{run}/artifacts?per_page=100', 'artifacts')
selected = select_windows_wheel_artifact(jobs, artifacts, run, os.environ['GITHUB_SHA'])
attempt = int(selected['name'].rsplit('-', 1)[1])
consume_artifact(selected['id'], selected['digest'].removeprefix('sha256:'), selected['name'],
                 os.environ['GITHUB_SHA'], run, attempt, pathlib.Path('ipc_wheels') / selected['name'])
pathlib.Path('ipc-wheel-selection.txt').write_text(selected['name'])
