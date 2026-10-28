import json, os, pathlib, subprocess, sys
sys.path.insert(0, 'scripts')
from app_assets import roster, select_producers
outputs = {
    app: {'artifact': os.environ[app.upper() + '_ARTIFACT'],
          'source_commit': os.environ[app.upper() + '_SOURCE_COMMIT']}
    for app in ('comfyui',)}
for app, artifact in select_producers(roster('apps.json'), outputs):
    destination = pathlib.Path('app-inputs') / app
    destination.mkdir()
    subprocess.run(['gh', 'run', 'download', os.environ['GITHUB_RUN_ID'],
                    '-n', artifact, '-D', str(destination)], check=True)
    if (destination / 'backend-producer.json').exists():
        raise ValueError('backend intermediate is not a final signed Desktop app/source pair')
pathlib.Path('app-producer-outputs.json').write_text(json.dumps(outputs, sort_keys=True) + '\n',
                                                      encoding='utf-8')
