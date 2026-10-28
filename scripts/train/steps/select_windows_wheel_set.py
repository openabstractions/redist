import json, os, pathlib, subprocess, sys
selected = json.loads(subprocess.check_output([
    sys.executable, 'scripts/app_producer_inputs.py', 'select-wheels', '--app', 'comfyui',
    '--candidate-source', os.environ['CANDIDATE_SHA'], '--run-id', os.environ['GITHUB_RUN_ID']]))
with pathlib.Path(os.environ['GITHUB_ENV']).open('a', encoding='utf-8') as output:
    output.write('WHEEL_ARTIFACT=' + selected['artifact'] + '\n')
    output.write('WHEEL_ATTEMPT=' + str(selected['run_attempt']) + '\n')
