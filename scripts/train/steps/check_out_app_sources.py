import os, subprocess, sys
extra = ['--producer-only'] if os.environ['APP_PRODUCER_ONLY'] == 'comfyui' else []
if extra:
    extra += ['--adopter-commit', os.environ['COMFYUI_PRODUCER_ADOPTER_COMMIT']]
for operation in ('pins', 'checkout'):
    subprocess.run([sys.executable, 'scripts/app_producer_inputs.py', operation,
                    '--app', 'comfyui', *extra], check=True)
