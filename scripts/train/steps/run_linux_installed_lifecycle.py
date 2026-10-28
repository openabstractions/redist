import json, pathlib
p = pathlib.Path('pkg/package-verification.json')
evidence = json.loads(p.read_text())
evidence['installed_lifecycle'] = 'passed_disposable_user_systemd'
p.write_text(json.dumps(evidence, indent=2))
