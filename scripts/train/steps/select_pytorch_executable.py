import os, pathlib, sys
sys.path.insert(0, 'scripts')
from release_tsv_rows import rows, platform_tools
selected = [row for row in platform_tools(rows(pathlib.Path('tools.tsv').read_text(), 'tools.tsv'), 'windows', 'amd64')
            if row[0] == 'pytorchd.exe']
with pathlib.Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
    output.write(f'enabled={str(bool(selected)).lower()}\n')
