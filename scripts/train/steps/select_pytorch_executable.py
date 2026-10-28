import os, pathlib, sys
sys.path.insert(0, 'scripts')
from release_tsv_rows import rows
selected = [row for row in rows(pathlib.Path('tools.tsv').read_text(), 'tools.tsv')
            if row[0] == 'pytorchd.exe']
if selected and (not selected[0][1].startswith('github.com/openabstractions/abstraction-provider-pytorch/go@')
                 or selected[0][2:] != ('cmd/pytorchd', 'pytorchimage', 'console')):
    raise ValueError('PyTorch executable has an unexpected owning module or feature')
with pathlib.Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
    output.write(f'enabled={str(bool(selected)).lower()}\n')
