"""Stage the core MSI's Go notices from its authenticated public graph."""
import argparse
import hashlib
import io
from pathlib import Path
import re
import stat
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from file_boundary import ordinary_path
import module_provenance

# The licence names and rendering contract of scripts/third_party_notices.py.
LICENCES = {
    "github.com/google/jsonschema-go": "MIT",
    "github.com/modelcontextprotocol/go-sdk": "Apache-2.0 and MIT (the project's licensing transition; see the text)",
    "github.com/segmentio/asm": "MIT",
    "github.com/segmentio/encoding": "MIT",
    "github.com/yosida95/uritemplate/v3": "BSD-3-Clause",
    "golang.org/x/oauth2": "BSD-3-Clause",
    "golang.org/x/sync": "BSD-3-Clause",
    "golang.org/x/sys": "BSD-3-Clause",
    "golang.org/x/time": "BSD-3-Clause",
}
LICENCE_FILES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "NOTICE", "PATENTS")
HEAD = """# Third-party notices

OpenAbstractions programs compile in the Go modules below. Each module's
licence text follows its name. scripts/third_party_notices.py writes this
file from the module graph; the installer's licence page carries it.
"""


def stage(graph_path=Path('public-go-graph.json'), archive_path=Path('public-go-graph.zip'),
          output=Path('THIRD_PARTY_NOTICES.md'), *, expected_sha256=None):
    import json
    if expected_sha256 is not None and not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('invalid expected third-party notice digest')
    graph = json.loads(ordinary_path(graph_path, kind='file').read_bytes())
    archive = ordinary_path(archive_path, kind='file').read_bytes()
    module_provenance.unpack_staged_graph(archive, None, graph)
    rows = sorted((row for row in graph.get('dependencies', [])
                   if not row['module'].startswith(module_provenance.ORG)), key=lambda row: (row['module'], row['version']))
    if not rows:
        raise ValueError('core third-party notice graph is empty')
    parts = [HEAD]
    with zipfile.ZipFile(io.BytesIO(archive)) as capsule:
        for row in rows:
            module, version = row['module'], row['version']
            if module not in LICENCES:
                raise ValueError('read and name the third-party licence: ' + module)
            parts.append(f"\n## {module} {version}\n\nLicence: {LICENCES[module]}\n")
            texts = []
            name = 'proxy/' + module_provenance.escape_module(module) + '/@v/' + version + '.zip'
            with zipfile.ZipFile(io.BytesIO(capsule.read(name))) as content:
                for filename in LICENCE_FILES:
                    member = module + '@' + version + '/' + filename
                    entries = [entry for entry in content.infolist() if entry.filename == member]
                    if not entries:
                        continue
                    if (len(entries) != 1 or entries[0].orig_filename != member or entries[0].is_dir()
                            or stat.S_ISLNK(entries[0].external_attr >> 16) or entries[0].file_size > 1 << 20):
                        raise ValueError('third-party licence is not one plain bounded file: ' + member)
                    text = content.read(entries[0]).decode('utf-8').replace('\r\n', '\n').replace('\r', '\n').strip()
                    texts.append((filename, text))
            if not texts:
                raise ValueError('third-party module has no licence text: ' + module)
            for filename, text in texts:
                parts.append(f"\n{filename}:\n\n```text\n{text}\n```\n")
    raw = ''.join(parts).encode('utf-8')
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError('third-party notice differs from the reviewed release digest')
    output = ordinary_path(output, kind='file', allow_missing=True)
    with output.open('xb') as destination:
        destination.write(raw)
    return dict(bytes=len(raw), sha256=digest)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args(argv)
    result = stage(expected_sha256=args.expected_sha256)
    print('staged THIRD_PARTY_NOTICES.md: {bytes} bytes, SHA256 {sha256}'.format(**result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
