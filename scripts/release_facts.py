"""Offline release-fact derivation and pre-publication admission.

The record contains allowlisted producer observations, never editable conclusions.
Missing observations stay pending. Reports are values in the existing stage/Job.
"""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess

SCHEMA = 1
SURFACES = ('README.md', 'RELEASE-CHECKLIST.md', 'PROGRESS.md',
    'openabstractions-flat/openabstractions.github.io/index.html',
    'openabstractions-flat/openabstractions.github.io/adopt.html',
    'openabstractions-flat/openabstractions.github.io/evidence.html',
    'openabstractions-flat/openabstractions.github.io/catalogue.html',
    'openabstractions-flat/openabstractions.github.io/adopters.html',
    'openabstractions-flat/openabstractions.github.io/cases.html',
    'openabstractions-flat/openabstractions.github.io/ai-apps.html',
    'openabstractions-flat/openabstractions.github.io/coverage.html',
    'research/org-edits/.github/CATALOGUE.md', 'docs/platforms.json',
    'research/org-edits/redist/README.md', 'research/org-edits/redist/NOTES.md')
SHA = re.compile(r'[0-9a-f]{64}\Z')
SOURCE = re.compile(r'[0-9a-f]{40}\Z')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\Z')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True).encode()).hexdigest()


def pointer(value, path):
    for part in path.lstrip('/').split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


# The projection's paths are JSON pointers into the original owner receipt.
# Projection creation checks these values against the original hashed bytes.
POINTERS = {
    'public': ('/id', '/tag_name', '/html_url', '/target_commitish', '/draft',
               '/published_at', '/assets'),
    'producer': ('/data/source_sha', '/data/version', '/data/metadata',
                 '/data/packages', '/data/macos', '/data/setup', '/data/release_assets',
                 '/data/release_body', '/data/unsigned_platforms', '/data/download_url', '/data/final_signed_msis'),
    'installed': ('/data/source_sha', '/data/version', '/data/operation', '/data/native'),
    'setup': ('/bundle', '/signatures', '/chain', '/policy_sha256'),
}


def public_msi_members(rows):
    """Retain only closed, logical MSI table observations in public facts."""
    if not isinstance(rows, list) or not rows or len(rows) > 100000:
        raise ValueError('invalid MSI observations')
    keys, paths = set(), set()
    for row in rows:
        if not isinstance(row, dict) or row.get('table') not in ('File', 'Binary', 'Icon'):
            raise ValueError('invalid MSI table observation')
        if (set(row) != {'table', 'id', 'bytes', 'sha256'} | ({'path'} if row['table'] == 'File' else set())
                or not isinstance(row['id'], str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,255}', row['id'])
                or type(row['bytes']) is not int or row['bytes'] < 0
                or not isinstance(row['sha256'], str) or not SHA.fullmatch(row['sha256'])
                or (row['table'], row['id'].casefold()) in keys):
            raise ValueError('invalid MSI observation fields')
        keys.add((row['table'], row['id'].casefold()))
        if row['table'] == 'File':
            path = row['path']
            if (not isinstance(path, str) or not path or len(path) > 32767
                    or any(c in path for c in '\\:\0*?"<>|')
                    or any(ord(c) < 32 or ord(c) == 127 for c in path)
                    or any(not part or part in ('.', '..') or part.rstrip(' .') != part for part in path.split('/'))
                    or path.casefold() in paths):
                raise ValueError('invalid logical MSI installed path')
            paths.add(path.casefold())
    if rows != sorted(rows, key=lambda row: (row['table'], row['id'])):
        raise ValueError('MSI observations are not canonical')
    return json.loads(json.dumps(rows))


def safe_value(value):
    """Remove private paths, commands and account/environment data recursively."""
    if isinstance(value, list):
        return [safe_value(row) for row in value]
    if isinstance(value, dict):
        allowed = {'id', 'name', 'size', 'digest', 'browser_download_url', 'arch',
            'artifact', 'bytes', 'sha256', 'signed', 'schema', 'source', 'version',
            'kind', 'run_id', 'run_attempt', 'preview', 'macos', 'windows_signing',
            'files', 'result', 'exit_code', 'file_digest', 'timestamp',
            'timestamp_digest', 'verification', 'new_signature', 'certificate',
            'chain', 'subject', 'issuer', 'sha1', 'policy_sha256', 'native64',
            'architecture', 'platform', 'executed', 'manual', 'status', 'core', 'signatures',
            'engine', 'bundle', 'signature', 'final_signed_msis', 'staged_sha256', 'producer_source'}
        result = {key: safe_value(item) for key, item in value.items() if key in allowed}
        if 'msi_members' in value:
            if not isinstance(value.get('name'), str) or not value['name'].endswith('.msi'):
                raise ValueError('MSI observations require an MSI file proof')
            result['msi_members'] = public_msi_members(value['msi_members'])
        return result
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    raise ValueError('unsupported producer value')


def project(raw, role, evidence_url):
    """Project one actual receipt; no network, subprocess or inferred facts."""
    if role not in POINTERS:
        raise ValueError('unknown release receipt role')
    value = json.loads(raw)
    values = {}
    for path in POINTERS[role]:
        try:
            values[path] = safe_value(pointer(value, path))
        except (KeyError, IndexError, TypeError):
            pass  # This exact missing producer field will derive pending.
    if not evidence_url.startswith('https://github.com/openabstractions/'):
        raise ValueError('release evidence needs an existing public source/run URL')
    return {'role': role, 'raw_sha256': hashlib.sha256(raw).hexdigest(),
            'evidence_url': evidence_url, 'values': values, 'projection_sha256': digest(values)}


def derive(record):
    if record.get('schema') != SCHEMA or record.get('context') not in ('published', 'candidate', 'intended'):
        raise ValueError('unsupported release evidence record')
    observations = record.get('observations')
    if not isinstance(observations, list):
        raise ValueError('release evidence observations are required')
    groups = {'public': [], 'producer': [], 'installed': [], 'setup': []}
    evidence = []
    for row in observations:
        if row.get('role') not in groups or not SHA.fullmatch(str(row.get('raw_sha256', ''))):
            raise ValueError('unbound release observation')
        if row.get('projection_sha256') != digest(row.get('values')):
            raise ValueError('release observation projection changed')
        if not set(row['values']) <= set(POINTERS[row['role']]):
            raise ValueError('observation contains fields outside its owner')
        groups[row['role']].append(row['values'])
        evidence.append(row['evidence_url'])
    if len(groups['public']) > 1 or len(groups['producer']) > 1:
        raise ValueError('ambiguous release producer or public readback')
    public = next(iter(groups['public']), {})
    producer = next(iter(groups['producer']), {})
    metadata = producer.get('/data/metadata', {})
    version = producer.get('/data/version')
    source = producer.get('/data/source_sha')
    if version is not None and not VERSION.fullmatch(str(version)):
        raise ValueError('invalid producer release version')
    if source is not None and not SOURCE.fullmatch(str(source)):
        raise ValueError('invalid producer source')
    if metadata and str(metadata.get('version', '')).removeprefix('v') != version:
        raise ValueError('candidate metadata version differs')
    url = None
    declared_url = producer.get('/data/download_url')
    if declared_url is not None:
        if declared_url != 'https://github.com/openabstractions/redist/releases/tag/v' + str(version):
            raise ValueError('producer download URL differs from release version')
        url = declared_url
    if public:
        if public.get('/draft') is not False or public.get('/tag_name') != 'v' + str(version):
            raise ValueError('public release version/draft differs from producer')
        if public.get('/target_commitish') != metadata.get('source'):
            raise ValueError('public commit differs from prepared producer')
        url = public.get('/html_url')
        if url != 'https://github.com/openabstractions/redist/releases/tag/v' + str(version):
            raise ValueError('public download URL differs from release version')
    assets = {}
    packages = producer.get('/data/packages', [])
    signing = metadata.get('windows_signing', {})
    verified = signing.get('files', []) if signing.get('result') == 'pass' else []
    setup_signing = producer.get('/data/setup', {}).get('signatures', {})
    if setup_signing.get('result') == 'pass':
        verified = [*verified, *setup_signing.get('files', [])]
    for setup in groups['setup']:
        bundle = setup.get('/bundle', {})
        signatures = setup.get('/signatures', {})
        final = signatures.get('bundle', {})
        if (bundle.get('signed') is not True or bundle.get('sha256') != final.get('sha256') or
                bundle.get('bytes') != final.get('bytes')):
            raise ValueError('Setup proof differs from final bundle identity')
        # Its existing unpack_setup owner has independently verified this exact
        # receipt against signed final bytes. Asset equality below binds it here.
        verified = [*verified, *signatures.values(),
                    *(entry.get('signature', {}) for entry in setup.get('/chain', []))]
    legacy_signatures = producer.get('/data/release_body', '').split('## Signatures\n', 1)
    legacy_signatures = legacy_signatures[1].split('\n## ', 1)[0] if len(legacy_signatures) == 2 else ''
    for row in producer.get('/data/release_assets', []):
        name, artifact = row.get('name'), row.get('artifact', {})
        if (not name or not SHA.fullmatch(str(artifact.get('sha256', ''))) or
                type(artifact.get('bytes')) is not int or artifact['bytes'] <= 0):
            raise ValueError('invalid producer asset identity')
        platform = ('windows' if name.endswith(('.msi', '.exe')) else
                    'macos' if name.endswith('.pkg') else 'linux' if '-linux-' in name else None)
        state = 'pending'
        if platform == 'windows' and any(item.get('sha256') == artifact['sha256'] and
                item.get('bytes') == artifact.get('bytes') and item.get('verification') and
                item.get('file_digest') == 'SHA256' and item.get('timestamp') == 'RFC3161'
                for item in verified):
            state = 'signed'
        if (platform == 'macos' and producer.get('/data/macos', {}).get('signed') is True and
                metadata.get('macos') == 'signed' and
                producer.get('/data/macos', {}).get('artifact') == artifact):
            state = 'signed'
        # The legacy completed producer explicitly declared Linux's lack of a
        # signature scheme. This is an observed declaration, never an asset default.
        if platform == 'linux' and ('linux' in producer.get('/data/unsigned_platforms', []) or re.search(r'\*\*Linux\*\*[^\n]*the tarballs are \*\*not signed\*\*', legacy_signatures)):
            state = 'unsigned'
        # Setup requires its own cryptographic producer observation; absence is pending.
        matches = [a for a in public.get('/assets', []) if a.get('name') == name]
        if public and (len(matches) != 1 or matches[0].get('digest') != 'sha256:' + artifact['sha256'] or
                       matches[0].get('size') != artifact.get('bytes')):
            raise ValueError('public asset differs from producer: ' + name)
        assets[name] = {'platform': platform, 'sha256': artifact['sha256'],
                        'bytes': artifact.get('bytes'), 'signing': state}
    installed = {p: [] for p in ('windows', 'linux', 'macos')}
    for row in groups['installed']:
        if row.get('/data/source_sha') != source or row.get('/data/version') != version:
            raise ValueError('installed evidence source/version differs')
        native = row.get('/data/native', {})
        if native.get('result') != 'pass' or native.get('exit_code') != 0 or native.get('executed') is False:
            continue
        artifact = native.get('artifact', {})
        if native.get('kind') == 'local_msi':
            for package in packages:
                if artifact.get('sha256') == package.get('artifact', {}).get('sha256') and artifact.get('bytes') == package.get('artifact', {}).get('bytes'):
                    installed['windows'].append(package['arch'])
        elif native.get('kind') == 'macos' and native.get('architecture'):
            if (artifact.get('sha256') == producer.get('/data/macos', {}).get('artifact', {}).get('sha256') and
                    artifact.get('bytes') == producer.get('/data/macos', {}).get('artifact', {}).get('bytes')):
                installed['macos'].append(native['architecture'])
    platforms = {}
    for platform in installed:
        states = {a['signing'] for a in assets.values() if a['platform'] == platform}
        platforms[platform] = {'signing': next(iter(states)) if len(states) == 1 else 'pending',
            'installed_tested_architectures': sorted(set(installed[platform])),
            'installation_state': 'observed' if installed[platform] else 'pending'}
    return {'schema': SCHEMA, 'context': record['context'], 'source_sha': source,
            'version': version, 'download_url': url, 'assets': assets,
            'platforms': platforms, 'evidence_links': sorted(set(evidence))}


def producer_record(metadata, assets, *, unsigned_platforms, setup_signatures=None, installed=(), source_sha=None):
    """Capture the existing producer's measured inventory and explicit outcomes.

    The artifact assembler and promotion share this schema. Installation evidence
    enters as projected acceptance receipts; package presence grants no outcome.
    The caller validates cryptographic receipts at its existing signing boundary.
    """
    # The generated record is attached to candidate metadata after creation.
    # Re-admission projects the original inputs without hashing itself.
    metadata = {key: value for key, value in metadata.items() if key != 'release_facts'}
    version = str(metadata.get('version', '')).removeprefix('v')
    source = source_sha if source_sha is not None else metadata.get('source')
    data = {'source_sha': source, 'version': version, 'metadata': metadata,
        'release_assets': assets, 'packages': [],
        'download_url': 'https://github.com/openabstractions/redist/releases/tag/v' + version,
        'unsigned_platforms': list(unsigned_platforms),
        'macos': {'signed': metadata.get('macos') == 'signed'},
        'setup': {'signatures': setup_signatures or {}}}
    for row in assets:
        name = row['name']
        for arch in ('x64', 'arm64'):
            if name in ('abstraction-' + arch + '.msi', 'abstraction-' + version + '-' + arch + '.msi'):
                data['packages'].append({'arch': arch, 'artifact': row['artifact']})
        if name == 'abstraction-' + version + '-macos-universal.pkg':
            data['macos']['artifact'] = row['artifact']
    evidence = 'https://github.com/openabstractions/redist/actions/runs/' + str(metadata['run_id'])
    record = {'schema': SCHEMA, 'context': 'candidate',
        'provenance_kind': 'allowlisted-existing-owner-receipt-projection',
        'observations': [project(json.dumps({'data': data}).encode(), 'producer', evidence), *installed]}
    derive(record)
    return record


def receipt_record(candidate, installed_receipts=()):
    """Project existing, already-authenticated producer/acceptance values.

    This pure join grants no authority to serialized input. The receiving owner
    validates original artifacts/native receipts before calling source_admission.
    """
    evidence = 'https://github.com/openabstractions/redist/actions/runs/' + str(candidate['metadata']['run_id'])
    producer = dict(candidate)
    declared = candidate['metadata'].get('release_facts')
    if declared is not None:
        selected = derive(declared)
        if selected['version'] != candidate['version'] or selected['source_sha'] != candidate['metadata']['source']:
            raise ValueError('received producer fact identity differs from candidate metadata')
        observation = next(row['values'] for row in declared['observations'] if row['role'] == 'producer')
        producer['download_url'] = selected['download_url']
        producer['unsigned_platforms'] = observation.get('/data/unsigned_platforms', [])
    record = {'schema': SCHEMA, 'context': 'candidate',
        'provenance_kind': 'allowlisted-existing-owner-receipt-projection',
        'observations': [project(json.dumps({'data': producer}).encode(), 'producer', evidence)]}
    for receipt in installed_receipts:
        record['observations'].append(project(json.dumps({'data': receipt}).encode(), 'installed', evidence))
    derive(record)
    return record


def render_notes(base, record):
    """Replace only the appended producer section, retaining reviewed base notes."""
    marker = '\n<!-- release-facts:generated -->\n'
    base = base.split(marker, 1)[0]
    return base.rstrip() + '\n' + marker + render_build_record(derive(record))


def plain(text):
    return re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]*>', ' ', text)).replace('**', '').replace('`', '')).strip()


def scan(text, facts, path):
    """Scan all statement blocks; unmatched fact assertions fail closed."""
    findings = []
    # Preserve source offsets while separating prose paragraphs, list items and
    # HTML block elements. Wrapped source lines remain the same statement.
    boundaries = re.compile(r'\n\s*\n|\n(?=\s*[-*] )|<br\s*/?>|(?=<(?:p|li|tr|h[1-6])\b)|(?<=\}),\s*(?=\{)', re.I)
    spans, start = [], 0
    for boundary in boundaries.finditer(text):
        spans.append((start, text[start:boundary.start()]))
        start = boundary.end()
    spans.append((start, text[start:]))
    statements = []
    for offset, block in spans:
        # A Linux clause must not turn the same paragraph's Windows clause
        # unsigned. Sentence boundaries retain explicit historical qualifiers.
        begin = 0
        for boundary in re.finditer(r';|,(?=\s*(?:and\s+)?(?:a\s+)?(?:Developer ID\s+)?(?:un)?signed\b)|(?<=[.!?])\s+(?=[A-Z])', block, re.I):
            prefix = block[:boundary.start()]
            if prefix.count('[') > prefix.count(']'):
                continue  # Keep an evidence link's versioned caption with its URL.
            statements.append((offset + begin, block[begin:boundary.start()]))
            begin = boundary.end()
        statements.append((offset + begin, block[begin:]))
    spans = statements
    for offset, block in spans:
        value = plain(block)
        low = value.lower()
        qualified = re.search(r'\bhistorical\b|\bdated (?:development|experiment)|\bdevelopment preview\b|\bsource[- ](?:only|level)\b|\b(?:planned|future) release\b|\bnot (?:yet )?(?:shipped|released|delivered)\b', low)
        current = re.search(r'\bavailable now\b|\blatest (?:runtime |public )?release\b|\bcurrent release\b', low)
        headings = list(re.finditer(r'^#{1,6} (.+)$', text[:offset], re.M))
        historical_section = headings and 'historical' in headings[-1].group(1).lower()
        sections = list(re.finditer(r'<section\b[^>]*\bid=["\']release-(\d+)-(\d+)-(\d+)["\']', text[:offset], re.I))
        historical_section = historical_section or (sections and '.'.join(sections[-1].groups()) != facts['version'])
        versions = re.findall(r'\b\d+\.\d+\.\d+\b', value)
        explicitly_older = versions and all(v != facts['version'] for v in versions)
        if (qualified or historical_section or explicitly_older or low.startswith('do not infer ')) and not current:
            continue  # A qualification supplies no delivered-release fact.
        def fail(code, expected, observed=value):
            findings.append({'path': path, 'line': text.count('\n', 0, offset) + 1,
                'code': code, 'message': code.replace('_', ' '), 'expected': expected, 'observed': observed})
        if re.search(r'available now|latest (?:runtime |public )?release|current release|^#+ release |^open abstractions ', low):
            for version in re.findall(r'\b\d+\.\d+\.\d+\b', value):
                if version != facts['version']:
                    fail('release_version', facts['version'], version)
        for version in re.findall(r'github\.com/openabstractions/redist/releases/(?:tag|download)/v(\d+\.\d+\.\d+)', value):
            if version != facts['version']:
                if not current and re.search(r'\[[^\]]*\b' + re.escape(version) + r'\b[^\]]*\]\(https://github\.com/openabstractions/redist/releases/', value):
                    continue  # Explicitly versioned historical evidence keeps its scope.
                fail('release_evidence_url', facts['download_url'], version)
        if re.search(r'evidence|verification|installed|signing', low):
            for url in re.findall(r'https://github\.com/openabstractions/redist/actions/runs/\d+', value):
                if url not in facts['evidence_links']:
                    fail('release_evidence_url', facts['evidence_links'], url)
        for platform, aliases in (('windows', r'windows|msi'), ('linux', r'linux'), ('macos', r'macos|\.pkg')):
            if not re.search(aliases, low):
                continue
            expected = facts['platforms'][platform]
            named = [asset for name, asset in facts['assets'].items() if name in value and asset['platform'] == platform]
            signing_state = expected['signing']
            if named:
                states = {asset['signing'] for asset in named}
                signing_state = next(iter(states)) if len(states) == 1 else 'pending'
            unsigned = re.search(r'\bunsigned\b|\bnot signed\b', low)
            signed = re.search(r'\bsigned\b|\bnotari[sz]ed\b', low) and not unsigned
            if (unsigned or signed) and signing_state != ('unsigned' if unsigned else 'signed'):
                fail('platform_signing', signing_state)
            if re.search(r'\b(?:signing|signature) (?:state|status)\s*(?:is|:)', low) and not (unsigned or signed):
                fail('unresolved_signing_statement', signing_state)
            if not re.search(r'not (?:installation|install)[- ]tested|no installed', low) and re.search(r'install(?:ation)?[- ]tested|installation (?:passed|verified)|installed acceptance (?:passed|proven)', low):
                arches = re.findall(r'\b(?:arm64|amd64|x86_64|x64)\b', low)
                if not arches or any(a not in expected['installed_tested_architectures'] for a in arches):
                    fail('installed_architecture', expected['installed_tested_architectures'])
    return findings


def render_build_record(facts):
    """The appended notes and Signatures consume the admitted closed facts."""
    rows = ['## Build record', '', 'Release: ' + str(facts['version'] or 'pending'),
            'Download: ' + str(facts['download_url'] or 'pending'), '', '## Signatures', '']
    for name, asset in sorted(facts['assets'].items()):
        if asset['platform']:
            rows.append('- `' + name + '`: ' + asset['signing'] + '.')
    rows.extend(('', '## Installed-tested architectures', ''))
    for platform, value in sorted(facts['platforms'].items()):
        rows.append('- ' + platform + ': ' + (', '.join(value['installed_tested_architectures']) or 'pending') + '.')
    rows.extend(('', '## Evidence', ''))
    rows.extend('- ' + url for url in facts['evidence_links'])
    return '\n'.join(rows) + '\n'


def latest_record(root):
    records = []
    for path in (root / 'research').glob('release-*/published.json'):
        value = json.loads(path.read_bytes())
        if value.get('schema') == SCHEMA and value.get('context') == 'published':
            facts = derive(value)
            if facts['version']:
                records.append((tuple(map(int, facts['version'].split('.'))), path))
    if not records:
        raise ValueError('no portable published producer/acceptance release record')
    return max(records)[1]


def check(root, source_sha, record_path=None, surfaces=SURFACES):
    root = Path(root).resolve()
    if not SOURCE.fullmatch(str(source_sha)):
        raise ValueError('fact admission needs exact source identity')
    record_path = Path(record_path) if record_path else latest_record(root)
    if not record_path.is_absolute():
        record_path = root / record_path
    if '..' in record_path.parts or any(p.is_symlink() or p.is_junction() for p in (record_path, *record_path.parents)):
        raise ValueError('release record must be an ordinary member of the source root')
    record_path = record_path.resolve()
    relative_record = record_path.relative_to(root)
    record_raw = record_path.read_bytes()
    record = json.loads(record_raw)
    facts = derive(record)
    inputs = [{'path': relative_record.as_posix(),
               'sha256': hashlib.sha256(record_raw).hexdigest()}]
    findings = []
    for path in surfaces:
        target = root / path
        if not target.is_file():
            findings.append({'path': path, 'line': 1, 'code': 'missing_surface',
                'message': 'required public surface is absent', 'expected': 'existing source', 'observed': 'absent'})
            continue
        raw = target.read_bytes()
        inputs.append({'path': path, 'sha256': hashlib.sha256(raw).hexdigest()})
        findings.extend(scan(raw.decode('utf-8'), facts, path))
    return {'schema': SCHEMA, 'kind': 'release-fact-findings', 'source_sha': source_sha,
        'context': facts['context'], 'version': facts['version'], 'facts_sha256': digest(facts),
        'facts': facts, 'inputs': inputs, 'allowed_paths': list(surfaces), 'findings': findings,
        'required_checks': [['py', '-3.12', '-m', 'unittest', 'release.test_facts'],
                            ['py', '-3.12', 'scripts/gate_select.py', '--run']],
        'accepted': not findings}


def validate_report(report, root, source_sha, version=None):
    """Publication reads accepted input bindings only; it runs no scan or repair."""
    if (not isinstance(report, dict) or report.get('schema') != SCHEMA or
            report.get('kind') != 'release-fact-findings' or report.get('accepted') is not True or
            report.get('findings') != [] or report.get('source_sha') != source_sha or not report.get('inputs')):
        raise ValueError('publication lacks exact accepted release facts')
    for row in report['inputs']:
        path = Path(root) / row['path']
        if not path.resolve().is_relative_to(Path(root).resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('accepted release fact input changed: ' + row['path'])
    if digest(report.get('facts')) != report.get('facts_sha256'):
        raise ValueError('accepted release facts changed')
    if version is not None and (report.get('context') != 'candidate' or report.get('version') != version):
        raise ValueError('final publication needs actual candidate facts for this version')
    if version is not None and (report['facts'].get('source_sha') != source_sha or
            report['facts'].get('context') != 'candidate' or not report['facts'].get('download_url')):
        raise ValueError('candidate fact identity/download evidence remains pending')


def findings_packet(report):
    return {key: report[key] for key in ('schema', 'kind', 'source_sha', 'context',
        'version', 'facts_sha256', 'inputs', 'allowed_paths', 'findings', 'required_checks')}


# The PLAN block is the accepted scope. Candidate metadata remains the artifact
# roster; this reader does not create another selection catalogue.
SCOPE_FENCE = re.compile(r'^```release-admission-scope[ \t]*\n(.*?)^```[ \t]*$', re.M | re.S)
MODES = {'native-oa': {'native-ipc', 'download-job', 'logging',
                       'refuse-without-runtime', 'resume-one-job'},
         'official-plus-plugin': {'plugin-install', 'model-list',
                                  'model-completion', 'tools', 'oa-integration'},
         'official-plus-extension': {'extension-install', 'workflow-prepare',
             'gpu-render', 'cancel-work', 'program-integration-lifecycle'}}
# Target kinds name existing receiving boundaries. Website evidence binds the
# built site artifact; it cannot be satisfied by an installer receipt.
TARGET_OWNERS = {'windows-x64': 'installed', 'macos-arm64': 'installed', 'web': 'website'}


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON member: ' + key)
        value[key] = item
    return value


def cited_text(text, heading):
    """Return one exact Markdown entry/section, normalising line endings only."""
    text = text.replace('\r\n', '\n')
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.rstrip('\n') == heading]
    if len(starts) != 1:
        raise ValueError('missing or ambiguous citation heading')
    start = starts[0]
    if heading.startswith('- **'):
        ends = [i for i in range(start + 1, len(lines))
                if lines[i].startswith(('- **', '# '))]
    elif re.match(r'^#{1,6} ', heading):
        level = len(heading.split(' ', 1)[0])
        ends = [i for i in range(start + 1, len(lines))
                if re.match(r'^#{1,' + str(level) + r'} ', lines[i])]
    else:
        raise ValueError('citation needs an exact Markdown heading or VISION entry')
    return ''.join(lines[start:ends[0] if ends else len(lines)]).rstrip('\n') + '\n'


def read_admission_scope(plan_text, version, read_text, previous=None):
    """Pure scope/citation reader. Owner review decides semantic authority."""
    issues = []
    def fail(code, item, message):
        issues.append({'code': code, 'id': item, 'message': message})
    blocks = SCOPE_FENCE.findall(plan_text.replace('\r\n', '\n'))
    if len(blocks) != 1:
        return None, [{'code': 'scope_block', 'id': '',
                       'message': 'exactly one release-admission-scope block is required'}]
    try:
        scope = json.loads(blocks[0], object_pairs_hook=_strict_object)
    except (ValueError, TypeError) as error:
        return None, [{'code': 'scope_json', 'id': '', 'message': str(error)}]
    required = {'schema', 'release', 'decisions', 'adopters', 'journeys', 'amendments'}
    if not isinstance(scope, dict) or set(scope) != required:
        return None, [{'code': 'scope_schema', 'id': '', 'message': 'scope members differ from schema1'}]
    if type(scope['schema']) is not int or scope['schema'] != 1 or scope['release'] != version or not VERSION.fullmatch(str(version)):
        fail('scope_identity', '', 'scope schema/release differs')
    for key in ('decisions', 'adopters', 'journeys', 'amendments'):
        if not isinstance(scope[key], list):
            fail('scope_schema', key, 'scope member must be a list')
    if issues:
        return scope, issues
    decisions = {}
    for row in scope['decisions']:
        if not isinstance(row, dict) or set(row) != {'id', 'path', 'heading', 'text_sha256'}:
            fail('scope_citation', '', 'invalid decision citation'); continue
        key = row['id']
        if not isinstance(key, str) or not key or key in decisions:
            fail('scope_citation', str(key), 'decision id is absent or duplicated'); continue
        decisions[key] = row
        if row['path'] not in ('VISION.md', 'research/release-0.8.0/PLAN.md'):
            fail('scope_citation', key, 'citation must name its existing VISION or PLAN owner'); continue
        try:
            raw = cited_text(read_text(row['path']), row['heading']).encode('utf-8')
            if not SHA.fullmatch(str(row['text_sha256'])) or hashlib.sha256(raw).hexdigest() != row['text_sha256']:
                fail('scope_citation', key, 'cited decision text changed')
        except (OSError, ValueError, TypeError) as error:
            fail('scope_citation', key, str(error))
    if not decisions:
        fail('scope_citation', '', 'accepted scope needs an authority citation')
    ids = set()
    for kind in ('adopters', 'journeys'):
        for row in scope[kind]:
            base = {'id', 'decision', 'targets'}
            fields = base | ({'mode', 'behavior'} if kind == 'adopters' else {'evidence_mode', 'outcomes'})
            if not isinstance(row, dict) or set(row) != fields:
                fail('scope_requirement', '', 'invalid ' + kind + ' row'); continue
            key = row['id']
            if not isinstance(key, str) or not key or key in ids:
                fail('scope_requirement', str(key), 'requirement id is absent or duplicated')
            ids.add(str(key))
            if not isinstance(row['decision'], str) or row['decision'] not in decisions:
                fail('scope_citation', key, 'requirement lacks its accepted citation')
            if (not isinstance(row['targets'], list) or not row['targets'] or
                    any(not isinstance(t, str) or t not in TARGET_OWNERS for t in row['targets']) or
                    len(set(row['targets'])) != len(row['targets'])):
                fail('scope_requirement', key, 'targets must name unique existing installed or website owners')
            values = row.get('behavior') if kind == 'adopters' else row.get('outcomes')
            if (not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values) or
                    len(set(values)) != len(values)):
                fail('scope_requirement', key, 'required observations must be unique and nonempty')
            elif kind == 'adopters' and (not isinstance(row['mode'], str) or row['mode'] not in MODES or not set(values) <= MODES[row['mode']]):
                fail('scope_mode', key, 'unknown adoption mode or behavior')
            elif kind == 'adopters' and row['mode'] == 'native-oa' and set(values) != MODES['native-oa']:
                fail('scope_mode', key, 'native-oa requires all five accepted receiver behaviors')
            if kind == 'journeys' and row['evidence_mode'] not in ('automated', 'owner-recorded'):
                fail('scope_mode', key, 'journey evidence must be automated or owner-recorded')
    removed = set()
    for row in scope['amendments']:
        if (not isinstance(row, dict) or set(row) != {'decision', 'replaces', 'ships_instead', 'reason'} or
                not isinstance(row.get('decision'), str) or row.get('decision') not in decisions or
                decisions.get(row.get('decision'), {}).get('path') != 'VISION.md' or
                not row.get('reason') or not isinstance(row.get('replaces'), list) or not row['replaces'] or
                any(not isinstance(k, str) or not k for k in row['replaces']) or
                not isinstance(row.get('ships_instead'), list) or not row['ships_instead'] or
                any(not isinstance(k, str) or not k for k in row['ships_instead'])):
            fail('scope_amendment', '', 'removal requires an explicit cited VISION owner amendment'); continue
        removed.update(row['replaces'])
        if not set(row['ships_instead']) <= ids | {'core'}:
            fail('scope_amendment', '', 'replacement is absent from scope')
    if previous is not None and not issues:
        old = {r['id']: (kind, r) for kind in ('adopters', 'journeys') for r in previous[kind]}
        current = {r['id']: (kind, r) for kind in ('adopters', 'journeys')
                   for r in scope[kind] if isinstance(r, dict) and isinstance(r.get('id'), str)}
        for key in sorted(old.keys() - ids - removed):
            fail('scope_removed', key, 'accepted obligation removed without owner amendment')
        for key in sorted(old.keys() & current.keys() - removed):
            old_kind, before = old[key]
            kind, after = current[key]
            weakened = kind != old_kind or not set(before['targets']) <= set(after.get('targets', []))
            if kind == old_kind == 'adopters':
                weakened |= before['mode'] != after.get('mode') or not set(before['behavior']) <= set(after.get('behavior', []))
            elif kind == old_kind == 'journeys':
                weakened |= (before['evidence_mode'] != after.get('evidence_mode') or
                             not set(before['outcomes']) <= set(after.get('outcomes', [])))
            if weakened:
                fail('scope_weakened', key, 'accepted mode, targets or observations changed without owner amendment')
    return scope, issues


def admission_outcomes(scope, selections, adopter_receipts, journey_receipts, *,
                       source_sha, inputs_sha256, probe_source_sha256,
                       candidate_artifacts, read_bytes, receiving_context=None):
    """Collect missing/mismatched exact producer/receiver evidence, with no effects.

    receiving_context is an in-process projection from the existing receiving
    owner AFTER its producer/native validation and checked_file calls. It is
    never loaded from a receipt, candidate metadata or user-supplied JSON.
    Missing context is pending. This pure function checks joins, not provenance.
    The owner must validate native peer observations before projecting receiver
    files here; a self-labelled os-peer JSON file cannot supply that validation.
    """
    findings, outcomes = [], {'adopters': [], 'journeys': []}
    def fail(code, key, target, message):
        findings.append({'code': code, 'id': key, 'target': target, 'message': message})
    def matching(rows, key, target):
        return [r for r in rows if isinstance(r, dict) and r.get('id') == key and r.get('target') == target]
    if not SOURCE.fullmatch(str(source_sha)) or not all(SHA.fullmatch(str(x)) for x in (inputs_sha256, probe_source_sha256)):
        fail('admission_identity', '', '', 'exact source, inputs and probe identities are required')
    if (candidate_artifacts.get('source_sha') != source_sha or
            candidate_artifacts.get('version') != scope['release'] or not candidate_artifacts.get('files')):
        fail('admission_artifacts', '', '', 'exact existing candidate_artifacts producer identity/files required')
    context_identity = {'source_sha': source_sha, 'version': scope['release'],
                        'inputs_sha256': inputs_sha256, 'probe_source_sha256': probe_source_sha256,
                        'candidate_artifacts_sha256': digest(candidate_artifacts)}
    functional_scope = bool(scope['adopters'] or scope['journeys'])
    context = receiving_context if isinstance(receiving_context, dict) else {}
    if functional_scope and (any(context.get(k) != v for k, v in context_identity.items()) or
            not isinstance(context.get('selections'), list) or not isinstance(context.get('receiver_files'), list)):
        fail('receiving_context', '', '', 'existing receiving owner has not validated exact producer/native inputs')
    globally_pending = bool(findings)
    scope_hash = digest(scope)
    for kind, receipts in (('adopters', adopter_receipts), ('journeys', journey_receipts)):
        for requirement in scope[kind]:
            key = requirement['id']
            for target in requirement['targets']:
                before = len(findings)
                if TARGET_OWNERS.get(target) == 'website':
                    # Populated only after the existing website owner validates
                    # its exact built files. Installed core proof has no such
                    # projection and cannot satisfy this target.
                    website = context.get('website_artifact')
                    if (not isinstance(website, dict) or website.get('source_sha') != source_sha or
                            website.get('version') != scope['release'] or
                            not website.get('files') or any(f not in candidate_artifacts.get('files', [])
                                for f in website.get('files', []))):
                        fail('website_artifact', key, target, 'exact validated website artifact is pending')
                selected = matching(selections, key, target) if kind == 'adopters' else selections
                chosen = selected[0] if len(selected) == 1 else {}
                if kind == 'adopters':
                    if len(selected) != 1:
                        fail('adopter_selection', key, target, 'required selected adopter is absent or ambiguous')
                    if chosen.get('mode') != requirement['mode']:
                        fail('adopter_mode', key, target, 'selected route differs from accepted adoption mode')
                    owner_choices = matching(context.get('selections', []), key, target)
                    package_hashes = {f.get('sha256') for f in candidate_artifacts.get('files', []) if isinstance(f, dict)}
                    if len(owner_choices) != 1 or owner_choices[0] != chosen or chosen.get('package_sha256') not in package_hashes:
                        fail('producer_selection', key, target, 'selection/package absent from validated existing producer context')
                    fields = ('package_sha256', 'executable_sha256', 'build_config_sha256', 'runtime_sha256', 'sdk_inputs_sha256')
                    if not all(SHA.fullmatch(str(chosen.get(f, ''))) for f in fields) or not SOURCE.fullmatch(str(chosen.get('adopter_source_sha', ''))):
                        fail('adopter_identity', key, target, 'selected artifact/source/build/runtime/SDK binding incomplete')
                    if requirement['mode'] == 'native-oa' and chosen.get('integration_enabled') is not True:
                        fail('native_integration', key, target, 'native integration must be built enabled')
                    if requirement['mode'] == 'official-plus-plugin' and (not SHA.fullmatch(str(chosen.get('plugin_sha256', ''))) or
                            not SOURCE.fullmatch(str(chosen.get('plugin_source_sha', '')))):
                        fail('plugin_identity', key, target, 'official executable needs exact OA plugin and source')
                    if requirement['mode'] == 'official-plus-extension' and (not SHA.fullmatch(str(chosen.get('extension_sha256', ''))) or
                            not SOURCE.fullmatch(str(chosen.get('extension_source_sha', '')))):
                        fail('extension_identity', key, target, 'official executable needs exact OA extension and source')
                rows = matching(receipts, key, target)
                receipt = rows[0] if len(rows) == 1 else {}
                if len(rows) != 1:
                    fail('functional_receipt', key, target, 'required functional receipt absent or ambiguous')
                expected = {'source_sha': source_sha, 'scope_sha256': scope_hash,
                            'inputs_sha256': inputs_sha256, 'probe_source_sha256': probe_source_sha256,
                            'candidate_artifacts_sha256': digest(candidate_artifacts)}
                expected['selection_sha256'] = digest(chosen if kind == 'adopters' else selections)
                if any(receipt.get(k) != v for k, v in expected.items()):
                    fail('functional_binding', key, target, 'functional receipt differs from exact candidate/scope/selection/inputs/probe')
                if receipt.get('result') != 'pass' or receipt.get('executed') is not True or receipt.get('exit_code') != 0:
                    fail('functional_result', key, target, 'missing, failed or deferred proof cannot satisfy a promise')
                proof = {}
                binding = receipt.get('receiver_evidence', {})
                owner_files = [f for f in context.get('receiver_files', []) if f == binding]
                if len(owner_files) != 1:
                    fail('receiving_provenance', key, target, 'receiver file not validated by the existing native receiving owner')
                try:
                    raw = read_bytes(binding['path'])
                    if not SHA.fullmatch(str(binding.get('sha256', ''))) or hashlib.sha256(raw).hexdigest() != binding['sha256']:
                        raise ValueError('receiver evidence bytes changed')
                    proof = json.loads(raw, object_pairs_hook=_strict_object)
                    if not isinstance(proof, dict):
                        proof = {}; raise ValueError('receiver proof must be an object')
                    if any(proof.get(k) != v for k, v in expected.items()) or proof.get('result') != 'pass' or proof.get('executed') is not True or proof.get('exit_code') != 0:
                        raise ValueError('receiver proof identity/result differs')
                except (KeyError, OSError, ValueError, TypeError) as error:
                    fail('receiver_evidence', key, target, str(error))
                required = requirement.get('behavior', requirement.get('outcomes', []))
                observations_value = proof.get('observations', [])
                if not isinstance(observations_value, list) or any(not isinstance(o, dict) for o in observations_value):
                    fail('receiver_observations', key, target, 'receiver observations must be objects')
                    observations_value = []
                for behavior in required:
                    observations = [o for o in observations_value if o.get('behavior') == behavior]
                    if len(observations) != 1 or observations[0].get('result') != 'pass':
                        fail('required_observation', key, target, 'missing passing observation: ' + behavior); continue
                    observation = observations[0]
                    if kind == 'adopters' and behavior in ('native-ipc', 'download-job', 'logging'):
                        actor = observation.get('actor_identity', {})
                        if not isinstance(actor, dict) or actor.get('binding') != 'os-peer' or actor.get('executable_sha256') != chosen.get('executable_sha256'):
                            fail('native_actor', key, target, behavior + ' is not attributed to selected native executable by receiver OS identity')
                    if behavior == 'download-job' and (not observation.get('job_id') or not all(SHA.fullmatch(str(observation.get(f, ''))) for f in ('request_sha256', 'result_sha256'))):
                        fail('download_observation', key, target, 'download lacks receiver job/request/result identity')
                    if behavior == 'logging' and not observation.get('record_ids'):
                        fail('logging_observation', key, target, 'logging lacks receiver record identities')
                    if behavior == 'refuse-without-runtime' and (observation.get('refused') is not True or observation.get('native_http_fallback_observed') is not False):
                        fail('refusal_observation', key, target, 'runtime refusal/no-fallback proof missing')
                    if behavior == 'resume-one-job' and (not observation.get('original_job_id') or observation.get('original_job_id') != observation.get('resumed_job_id') or observation.get('transfer_count') != 1):
                        fail('resume_observation', key, target, 'resume must reconcile one original job and transfer')
                if kind == 'journeys':
                    if proof.get('evidence_mode') != requirement['evidence_mode']:
                        fail('journey_mode', key, target, 'journey evidence mode differs')
                    if requirement['evidence_mode'] == 'owner-recorded':
                        recording = proof.get('recording', {})
                        try:
                            raw = read_bytes(recording['path'])
                            if hashlib.sha256(raw).hexdigest() != recording.get('sha256'):
                                raise ValueError('owner recording bytes changed')
                        except (KeyError, OSError, ValueError, TypeError) as error:
                            fail('journey_recording', key, target, str(error))
                outcomes[kind].append({'id': key, 'target': target,
                    'state': 'pass' if len(findings) == before and not globally_pending else 'pending',
                    'observations': list(required)})
    return {'scope_sha256': scope_hash, 'outcomes': outcomes, 'findings': findings,
            'accepted': not findings}


def render_admission_outcomes(report):
    """Notes consume the same admitted outcomes; pending never becomes a claim."""
    lines = ['## Demonstrated scope', '']
    for kind in ('adopters', 'journeys'):
        for row in report['outcomes'][kind]:
            details = ': ' + ', '.join(row.get('observations', [])) if row.get('observations') else ''
            lines.append('- ' + row['id'] + ' (' + row['target'] + '): ' + row['state'] + details + '.')
    return '\n'.join(lines) + '\n'


def collect_admission(plan_text, version, read_text, *, previous=None, **evidence):
    """One owning entry point for selection, preparation, completion and notes."""
    scope, findings = read_admission_scope(plan_text, version, read_text, previous)
    if findings:
        outcomes = {'adopters': [], 'journeys': []}
        if isinstance(scope, dict):
            for kind in outcomes:
                for row in scope.get(kind, []) if isinstance(scope.get(kind), list) else []:
                    if isinstance(row, dict):
                        outcomes[kind].append({'id': str(row.get('id', '')),
                            'target': '', 'state': 'pending', 'observations': []})
        return {'scope_sha256': digest(scope), 'outcomes': outcomes,
                'scope_valid': False, 'findings': findings, 'accepted': False}
    return dict(admission_outcomes(scope, **evidence), scope_valid=True)


def requires_admission(version):
    """Historical releases retain their original accepted contract."""
    version = str(version).removeprefix('v')
    return bool(VERSION.fullmatch(str(version))) and tuple(map(int, version.split('.'))) >= (0, 8, 0)


def scope_selection(scope, rows):
    """The existing optional roster cannot erase a required adopter."""
    selected = {row.get('id') for row in rows if isinstance(row, dict)}
    return [{'code': 'adopter_selection', 'id': row['id'],
             'message': 'required adopter is absent from selected producer roster'}
            for row in scope['adopters'] if row['id'] not in selected]


def source_admission(root, source_sha, version, *, candidate_artifacts=None,
                     selections=(), adopter_receipts=(), journey_receipts=(),
                     inputs_sha256='', probe_source_sha256='', receiving_context=None,
                     previous=None, installed_receipts=()):
    """Read the source-owned scope into the existing preparation/Job report.

    Source preflight calls without native inputs deliberately reports pending.
    Completion calls only after existing producer/native validation, supplying
    its in-process context. This function never reads context from JSON.
    """
    root, inputs = Path(root).resolve(), []
    def read(path, binary=False):
        target = Path(path)
        target = target if target.is_absolute() else root / target
        raw = target.read_bytes()
        inputs.append({'path': str(target.resolve()), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
        return raw if binary else raw.decode('utf-8-sig')
    path = 'research/release-0.8.0/PLAN.md'
    try:
        text = read(path)
        value = collect_admission(text, version, read, previous=previous,
            source_sha=source_sha, inputs_sha256=inputs_sha256,
            probe_source_sha256=probe_source_sha256, candidate_artifacts=candidate_artifacts or {},
            selections=list(selections), adopter_receipts=list(adopter_receipts),
            journey_receipts=list(journey_receipts), read_bytes=lambda p: read(p, True),
            receiving_context=receiving_context)
        if value['scope_valid']:
            try:
                scope_declaration(root, version, read_text=read)
            except (OSError, ValueError) as error:
                value['scope_valid'] = value['accepted'] = False
                value['findings'].append({'code': 'scope_projection', 'id': '', 'message': str(error)})
    except (OSError, ValueError) as error:
        value = {'accepted': False, 'scope_valid': False, 'scope_sha256': digest(None),
                 'outcomes': {'adopters': [], 'journeys': []},
                 'findings': [{'code': 'scope_input', 'id': '', 'message': str(error)}]}
    # This is the same between-release check used by prepare and the selector.
    # It checks public source claims against the latest historical publication;
    # it does not turn an unfinished candidate into a delivered release.
    # Public claims are independently checkable even when a scope citation is
    # stale. Keep their findings together without accepting the invalid scope.
    try:
        public_facts = check(root, source_sha)
        for binding in public_facts['inputs']:
            raw = read(binding['path'], True)
            if hashlib.sha256(raw).hexdigest() != binding['sha256']:
                raise ValueError('public release fact input changed during admission')
        value['public_release_facts'] = public_facts
        if not public_facts['accepted']:
            value['accepted'] = False
            value['findings'].extend({'code': 'public_release_fact', 'id': row['path'],
                'message': row['message']} for row in public_facts['findings'])
    except (OSError, ValueError) as error:
        value['accepted'] = False
        value['findings'].append({'code': 'public_release_fact', 'id': '', 'message': str(error)})
    if candidate_artifacts:
        try:
            record = receipt_record(candidate_artifacts, installed_receipts)
            value['candidate_release_facts'] = derive(record)
            value['candidate_release_facts_record'] = record
        except (KeyError, TypeError, ValueError) as error:
            value['accepted'] = False
            value['findings'].append({'code': 'candidate_release_fact', 'id': '', 'message': str(error)})
    value.update(schema=1, kind='release-admission-findings', source_sha=source_sha,
                 version=version, inputs=inputs)
    value['report_sha256'] = digest(value)
    return value


def validate_admission_report(report, root, source_sha, version, *, require_delivery=True):
    """Check report structure and exact input hashes; this grants no provenance.

    Delivery callers first revalidate through the existing receiving owner and
    compare its recomputed report. A self-digest cannot establish execution.
    """
    if (not isinstance(report, dict) or report.get('schema') != 1 or
            report.get('kind') != 'release-admission-findings' or
            (require_delivery and (report.get('accepted') is not True or report.get('findings') != [])) or
            report.get('scope_valid') is not True or
            report.get('source_sha') != source_sha or report.get('version') != version or
            not report.get('inputs') or digest({k: v for k, v in report.items() if k != 'report_sha256'}) != report.get('report_sha256')):
        raise ValueError('required adopter/journey admission is pending or differs from exact completed owner report')
    if not require_delivery:
        declared = source_admission(root, source_sha, version)
        if (declared.get('scope_valid') is not True or any(report.get(key) != declared.get(key)
                for key in ('scope_sha256', 'inputs'))):
            raise ValueError('preparation declaration differs from current accepted source scope/catalogue')
    for binding in report['inputs']:
        path = Path(binding['path'])
        raw = (path if path.is_absolute() else Path(root) / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != binding.get('sha256') or len(raw) != binding.get('bytes'):
            raise ValueError('accepted admission input changed: ' + binding['path'])
    if 'public_release_facts' in report:
        validate_report(report['public_release_facts'], root, source_sha)


def public_admission(report, selections):
    """Allowlisted projection at the already validated producer boundary.

    Raw scope, citations, paths, commands, account/environment and receiver
    evidence remain private. This capsule adds no producer authority of its own.
    """
    if report.get('scope_valid') is not True:
        raise ValueError('invalid declared scope has no public producer capsule')
    value = {'schema': 1, 'version': report['version'],
             'scope_sha256': report['scope_sha256'],
             'delivery_accepted': False,
             'outcomes': {kind: [dict({k: row[k] for k in ('id', 'target')}, state='pending')
                                for row in report['outcomes'][kind]] for kind in ('adopters', 'journeys')},
             'selections': [{k: row[k] for k in ('id', 'target', 'mode', 'package_sha256')}
                            for row in selections]}
    value['capsule_sha256'] = digest(value)
    return value


def scope_declaration(root, version, *, emit=False, read_text=None):
    """Emit/check the existing source catalogue's normalized PLAN projection.

    This declaration contains no source commit or completed package proof. It
    can be committed together with its PLAN. The existing candidate producer
    binds actual prepared source and catalogue bytes in output metadata.
    """
    root = Path(root)
    read = read_text or (lambda path: (root / path).read_text(encoding='utf-8-sig'))
    scope, findings = read_admission_scope(read('research/release-0.8.0/PLAN.md'), version, read)
    if findings:
        raise ValueError('scope declaration: ' + json.dumps(findings, sort_keys=True))
    path = 'monitor/internal/setup/adopter_assets.json'
    document = json.loads(read(path), object_pairs_hook=_strict_object)
    if (not isinstance(document, dict) or document.get('schema') != 1 or
            document.get('release_tag') != 'v' + version or not isinstance(document.get('apps'), list)):
        raise ValueError('source adopter catalogue differs from declared release')
    selections = []
    for requirement in scope['adopters']:
        for row in document['apps']:
            if row.get('id') == requirement['id']:
                target = {'windows/amd64': 'windows-x64', 'darwin/arm64': 'macos-arm64'}.get(row.get('platform'))
                if target in requirement['targets']:
                    selections.append({'id': row['id'], 'target': target, 'mode': requirement['mode'],
                                       'package_sha256': row.get('binary_sha256')})
    report = {'scope_valid': True, 'version': version, 'scope_sha256': digest(scope),
        'outcomes': {kind: [{'id': row['id'], 'target': target} for row in scope[kind]
                           for target in row['targets']] for kind in ('adopters', 'journeys')}}
    capsule = public_admission(report, selections)
    validate_public_admission(capsule, version, document['apps'])
    if emit:
        document['release_admission'] = capsule
        (root / path).write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8', newline='\n')
    elif document.get('release_admission') != capsule:
        raise ValueError('source adopter catalogue declaration is absent or stale against accepted PLAN')
    return capsule


def validate_public_admission(value, version, rows, source_sha=None, *, require_delivery=False):
    """Supplement existing public producer validation; never read private scope."""
    keys = {'schema', 'version', 'scope_sha256', 'delivery_accepted', 'outcomes', 'selections', 'capsule_sha256'}
    if (not isinstance(value, dict) or set(value) != keys or value.get('schema') != 1 or
            value.get('version') != version or
            (source_sha is not None and not SOURCE.fullmatch(str(source_sha))) or
            not SHA.fullmatch(str(value.get('scope_sha256'))) or
            digest({k: v for k, v in value.items() if k != 'capsule_sha256'}) != value.get('capsule_sha256')):
        raise ValueError('missing or changed approved producer admission capsule')
    outcomes = value['outcomes']
    if not isinstance(outcomes, dict) or set(outcomes) != {'adopters', 'journeys'}:
        raise ValueError('invalid approved admission outcomes')
    for kind in outcomes:
        if not isinstance(outcomes[kind], list) or any(not isinstance(r, dict) or set(r) != {'id', 'target', 'state'} or
               not isinstance(r['id'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,63}', r['id']) or
               not isinstance(r['target'], str) or r['target'] not in TARGET_OWNERS or r['state'] not in ('pass', 'pending') or
               (require_delivery and r['state'] != 'pass')
               for r in outcomes[kind]):
            raise ValueError('promised public outcome is pending')
        if len({(r['id'], r['target']) for r in outcomes[kind]}) != len(outcomes[kind]):
            raise ValueError('duplicate public admission outcome')
    if require_delivery and value.get('delivery_accepted') is not True:
        raise ValueError('required producer delivery outcomes are pending')
    choices = value['selections']
    if not isinstance(choices, list) or any(not isinstance(r, dict) or
            set(r) != {'id', 'target', 'mode', 'package_sha256'} or
            not isinstance(r['id'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,63}', r['id']) or
            not isinstance(r['target'], str) or r['target'] not in TARGET_OWNERS or
            not isinstance(r['mode'], str) or r['mode'] not in MODES or
            not SHA.fullmatch(str(r['package_sha256'])) for r in choices):
        raise ValueError('approved admission selection is absent')
    by_id = {row['id']: row for row in rows}
    for item in outcomes['adopters']:
        selected = [r for r in choices if r.get('id') == item['id'] and r.get('target') == item['target']]
        row = by_id.get(item['id'], {})
        if (require_delivery and len(selected) != 1) or (selected and
                (len(selected) != 1 or selected[0].get('package_sha256') != row.get('binary_sha256'))):
            raise ValueError('required adopter absent from exact validated producer roster: ' + item['id'])
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--source', help='exact source SHA; defaults to local Git HEAD')
    parser.add_argument('--record', type=Path)
    parser.add_argument('--check', action='store_true', help='check the named public source surfaces offline')
    parser.add_argument('--render', action='store_true', help='render appended build/signature facts from the same record')
    parser.add_argument('--declaration', choices=('check', 'emit'), help='check or emit the existing source catalogue PLAN projection before commit')
    parser.add_argument('--version', help='declared release MAJOR.MINOR.PATCH')
    args = parser.parse_args(argv)
    if args.declaration:
        if not args.version or not requires_admission(args.version):
            parser.error('--declaration requires --version 0.8.0 or later')
        print(json.dumps(scope_declaration(args.root, args.version, emit=args.declaration == 'emit'), sort_keys=True, indent=2))
        return 0
    if args.render:
        record = args.record or latest_record(args.root)
        print(render_build_record(derive(json.loads(Path(record).read_bytes()))), end='')
        return 0
    source = args.source
    if source is None:
        result = subprocess.run(['git', 'rev-parse', '--verify', 'HEAD'], cwd=args.root,
                                capture_output=True, text=True, check=True)
        source = result.stdout.strip()
    report = check(args.root, source, args.record)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report['accepted'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
