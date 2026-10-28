"""Private normal-producer checks for client-native artifacts; never loads them.

Linux policy/ELF semantics belong to auditwheel 6.8.2. macOS metadata comes from
the selected Xcode lipo/otool tools. A check consumes actual files, not build flags.
"""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


AUDITWHEEL_VERSION = '6.8.2'
AUDITWHEEL_SOURCE = '26d25b5fa7fff2fe976a7c7c00423dcdc1334349'
AUDITWHEEL_PINS = {
    'policy/__init__.py': '066cd6650dfc926cc5eb30b323e65e88841ef8480e082560a5a8bc2bdb29c65e',
    'policy/manylinux-policy.json': '104863eb197685edf6407a51ccde6cbd906be736efb959a991a60d102f1ccf96',
    'elfutils.py': 'b47e90df1f7b1e5f830e41b3e6b5ef501121f1e3474945e8c4edbe769b651a44',
    'lddtree.py': '299209b74749652880c41fd01d4287e2551264da2d90fdd32fd0edf141c30f25',
    'wheel_abi.py': '29930d6e5af5c552b86734935aa4bbaafea1876ec77bbaa1192fd2ca9aefcd74',
    'main_show.py': '498a4b87b549f1c51d742f55acc6cd1f1844e2f823030d3eb25d5a450513cced',
    'architecture.py': 'd9bd3f2c18806ccdfc6272524f26149b777eed85153fc218946bdf6eeda60500',
    'libc.py': '13cc79ed811dddecf9c8ffafe4ba578f526d14a63aa98cca3fe014967a189cc6',
}
POLICY = 'manylinux_2_28_x86_64'


class Refused(ValueError):
    pass


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def tool_output(argv):
    # Metadata utilities only. No ldd/native loader or analyzed binary execution.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, timeout=30)
        if output.tell() > 1024 * 1024:
            raise Refused('native metadata output exceeds its bound')
        output.seek(0); text = output.read().decode('utf-8', errors='strict')
    if result.returncode:
        raise Refused('native metadata tool refused: ' + str(argv[0]))
    return text


class Auditwheel:
    def __init__(self):
        import auditwheel
        from auditwheel.architecture import Architecture
        from auditwheel.libc import Libc
        from auditwheel.policy import WheelPolicies
        if importlib.metadata.version('auditwheel') != AUDITWHEEL_VERSION:
            raise Refused('auditwheel version differs from inspected producer API')
        root = Path(auditwheel.__file__).parent
        for relative, expected in AUDITWHEEL_PINS.items():
            if digest(root / relative) != expected:
                raise Refused('auditwheel source/policy differs: ' + relative)
        self.arch = Architecture.x86_64
        self.libc = Libc.GLIBC
        self.policies = WheelPolicies(libc=self.libc, arch=self.arch)
        self.target = self.policies.get_policy_by_name(POLICY)

    def raw(self, path):
        from auditwheel.elfutils import elf_file_filter, elf_find_versioned_symbols
        from auditwheel.lddtree import ldd
        tree = ldd(path)
        if tree.platform.baseline_architecture != self.arch or tree.platform.extended_architecture not in (None, self.arch):
            raise Refused('native ELF architecture or ISA exceeds x86_64 baseline')
        versions = {}
        found = False
        for _, elf in elf_file_filter([path]):
            found = True
            if elf.header['e_type'] != 'ET_DYN':
                raise Refused('native ELF is not a shared object')
            for library, symbol in elf_find_versioned_symbols(elf):
                versions.setdefault(library, set()).add(symbol)
        if not found:
            raise Refused('native file is not ELF')
        policy = self.policies.versioned_symbols_policy(versions)
        # An empty independent directory prevents a neighboring/RPATH library
        # from being treated as bundled. These packages declare no bundled deps.
        with tempfile.TemporaryDirectory(prefix='oa-auditwheel-empty-') as empty:
            external = self.policies.lddtree_external_references(tree, Path(empty))[POLICY]
        if policy.priority < self.target.priority or external.libs or external.blacklist:
            raise Refused('native ELF exceeds manylinux 2.28 symbols/dependency policy')
        return {'policy': policy.name, 'needed': sorted(tree.needed)}

    def wheel(self, path):
        from auditwheel.wheel_abi import analyze_wheel_abi
        result = analyze_wheel_abi(self.libc, self.arch, path, frozenset(),
                                   disable_isa_ext_check=False, allow_graft=False,
                                   requested_policy_base_name='manylinux_2_28')
        external = result.external_refs[POLICY]
        if result.overall_policy.priority < self.target.priority or external.libs or external.blacklist:
            raise Refused('wheel exceeds manylinux 2.28 policy')
        return {'policy': result.overall_policy.name}

    def provenance(self):
        # The immutable image fixes the dependency closure. Retain the installed
        # distribution identities as well, including the ELF parser dependency.
        result = {'auditwheel_source': AUDITWHEEL_SOURCE, 'pins': AUDITWHEEL_PINS, 'distributions': {}}
        for name in ('auditwheel', 'pyelftools', 'packaging'):
            distribution = importlib.metadata.distribution(name)
            files = {}
            for item in distribution.files or ():
                if str(item).endswith(('.py', '.json', '/METADATA')):
                    if len(files) >= 1000:raise Refused('semantic tool distribution exceeds bound')
                    files[str(item)] = digest(distribution.locate_file(item))
            if not files:raise Refused('semantic tool distribution lacks source provenance')
            result['distributions'][name] = {'version': distribution.version, 'files': files}
        return result


def mac_metadata(text):
    """Read documented otool load-command output, preserving per-slice checks."""
    commands = re.split(r'(?m)^Load command \d+\s*$', text)
    minimum = []
    for command in commands:
        kind = re.search(r'(?m)^\s*cmd (LC_\w+)\s*$', command)
        if not kind:continue
        kind = kind.group(1)
        if kind == 'LC_BUILD_VERSION':
            platform = re.search(r'(?m)^\s*platform (\S+)', command)
            version = re.search(r'(?m)^\s*minos (\S+)', command)
            if not platform or platform.group(1) not in ('1', 'macos') or not version:
                raise Refused('native Mach-O platform is not macOS')
            minimum.append(version.group(1))
        elif kind == 'LC_VERSION_MIN_MACOSX':
            version = re.search(r'(?m)^\s*version (\S+)', command)
            if not version:raise Refused('native Mach-O minimum is absent')
            minimum.append(version.group(1))
        elif kind in ('LC_LOAD_DYLIB', 'LC_LOAD_WEAK_DYLIB', 'LC_REEXPORT_DYLIB', 'LC_LOAD_UPWARD_DYLIB',
                      'LC_LAZY_LOAD_DYLIB', 'LC_PREBOUND_DYLIB'):
            name = re.search(r'(?m)^\s*name (.+) \(offset \d+\)', command)
            if (not name or any(part in ('', '.', '..') for part in name.group(1).split('/')[1:])
                    or not name.group(1).startswith(('/usr/lib/', '/System/Library/Frameworks/'))):
                raise Refused('native Mach-O has an unhandled non-system dependency')
    if len(minimum) != 1 or not re.fullmatch(r'\d+(?:\.\d+){1,2}', minimum[0]):
        raise Refused('native Mach-O needs one explicit minimum per architecture')
    if tuple(map(int, minimum[0].split('.'))) > (11, 0, 0):
        raise Refused('native Mach-O minimum exceeds macOS 11')
    return {'minimum': minimum[0]}


def check_macos(path, architectures, tools):
    actual = tool_output([tools['lipo'], '-archs', str(path)]).split()
    if len(actual) != len(set(actual)) or set(actual) != set(architectures):
        raise Refused('native Mach-O architecture set differs')
    result = {}
    for arch in architectures:
        header = tool_output([tools['otool'], '-arch', arch, '-hv', str(path)])
        expected = 'BUNDLE' if path.suffix == '.node' else 'DYLIB'
        if not re.search(r'\b' + expected + r'\b', header):
            raise Refused('native Mach-O shared object kind differs')
        text = tool_output([tools['otool'], '-arch', arch, '-l', str(path)])
        result[arch] = mac_metadata(text)
        result[arch].update(header=header, load_commands=text)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=('linux-x64', 'darwin-x64', 'darwin-arm64', 'darwin-universal'), required=True)
    parser.add_argument('--file', type=Path, action='append', required=True)
    parser.add_argument('--wheel', type=Path, action='append', default=[])
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.receipt.exists() or args.receipt.resolve() in {path.resolve() for path in args.file + args.wheel}:
        raise Refused('native metadata receipt must be a fresh separate output')
    if not 1 <= len(args.file) <= 4 or len(args.wheel) > 2 or len(set(args.file + args.wheel)) != len(args.file + args.wheel):
        raise Refused('native artifact inventory differs')
    if any(path.is_symlink() or not path.is_file() for path in args.file + args.wheel):
        raise Refused('native artifact must be an existing regular file')
    if any(path.stat().st_size > 64 * 1024 * 1024 for path in args.file + args.wheel):
        raise Refused('native artifact exceeds producer bound')
    before = {str(path): digest(path) for path in args.file + args.wheel}
    report = {'schema': 1, 'platform': args.platform, 'inputs': before, 'artifacts': {}}
    if args.platform == 'linux-x64':
        owner = Auditwheel()
        for path in args.file:report['artifacts'][str(path)] = owner.raw(path)
        for path in args.wheel:
            # Keep standard human-readable auditwheel output alongside the strict
            # API verdict. A successful show process alone never admits a wheel.
            show = tool_output([sys.executable, '-m', 'auditwheel', 'show', str(path)])
            report['artifacts'][str(path)] = dict(owner.wheel(path), auditwheel_show=show)
        report['tools'] = owner.provenance()
    else:
        if args.wheel:raise Refused('Darwin wheel policy is owned by its platform/member receiver')
        architectures = {'darwin-x64': ['x86_64'], 'darwin-arm64': ['arm64'], 'darwin-universal': ['x86_64', 'arm64']}[args.platform]
        tools = {name: shutil.which(name) for name in ('lipo', 'otool')}
        if not all(tools.values()):raise Refused('Xcode native metadata tools are unavailable')
        for path in args.file:report['artifacts'][str(path)] = check_macos(path, architectures, tools)
        report['tools'] = {name: {'path': path, 'sha256': digest(path)} for name, path in tools.items()}
    if before != {str(path): digest(path) for path in args.file + args.wheel}:
        raise Refused('native artifacts changed during receiving')
    encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if len(encoded.encode('utf-8')) > 2 * 1024 * 1024:
        raise Refused('native metadata receipt exceeds bound')
    args.receipt.write_text(encoded, encoding='utf-8')
    return 0


if __name__ == '__main__':
    try:raise SystemExit(main())
    except (OSError, ValueError, ImportError, subprocess.SubprocessError) as error:
        print('FAIL ' + str(error), file=sys.stderr)
        raise SystemExit(1)
