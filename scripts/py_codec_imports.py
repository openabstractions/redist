"""Import every generated OA codec of a Python wheel set installed together, offline.

A generated client (_codec.py) reads types off the codecs of the packages it
requires when it is imported: abstraction.asks names
abstraction.rights.api._codec.PermissionSelection. A packed package whose
dependency lacks such a type installs and then fails on import, which 0.4.0
found only in the private workspace. With --wheels this installs every
wheel in DIR into one temporary directory with `pip install --no-index`,
resolving each wheel's requirements among those wheels alone, and imports
every _codec module the set installed, in an isolated interpreter that sees
only that directory. After the imports and wheel input recheck pass, it reports
each wheel's digest, Python imports and native library loads. Redist's candidate workflow runs it on
the wheel set it builds from pypi.tsv (python job). scripts/python_roster.py
uses the same import against the private sources.

  python3 scripts/py_codec_imports.py --wheels DIR    install DIR/*.whl together and import their codecs
  python3 scripts/py_codec_imports.py --help          this text
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

try:
    from . import py_wheels
except ImportError:  # direct script invocation from scripts/
    import py_wheels

# The optional Facade wheel ships this exact package outside the namespace.
FACADE_NATIVE_MODULE = "abstraction_facade_native"

# This code runs inside the isolated import interpreter.
NATIVE_IMAGE = """
def loaded_image(library, symbol):
    address = ctypes.cast(getattr(library, symbol), ctypes.c_void_p)
    if sys.platform == 'win32':
        get_path = ctypes.WinDLL('kernel32', winmode=0x800).GetModuleFileNameW
        get_path.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
        get_path.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_path(library._handle, buffer, len(buffer))
        if 0 < length < len(buffer):
            return buffer.value
    elif sys.platform in ('linux', 'darwin'):
        class DlInfo(ctypes.Structure):
            _fields_ = [('filename', ctypes.c_char_p), ('base', ctypes.c_void_p),
                        ('symbol', ctypes.c_char_p), ('address', ctypes.c_void_p)]
        dl = ctypes.CDLL('libdl.so.2' if sys.platform == 'linux' else None)
        dladdr = dl.dladdr
        dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(DlInfo)]
        dladdr.restype = ctypes.c_int
        info = DlInfo()
        if dladdr(address, ctypes.byref(info)) and info.filename:
            return os.fsdecode(info.filename)
    raise ImportError('could not identify the loaded native image')
"""

CODEC_IMPORT = """import ctypes, hashlib, importlib, json, os, platform, sys, sysconfig
""" + NATIVE_IMAGE + """
paths = sys.argv[1].split(os.pathsep)
sys.path[:0] = paths
bindings = json.load(sys.stdin)
root = os.path.realpath(paths[0])
python_platform = sysconfig.get_platform()
machine = platform.machine().lower()
if sys.platform == 'win32':
    machine = {'win-amd64': 'x86_64', 'win-arm64': 'arm64', 'win32': 'x86'}.get(python_platform, '')
elif sys.platform == 'linux':
    machine = python_platform.removeprefix('linux-')
arch = {'amd64': 'x86_64', 'aarch64': 'arm64'}.get(machine, machine)
native_target = {
    ('win32', 'x86_64'): 'win_amd64', ('win32', 'arm64'): 'win_arm64',
    ('linux', 'x86_64'): 'manylinux_2_28_x86_64', ('linux', 'arm64'): 'manylinux_2_28_aarch64',
    ('darwin', 'x86_64'): 'macosx_11_0_x86_64', ('darwin', 'arm64'): 'macosx_11_0_arm64',
}.get((sys.platform, arch)) if ctypes.sizeof(ctypes.c_void_p) == 8 else None
native = bindings.get('native', {})
for _, tag, _ in native.values():
    if tag != native_target:
        raise ImportError('native wheel target differs from child platform: ' + tag)

def verify(path, member, digest):
    if os.path.relpath(path, root).replace(os.sep, '/') != member:
        raise ImportError(member + ' differs from the selected wheel path')
    actual = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            actual.update(block)
    if actual.hexdigest() != digest:
        raise ImportError(member + ' differs from the selected wheel bytes')

for name in sys.argv[2:]:
    binding = bindings.get('imports', {}).get(name)
    if binding is not None:
        verify(os.path.realpath(os.path.join(root, binding[0])), *binding)
    module = importlib.import_module(name)
    file = os.path.realpath(module.__file__)
    if not any(os.path.commonpath([os.path.realpath(path), file]) == os.path.realpath(path) for path in paths):
        raise ImportError(name + ' escaped the selected package target')
    if binding is not None:
        verify(file, *binding)

loaded = {}
for member, (digest, tag, symbol) in native.items():
    path = os.path.realpath(os.path.join(root, member))
    verify(path, member, digest)
    library = ctypes.CDLL(path)
    image = os.path.realpath(loaded_image(library, symbol))
    if os.path.normcase(image) != os.path.normcase(path):
        raise ImportError(member + ' loaded a different image')
    verify(image, member, digest)
    loaded[member] = digest
print(json.dumps({'python': platform.python_version(), 'platform': python_platform,
                  'arch': arch, 'native': loaded}))
"""

def codec_modules(directory):
    """Dotted names of the _codec.py modules under directory (a package source or site directory)."""
    directory = Path(directory)
    return sorted(".".join(path.relative_to(directory).with_suffix("").parts)
                  for path in directory.rglob("_codec.py")
                  if "build" not in path.relative_to(directory).parts and path.relative_to(directory).parts[0] == "abstraction")


def import_environment():
    return {key: value for key, value in os.environ.items()
            if not key.upper().startswith(('LD_', 'DYLD_'))
            and key.upper() not in ('_PYTHON_HOST_PLATFORM', '_PYTHON_SYSCONFIGDATA_NAME',
                                    '_PYTHON_SYSCONFIGDATA_PATH', 'MACOSX_DEPLOYMENT_TARGET')}


def import_codecs(path, modules, *, bindings=None, observation=None):
    """None when every module imports with only path (a list of directories) on sys.path; else the last error line."""
    # -B: an import of package source writes no __pycache__ into it.
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", CODEC_IMPORT, os.pathsep.join(map(str, path)), *modules],
                            input=json.dumps(bindings or {}), env=import_environment(), capture_output=True, text=True)
    if result.returncode:
        return (result.stderr.strip().splitlines() or ["exit %d" % result.returncode])[-1]
    if observation is not None:
        try:
            measured = json.loads(result.stdout.splitlines()[-1])
        except (IndexError, ValueError):
            return 'missing import child observation'
        expected = {member: pin[0] for member, pin in (bindings or {}).get('native', {}).items()}
        if (not isinstance(measured, dict) or measured.get('native') != expected
                or any(not isinstance(measured.get(key), str) or not measured[key]
                       for key in ('python', 'platform', 'arch'))):
            return 'import child observation differs from the selected inputs'
        observation.update(measured)
    return None


def wheel_import_members(wheel):
    """Map each concrete package import to its exact member in the copied wheel."""
    with zipfile.ZipFile(wheel) as archive:
        modules = {}
        for name in archive.namelist():
            parts = Path(name).parts
            if name == FACADE_NATIVE_MODULE + "/__init__.py":
                module = FACADE_NATIVE_MODULE
            elif (name.endswith('.py') and len(parts) == 1 and parts[0].startswith('abstraction_')):
                module = Path(name).stem
            elif (parts and parts[0] == 'abstraction' and parts[-1] in ('__init__.py', '_codec.py')):
                dotted = list(parts[:-1]) if parts[-1] == '__init__.py' else list(parts[:-1]) + ['_codec']
                if not all(part.isidentifier() for part in dotted):
                    continue
                module = '.'.join(dotted)
            else:
                continue
            if module in modules:
                raise ValueError('wheel repeats Python import ' + module)
            with archive.open(name) as stream:
                modules[module] = (name, stream_sha256(stream))
        if not modules:
            raise ValueError('wheel has no declared OA package import: ' + Path(wheel).name)
        return modules


def wheel_modules(wheel):
    return set(wheel_import_members(wheel))


def wheel_native_member(wheel):
    """Receive the existing native family's fixed library and its exact bytes."""
    family = next((f for f in py_wheels.NATIVE_FAMILIES.values() if wheel.name.startswith(f["wheel"] + "-")), None)
    if family is None:
        if wheel.name.endswith("-any.whl"):
            return None
        raise ValueError('wheel has no declared native family: ' + wheel.name)
    _, tag, _ = py_wheels.check(wheel)
    member = f"{family['module']}/_native/{family['libraries'][tag]}"
    symbol = 'oa_ipc_open' if family['module'] == 'abstraction/ipc' else 'oa_appmodel_abi_version'
    with zipfile.ZipFile(wheel) as archive, archive.open(member) as stream:
        return member, stream_sha256(stream), tag, symbol


def stream_sha256(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1 << 20), b""):
        digest.update(block)
    return digest.hexdigest()


def wheel_sha256(wheel):
    with wheel.open("rb") as stream:
        return stream_sha256(stream)


def wheel_set_findings(wheels):
    """Install every wheel in the directory together, offline, and import every codec it installed."""
    wheels = Path(wheels)
    files = sorted(wheels.glob("*.whl"))
    if not files:
        return ["no wheels in " + str(wheels)]
    selected = {}
    owners = {}
    bindings = {"imports": {}, "native": {}}
    with tempfile.TemporaryDirectory(prefix="py-codec-imports-") as tmp:
        copies = Path(tmp) / "wheels"
        copies.mkdir()
        try:
            for wheel in files:
                copy = copies / wheel.name
                shutil.copyfile(wheel, copy)
                imports = wheel_import_members(copy)
                native = wheel_native_member(copy)
                for module in sorted(imports):
                    if module in owners:
                        return [f"duplicate Python import {module}: {owners[module]} and {wheel.name}"]
                    owners[module] = wheel.name
                bindings["imports"].update(imports)
                if native is not None:
                    member, digest, tag, symbol = native
                    if member in bindings["native"]:
                        return ["duplicate Python native member: " + member]
                    bindings["native"][member] = (digest, tag, symbol)
                selected[wheel] = (wheel_sha256(copy), imports, native)
        except (OSError, ValueError, py_wheels.Refused, zipfile.BadZipFile) as error:
            return [str(error)]
        target = Path(tmp) / "site"
        result = subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-index",
                                 "--no-compile", "--ignore-installed", "--find-links", str(copies), "--target", str(target),
                                 *(str(copies / wheel.name) for wheel in files)], env=import_environment(),
                                capture_output=True, text=True)
        if result.returncode:
            reason = (result.stderr.strip().splitlines() or ["exit %d" % result.returncode])[-1]
            return ["the wheel set does not install together from %s alone: %s" % (wheels, reason)]
        codecs = codec_modules(target)
        if not codecs:
            return ["the wheel set installed no generated codec"]
        modules = sorted(set(owners) | set(codecs))
        observation = {}
        reason = import_codecs([target], modules, bindings=bindings, observation=observation)
        if reason:
            return ["the wheel set's codecs do not import together: " + reason]
        try:
            for wheel, (digest, _, _) in selected.items():
                if wheel_sha256(copies / wheel.name) != digest:
                    return ["wheel copy changed during import verification: " + wheel.name]
        except OSError as error:
            return ["could not recheck wheel copies: " + str(error)]
    try:
        for wheel, (digest, _, _) in selected.items():
            if wheel_sha256(wheel) != digest:
                return ["wheel changed during import verification: " + wheel.name]
    except OSError as error:
        return ["could not recheck wheel inputs: " + str(error)]
    if sorted(wheels.glob("*.whl")) != files:
        return ["the wheel set changed during import verification"]
    print("imported %d modules from %d wheels" % (len(modules), len(files)))
    for wheel, (digest, imported, native) in selected.items():
        native_proof = "" if native is None else f" native_loaded={native[0]} native_sha256={observation['native'][native[0]]}"
        print(f"PASS {wheel.name} sha256={digest} python_imports={','.join(sorted(imported))}"
              f" python={observation['python']} platform={observation['platform']} arch={observation['arch']}{native_proof}")
    return []


def main(argv):
    if any(a in ("-h", "--help") for a in argv):
        print(__doc__.strip())
        return 0
    if len(argv) != 2 or argv[0] != "--wheels":
        print("py_codec_imports.py takes --wheels DIR; --help explains it", file=sys.stderr)
        return 2
    problems = wheel_set_findings(argv[1])
    for line in problems:
        print("FAIL  " + line)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
