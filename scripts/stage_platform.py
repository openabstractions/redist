#!/usr/bin/env python3
"""Run a staged release's qualification on this machine: one platform leg.

`oa stage-release` writes a bundle (plan.json, the staged module proxy and one
Git bundle per repository) and runs this script on Windows, on Linux and on
macOS. It needs Python 3.8 or newer, git, bash and go, and no network other
than the module proxy the plan names for third-party modules.

    stage_platform.py run --bundle DIR --work DIR --platform windows|linux|macos
                          [--path-prefix PATHS]

Each job starts from fresh Git clones of the bundled repositories, made the way
a hosted runner checks them out: core.autocrlf=true on Windows, false elsewhere.
Two kinds of job run:
  preflight   required tools and version constraints derived from the staged
              jobs; records the selected executables and observed versions
  module      go build, go test -count=1, and go test -race -count=1 on every
              package that starts goroutines or imports sync
  workflow    a job of a repository's push-triggered workflow, one matrix entry
              per platform: checkout and run steps, with ${{ }} expressions,
              step outputs and the GITHUB_* files a runner provides
Results: WORK/results/results.json and one log per step under WORK/results/logs.
Exit 0 when every job passed, 1 otherwise, 2 when the bundle cannot be read.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform as host_platform
import re
import shutil
import stat
import subprocess
import sys
import time
import tempfile
import uuid

if __package__:
    from .file_boundary import remove_tree
else:
    from file_boundary import remove_tree

# Whole serve-package budget shared with the focused local gate.
SERVE_TEST_TIMEOUT = "30m"

PLATFORMS = ("windows", "linux", "macos")
RUNNER_OS = {"windows": "Windows", "linux": "Linux", "macos": "macOS"}
# actions/checkout on hosted Windows images inherits the image's core.autocrlf=true.
AUTOCRLF = {"windows": "true", "linux": "false", "macos": "false"}
GIT_BASH = "C:/Program Files/Git/bin/bash.exe"
CONCURRENT = re.compile(r'\bgo\s+(?:func\s*\(|[A-Za-z_][\w.]*\s*\()|"sync(?:/atomic)?"')
SDK_UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
SDK_UPLOAD_NAME = "windows-go-sdk-${{ github.job }}-${{ github.run_attempt }}"
SDK_UPLOAD_PATHS = ("windows-go-sdk-proof.json", "${{ runner.temp }}/windows-go-smoke/named-pipe-race.log",
                    "${{ runner.temp }}/windows-go-smoke/smoke-receipt.json")


class Unsupported(ValueError):
    """A workflow construct this runner does not emulate; the job fails and says which."""


def result_log_path(results, name):
    """The existing writer/reader share one ordinary, owned log boundary."""
    if not isinstance(name, str) or not re.fullmatch(r"logs/[A-Za-z0-9._-]+", name):
        raise Unsupported("unsafe result log path")
    path = Path(results) / name
    for item in (Path(results), path.parent, path):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise Unsupported("linked result log path")
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_nlink != 1:
        raise Unsupported("result log is not an ordinary file")
    return path


def _output_link(path):
    try: info = path.lstat()
    except FileNotFoundError: return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def platform_of(runs_on):
    value = str(runs_on).lower()
    for prefix, name in (("ubuntu", "linux"), ("windows", "windows"), ("macos", "macos")):
        if value.startswith(prefix):
            return name
    raise Unsupported("runs-on " + str(runs_on) + " names no hosted platform")


def version_tuple(value):
    match = re.fullmatch(r"\d+(?:\.\d+){0,2}", str(value))
    if not match:
        raise Unsupported("invalid planned version " + repr(value))
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (3 - len(parts))


def probe_tools(requirements, env):
    """Record the actual selected executables and compare declared version constraints."""
    observed, failures = {}, list(requirements.get("errors", []))
    arguments = {"go": ["version"], "git": ["--version"], "bash": ["--version"],
                 "node": ["--version"], "cmake": ["--version"]}
    patterns = {"go": r"\bgo(\d+(?:\.\d+){1,2})\b", "git": r"\b(\d+(?:\.\d+){1,2})\b",
                "bash": r"\bversion\s+(\d+(?:\.\d+){1,2})\b", "python3": r"\bPython\s+(\d+(?:\.\d+){1,2})\b",
                "node": r"\bv(\d+(?:\.\d+){1,2})\b", "cmake": r"\bcmake version\s+(\d+(?:\.\d+){1,2})\b",
                "cxx": r"\b(\d+(?:\.\d+){1,2})\b"}
    for tool, constraint in sorted(requirements.items()):
        if tool == "errors":
            continue
        choices = ["g++", "clang++"] if tool == "cxx" else [tool]
        selected = ("python3", sys.executable) if tool == "python3" else \
                   ("bash", bash()) if tool == "bash" and Path(bash()).is_file() else \
                   next(((name, shutil.which(name, path=env.get("PATH"))) for name in choices
                         if shutil.which(name, path=env.get("PATH"))), None)
        if selected is None:
            observed[tool] = {"status": "missing", "required": constraint}
            failures.append(tool + " is not on PATH")
            continue
        name, path = selected
        try:
            # The shell shim is what workflow scripts invoke, including on
            # Windows. Observe its interpreter instead of assuming that the
            # runner's sys.executable is also the job's python3.
            command = ([bash(), "--noprofile", "--norc", "-c",
                        "command -v python3; python3 -c 'import sys; print(sys.executable)'; python3 --version"]
                       if tool == "python3" else [path, *arguments.get(tool, ["--version"])])
            result = subprocess.run(command, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            lines = result.stdout.decode(errors="replace").strip().splitlines() if result.stdout else []
            if tool == "python3" and len(lines) == 3:
                shim, invoked, output = lines
            else:
                shim, invoked = None, None
                output = lines[0] if lines else ""
        except (OSError, subprocess.SubprocessError) as error:
            output, result, shim, invoked = str(error), None, None, None
        match = re.search(patterns[tool], output)
        version = match.group(1) if match else None
        record = {"path": invoked or path, "output": output, "version": version, "required": constraint}
        if shim is not None:
            record["shim"] = shim
        if tool == "python3" and invoked is None:
            record["status"] = "unavailable"
            failures.append("python3 job interpreter could not be identified: " + output)
        elif tool == "python3" and os.path.normcase(os.path.realpath(invoked)) != os.path.normcase(os.path.realpath(sys.executable)):
            record["status"] = "mismatch"
            failures.append("python3 job interpreter " + invoked + " differs from stage runner " + sys.executable)
        elif result is None or result.returncode != 0 or not version:
            record["status"] = "unavailable"
            failures.append(tool + " version probe failed: " + output)
        elif ("minimum" in constraint and version_tuple(version) < version_tuple(constraint["minimum"])) or \
                ("exact" in constraint and version_tuple(version) != version_tuple(constraint["exact"])):
            record["status"] = "mismatch"
            failures.append(tool + " " + version + " does not satisfy " + str(constraint))
        else:
            record["status"] = "pass"
        observed[tool] = record
    if requirements.get("go", {}).get("cgo") and observed.get("go", {}).get("status") == "pass":
        try:
            cgo = subprocess.run([observed["go"]["path"], "env", "CGO_ENABLED"], env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=30)
            enabled = cgo.stdout.decode(errors="replace").strip() if cgo.returncode == 0 else "unavailable"
        except (OSError, subprocess.SubprocessError):
            enabled = "unavailable"
        observed["go"]["cgo_enabled"] = enabled
        if enabled != "1":
            failures.append("go env CGO_ENABLED=" + enabled + "; the race detector needs a C compiler")
        else:
            try:
                selected = subprocess.run([observed['go']['path'], 'env', 'CC'], env=env,
                    capture_output=True, text=True, timeout=30)
                if selected.returncode:
                    raise Unsupported('Go cgo compiler selection unavailable')
                observed['go']['cc'] = selected.stdout.strip()
                observed['go']['c_compiler'] = _go_c_compiler(selected.stdout.strip(), env)
            except (Unsupported, OSError, subprocess.SubprocessError) as error:
                failures.append('Go cgo prerequisite: ' + str(error))
    return observed, failures


# ---- ${{ }} expressions -----------------------------------------------------

TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>-?\d+(?:\.\d+)?)|(?P<op>==|!=|&&|\|\||<=|>=|[!()<>,\[\].*])|(?P<name>[A-Za-z_][\w-]*))")


def tokens(text):
    out, pos = [], 0
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise Unsupported("expression " + repr(text))
        pos = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


def truthy(value):
    return value not in (None, False, 0, "", -0.0)


def loose(value):
    if isinstance(value, str):
        return value.lower() if value.lower() not in ("true", "false") else value.lower() == "true"
    return value


def evaluate(expression, context):
    """GitHub's expression subset these workflows use: contexts, literals, ==, !=, !, &&, ||, status functions."""
    items, index = tokens(expression), [0]

    def peek():
        return items[index[0]] if index[0] < len(items) else (None, None)

    def take(expected=None):
        item = peek()
        if expected is not None and item[1] != expected:
            raise Unsupported("expression " + repr(expression) + ": expected " + expected)
        index[0] += 1
        return item

    def primary():
        kind, value = take()
        if kind == "str":
            return value[1:-1].replace("''", "'")
        if kind == "num":
            return float(value) if "." in value else int(value)
        if value == "(":
            result = either()
            take(")")
            return result
        if value == "!":
            return not truthy(primary())
        if kind != "name":
            raise Unsupported("expression " + repr(expression))
        if value in ("true", "false"):
            return value == "true"
        if value == "null":
            return None
        if peek()[1] == "(":
            take("(")
            args = []
            while peek()[1] != ")":
                args.append(either())
                if peek()[1] == ",":
                    take(",")
            take(")")
            return call(value, args)
        current = context.get(value)
        while peek()[1] in (".", "["):
            if take()[1] == ".":
                key = take()[1]
            else:
                key = either()
                take("]")
            current = current.get(key) if isinstance(current, dict) else None
        return current

    def call(name, args):
        status = context.get("__status", "success")
        if name == "always":
            return True
        if name == "success":
            return status == "success"
        if name == "failure":
            return status == "failure"
        if name == "cancelled":
            return False
        if name == "contains":
            haystack, needle = args
            if isinstance(haystack, (list, tuple)):
                return any(str(x).lower() == str(needle).lower() for x in haystack)
            return str(needle).lower() in str(haystack or "").lower()
        if name == "startsWith":
            return str(args[0] or "").lower().startswith(str(args[1]).lower())
        if name == "endsWith":
            return str(args[0] or "").lower().endswith(str(args[1]).lower())
        if name == "format":
            text = str(args[0])
            for i, arg in enumerate(args[1:]):
                text = text.replace("{" + str(i) + "}", str(arg))
            return text
        raise Unsupported("function " + name + "()")

    def comparison():
        left = primary()
        while peek()[1] in ("==", "!=", "<", ">", "<=", ">="):
            op = take()[1]
            right = primary()
            a, b = loose(left), loose(right)
            if isinstance(a, str) and isinstance(b, str):
                a, b = a.lower(), b.lower()
            left = {"==": a == b, "!=": a != b, "<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]
        return left

    def both():
        left = comparison()
        while peek()[1] == "&&":
            take()
            right = comparison()
            left = right if truthy(left) else left
        return left

    def either():
        left = both()
        while peek()[1] == "||":
            take()
            right = both()
            left = left if truthy(left) else right
        return left

    result = either()
    if index[0] != len(items):
        raise Unsupported("expression " + repr(expression))
    return result


def substitute(text, context):
    if not isinstance(text, str):
        return text

    def value(match):
        result = evaluate(match.group(1), context)
        if result is None:
            return ""
        if isinstance(result, bool):
            return "true" if result else "false"
        return str(result)

    return re.sub(r"\$\{\{(.*?)\}\}", value, text, flags=re.S)


def condition(text, context):
    """A job or step if:, which may omit ${{ }}; the default is success()."""
    if text is None or text == "":
        return evaluate("success()", context)
    if isinstance(text, bool):
        return text
    text = str(text).strip()
    match = re.fullmatch(r"\$\{\{(.*)\}\}", text, flags=re.S)
    expression = match.group(1) if match else text
    # A status function anywhere in the condition replaces the implicit success().
    if not re.search(r"\b(always|success|failure|cancelled)\s*\(", expression):
        expression = "success() && (" + expression + ")"
    return truthy(evaluate(expression, context))


# ---- execution --------------------------------------------------------------

VISUAL_STUDIO = {"16": "Visual Studio 16 2019", "17": "Visual Studio 17 2022", "18": "Visual Studio 18 2026"}


def visual_studio_generator():
    """The CMake generator of the newest Visual Studio with C++ tools, as hosted Windows images default to; None without one."""
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    if not vswhere.is_file():
        return None
    try:
        version = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                                  "-property", "installationVersion"], stdout=subprocess.PIPE, timeout=60).stdout.decode().strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return VISUAL_STUDIO.get(version.split(".", 1)[0])


def write_lf(path, text):
    """Shell scripts keep LF on Windows; Path.write_text takes no newline argument before Python 3.10."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def bash():
    if os.name == "nt":
        return GIT_BASH
    return shutil.which("bash") or "/bin/bash"


def _go_compiler_command(value):
    """Go cmd/internal/quoted.Split: ASCII spaces, leading quotes, no escapes.

    cmd/go/internal/work.envList uses this grammar for CC. Interior quotes
    are literal; adjacent quoted fields are separate arguments.
    """
    if not isinstance(value, str):
        raise Unsupported("native Go cache compiler command is invalid")
    fields = []
    while value:
        value = value.lstrip(" \t\r\n")
        if not value:
            break
        if value[0] in "\"'":
            end = value.find(value[0], 1)
            if end < 0:
                raise Unsupported("native Go cache compiler command has an unterminated quote")
            fields.append(value[1:end])
            value = value[end + 1:]
        else:
            end = next((i for i, char in enumerate(value) if char in " \t\r\n"), len(value))
            fields.append(value[:end])
            value = value[end:]
    if not fields or not fields[0]:
        raise Unsupported("native Go cache compiler command is empty")
    return fields


def _go_c_compiler(value, env):
    """Observe the compiler selected by Go using its existing quoted argv rules."""
    command = _go_compiler_command(value)
    compiler = shutil.which(command[0], path=env.get('PATH'))
    if not compiler:
        raise Unsupported('native Go cache needs the selected C compiler')
    observed = subprocess.run([compiler, *command[1:], '--version'], env=env, capture_output=True,
                              text=True, timeout=30)
    if observed.returncode or not observed.stdout.strip():
        raise Unsupported('native Go cache C compiler identity unavailable')
    return {'path': os.path.realpath(compiler), 'version': observed.stdout}


def native_go_cache(root, env, platform, purpose, go="go", record=None):
    """Select an ordinary Go compilation cache; Go owns action validation."""
    if platform not in PLATFORMS or purpose not in ("qualification", "artifacts", "acceptance"):
        raise Unsupported("unknown native Go cache platform or trust purpose")
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts:
        raise Unsupported("native Go cache root must be absolute")
    for path in (root, *root.parents):
        if path.is_symlink() or (path.exists() and getattr(path.lstat(), "st_file_attributes", 0) & 0x400):
            raise Unsupported("native Go cache root is linked")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt" and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077):
        raise Unsupported("native Go cache root must be private to its owner")
    executable = shutil.which(str(go), path=env.get("PATH"))
    if not executable:
        raise Unsupported("native Go cache needs the selected Go executable")
    selected = subprocess.run([executable, "env", "-json", "GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED",
                               "GOAMD64", "GOARM64", "GOEXPERIMENT", "CC"], env=env, capture_output=True,
                              text=True, timeout=30)
    if selected.returncode:
        raise Unsupported("native Go cache toolchain identity unavailable: " + selected.stderr.strip())
    identity = json.loads(selected.stdout)
    if not all(identity.get(key) for key in ("GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED")):
        raise Unsupported("native Go cache toolchain identity incomplete")
    identity["go"] = os.path.normcase(os.path.realpath(executable))
    if platform == "windows":
        identity["source_identity"] = windows_sdk_identity(env, executable)
        identity["SourceGoStd"] = identity["source_identity"]["stdlib_sha256"]
    identity["build_environment"] = {key: env.get(key, "") for key in
                                     ("GOFLAGS", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS")}
    if identity["CGO_ENABLED"] == "1":
        identity['c_compiler'] = _go_c_compiler(identity.get('CC', env.get('CC', 'gcc')), env)
        identity['c_compiler']['sha256'] = hashlib.sha256(Path(identity['c_compiler']['path']).read_bytes()).hexdigest()
        identity["system"] = host_platform.platform()
        if platform == "macos":
            for name, argv in (("sdk_path", ["xcrun", "--show-sdk-path"]),
                               ("sdk_version", ["xcrun", "--show-sdk-version"]),
                               ("os_build", ["sw_vers", "-buildVersion"])):
                observed = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
                if observed.returncode:
                    raise Unsupported("native Go cache system SDK identity unavailable")
                identity[name] = observed.stdout.strip()
    scope = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
    # These native producer/caller phases consume the same reviewed owned inputs.
    # Keep the phase diagnostic; Go validates each action's source and flags.
    namespace = "owned-native" if purpose in ("artifacts", "acceptance") else purpose
    cache = root / namespace / platform / scope
    for path in (root / namespace, root / namespace / platform, cache):
        if path.is_symlink() or (path.exists() and getattr(path.lstat(), "st_file_attributes", 0) & 0x400):
            raise Unsupported("native Go cache scope is linked")
        if path.exists() and os.name != "nt" and path.stat().st_uid != os.getuid():
            raise Unsupported("native Go cache scope belongs to a different owner")
    cache.mkdir(parents=True, exist_ok=True)
    if record:
        record({"root": str(root), "cache": str(cache), "platform": platform, "purpose": purpose,
                "toolchain": identity, "scope": scope})
    return str(cache)


def windows_sdk_module():
    if __package__:
        from . import windows_go_sdk
    else:
        import windows_go_sdk
    return windows_go_sdk


def windows_sdk_environment(cache_root, env, *, sdk_owner=None):
    """Select the source-verified SDK for one Windows producer phase."""
    sdk = windows_sdk_module() if sdk_owner is None else sdk_owner
    linked = env.get("OA_WINDOWS_GO_SDK_RECEIPT")
    receipt = (sdk.validate_sdk_receipt(json.loads(Path(linked).read_bytes())) if linked
               else sdk.prepare_sdk(cache_root))
    return sdk.sdk_environment(receipt, env), receipt


def windows_sdk_identity(env, executable):
    linked = env.get("OA_WINDOWS_GO_SDK_RECEIPT")
    if not linked:
        raise Unsupported("Windows Go needs its verified SDK receipt")
    receipt = windows_sdk_module().validate_sdk_receipt(json.loads(Path(linked).read_bytes()))
    if os.path.normcase(os.path.realpath(receipt["go"])) != os.path.normcase(os.path.realpath(executable)):
        raise Unsupported("Go executable differs from verified Windows SDK")
    return receipt["source_identity"]


def execution_context(plan):
    context = plan.get('qualification_context')
    if context is None:
        return {'event_name': 'push', 'ref': 'refs/heads/main',
                'commits': {name: row['commit'] for name, row in plan.get('repos', {}).items()}}
    if (set(context) != {'driver_plan_version', 'source', 'version', 'event_name', 'ref', 'commits'}
            or context['driver_plan_version'] != 5 or context['source'] != plan['source']
            or not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', str(context['version']))
            or context['event_name'] != 'push' or context['ref'] != 'refs/heads/release/' + context['version']
            or not isinstance(context['commits'], dict)
            or any(not re.fullmatch(r'[0-9a-f]{40}', str(v)) for v in context['commits'].values())):
        raise Unsupported('invalid v5 prepared qualification context')
    if plan.get('repos') and context['commits'] != {name: row['commit'] for name, row in plan['repos'].items()}:
        raise Unsupported('qualification context differs from actual bundle commits')
    return {key: context[key] for key in ('event_name', 'ref', 'commits')}


def github_context(plan, repo):
    context = execution_context(plan)
    return {'event_name': context['event_name'], 'ref': context['ref'],
            'ref_name': context['ref'].removeprefix('refs/heads/'),
            'sha': context['commits'].get(repo), 'repository': plan['org'] + '/' + repo,
            'event': {'repository': {'name': repo, 'full_name': plan['org'] + '/' + repo}}}


class Leg:
    def __init__(self, bundle, work, name, path_prefix="", go_build_cache=None, output_invocation=None):
        self.bundle, self.work, self.name = Path(bundle).resolve(), Path(work).resolve(), name
        self.plan = json.loads((self.bundle / "plan.json").read_text(encoding="utf-8"))
        self.results = self.work / "results"
        self.logs = self.results / "logs"
        self.prefix = [os.path.expanduser(p) for p in path_prefix.split(os.pathsep) if p] if path_prefix else []
        self.counter = 0
        self.go_build_cache = go_build_cache
        self.go_cache = None
        self.windows_sdk = None
        self.output_invocation = output_invocation or uuid.uuid4().hex
        if not re.fullmatch(r'[0-9a-f]{32}', self.output_invocation):
            raise Unsupported('invalid output invocation')
        self.output_logs = []
        self.output_marker = None
        self.output_marker_identity = None

    def publish_output(self, value):
        """Replace only this invocation's unchanged incomplete results record."""
        target = self.results / 'results.json'
        for path in (self.results, target):
            if _output_link(path):
                raise Unsupported('linked output declaration')
        if target.exists():
            info = target.stat()
            identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            if (not target.is_file() or info.st_nlink != 1 or self.output_marker is None or
                    identity != self.output_marker_identity or target.read_bytes() != self.output_marker):
                raise Unsupported('terminal results already exist or incomplete marker changed')
        elif self.output_marker is not None:
            raise Unsupported('incomplete output marker disappeared')
        raw = (json.dumps(value, indent=2) + '\n').encode('utf-8')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.results, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            if target.exists():
                info = target.stat()
                if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != self.output_marker_identity or
                        _output_link(target) or info.st_nlink != 1 or
                        target.read_bytes() != self.output_marker):
                    raise Unsupported('incomplete output marker changed before replacement')
            elif self.output_marker is not None:
                raise Unsupported('incomplete output marker disappeared before replacement')
            temporary.replace(target)
        finally:
            if temporary is not None: temporary.unlink(missing_ok=True)
        info = target.stat()
        self.output_marker, self.output_marker_identity = raw, (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)

    def declare_log(self, name):
        if name in self.output_logs or len(self.output_logs) >= 1000:
            raise Unsupported('duplicate or excessive declared result logs')
        self.output_logs.append(name)
        self.publish_output({'platform': self.name, 'source': self.plan['source'], 'status': 'incomplete',
            'output_roster': {'invocation_id': self.output_invocation, 'complete': False,
                              'work_root': str(self.work), 'logs': list(self.output_logs)}})

    def base_env(self, job_dir):
        env = dict(os.environ)
        # Live Panel launch permission belongs to its separate controlled evidence run.
        for name in ("GOFLAGS", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOWORK", "GOPATH", "GOTOOLCHAIN",
                     "PYTHONPATH", "GIT_DIR", "GIT_WORK_TREE", "CI", "GITHUB_ACTIONS", "OA_LIVE_PANEL"):
            env.pop(name, None)
        shims = self.work / "bin"
        paths = [str(shims)] + self.prefix + [env.get("PATH", "")]
        env["PATH"] = os.pathsep.join(p for p in paths if p)
        proxy = (self.bundle / "proxy").as_uri()
        env.update(GOPROXY=proxy + "," + self.plan.get("upstream_proxy", "https://proxy.golang.org"),
                   GONOSUMDB=",".join(sorted(m["module"] for m in self.plan["modules"])),
                   GOMODCACHE=str(self.work / "gomod"), GOCACHE=str(self.work / "gocache"),
                   GOPATH=str(self.work / "gopath"), GOTOOLCHAIN="local",
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(self.work / "gitconfig"),
                   GIT_TERMINAL_PROMPT="0")
        if self.name == "windows" and "CMAKE_GENERATOR" not in env:
            # A hosted Windows image's CMake picks its Visual Studio; a CMake from MinGW picks Ninja and refuses -A x64.
            generator = visual_studio_generator()
            if generator:
                env["CMAKE_GENERATOR"] = generator
        if self.name != "windows":
            # Go telemetry, pip and git write under HOME; keep every write inside the leg.
            env["HOME"] = str(self.work / "home")
            env["XDG_CONFIG_HOME"] = str(self.work / "home" / ".config")
            env["XDG_CACHE_HOME"] = str(self.work / "home" / ".cache")
        else:
            sdk = windows_sdk_module()
            if self.windows_sdk is None:
                root = Path(self.go_build_cache) if self.go_build_cache else self.bundle.parent
                env, self.windows_sdk = windows_sdk_environment(root / "windows-go-sdk", env)
            else:
                env = sdk.sdk_environment(self.windows_sdk, env)
        return env

    def prepare(self):
        if self.name == "windows":
            windows_sdk_module()._private_root(self.work / "gocache", create=True)
        remove_tree(self.results)
        self.logs.mkdir(parents=True, exist_ok=True)
        for name in ("gomod", "gocache", "gopath", "home", "bin", "jobs"):
            (self.work / name).mkdir(parents=True, exist_ok=True)
        (self.work / "gitconfig").write_text("[user]\n\tname = stage\n\temail = stage@example.invalid\n[safe]\n\tdirectory = *\n", encoding="utf-8")
        # python3 resolves to the interpreter running this leg, as a hosted image's python3 does to its own.
        shim = self.work / "bin" / "python3"
        if os.name == "nt":
            write_lf(shim, "#!/bin/sh\nexec '" + Path(sys.executable).as_posix() + "' \"$@\"\n")
        else:
            shim.write_text("#!/bin/sh\nexec '" + sys.executable + "' \"$@\"\n", encoding="utf-8")
            shim.chmod(0o755)

    def log(self, text):
        print("[" + self.name + "] " + text, flush=True)

    def execute(self, args, cwd, env, timeout, label, shell_script=None):
        if self.name == "windows":
            env = windows_sdk_module().sdk_environment(self.windows_sdk, env)
        self.counter += 1
        name = "%03d-%s.txt" % (self.counter, re.sub(r"[^A-Za-z0-9._-]+", "_", label)[:80])
        self.declare_log('logs/' + name)
        started = time.time()
        with open(self.logs / name, "wb") as out:
            out.write(("$ " + (shell_script if shell_script is not None else " ".join(args)) + "\n").encode())
            out.flush()
            try:
                p = subprocess.run(args, cwd=str(cwd), env=env, stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
                code = p.returncode
            except subprocess.TimeoutExpired:
                code = "timeout"
                out.write(("\nexceeded " + str(timeout) + " s\n").encode())
            except OSError as error:
                code = "error"
                out.write(("\n" + str(error) + "\n").encode())
        return {"exit": code, "seconds": round(time.time() - started, 1), "log": "logs/" + name}

    def github_context(self, repo):
        return github_context(self.plan, repo)

    def clone(self, repo, target, env):
        entry = self.plan["repos"].get(repo)
        if not entry:
            raise Unsupported("repository " + repo + " is not in the qualification bundle")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and any(target.iterdir()):
            raise Unsupported("checkout path " + str(target) + " is not empty")
        return self.execute(["git", "-c", "init.defaultBranch=main", "clone", "--quiet", "--branch", self.github_context(repo)["ref_name"],
                             "-c", "core.autocrlf=" + AUTOCRLF[self.name],
                             str(self.bundle / entry["bundle"]), str(target)], target.parent, env, 600, "checkout " + repo)

    # -- preflight --
    def preflight(self, job):
        env = self.base_env(self.work)
        checks = []
        if self.name == "linux":
            uid = os.geteuid() if hasattr(os, "geteuid") else None
            permitted = uid is not None and uid != 0
            message = "effective uid=" + str(uid) + "\n"
            if not permitted:
                message += "FAIL  Linux qualification requires a non-root user; select one in the Linux command prefix.\n"
            checks.append({"name": "account", "exit": 0 if permitted else 1, "seconds": 0,
                           "log": self.note("qualification account", message)})
            if not permitted:
                return checks
        if "tools" not in self.plan:
            # A bundle made before per-platform requirements existed keeps
            # its original conservative preflight rather than losing checks.
            required = {"go": {"cgo": True}, "git": {}, "bash": {}, "cmake": {}, "node": {},
                        "cxx": {}, "python3": {"minimum": self.plan.get("python_minimum", "3.10")}}
            requirement_source = "legacy conservative"
        else:
            tools = self.plan["tools"]
            required = tools.get(self.name) if isinstance(tools, dict) else None
            if not isinstance(required, dict) or not required:
                required = {"errors": ["qualification plan has no tool requirements for " + self.name]}
            requirement_source = "staged plan"
        started = time.monotonic()
        observed, failures = probe_tools(required, env)
        if self.name == "windows" and "go" in observed:
            observed["go"]["source_identity"] = self.windows_sdk["source_identity"]
            observed["go"]["SourceGoStd"] = self.windows_sdk["source_identity"]["stdlib_sha256"]
            observed["go"]["receipt_path"] = self.windows_sdk["receipt_path"]
        lines = [name + " " + str(row.get("version") or row["status"]) + " at " + str(row.get("path", ""))
                 for name, row in sorted(observed.items())]
        lines.extend("FAIL  " + failure for failure in failures)
        checks.append({"name": "tools", "exit": 1 if failures else 0, "seconds": round(time.monotonic() - started, 3),
                       "log": self.note("tool versions", "\n".join(lines) + "\n"),
                       "required": required, "observed": observed, "requirement_source": requirement_source})
        return checks

    # -- module --
    def module(self, job, job_dir, env):
        steps = []
        workspace = job_dir / "w"
        result = self.clone(job["repo"], workspace / job["repo"], env)
        steps.append(dict(result, name="checkout " + job["repo"]))
        if result["exit"] != 0:
            return steps
        directory = workspace / job["repo"] / job["subdir"] if job["subdir"] else workspace / job["repo"]
        if not (directory / "go.mod").is_file():
            steps.append({"name": "locate module", "exit": "missing", "seconds": 0,
                          "log": self.note("missing " + job["module"], "no go.mod at " + str(directory) + " in the checkout\n")})
            return steps
        if self.go_build_cache:
            if self.go_cache is None:
                self.go_cache = native_go_cache(self.go_build_cache, env, self.name, "qualification",
                                               record=lambda value: self.note("Go compilation cache", json.dumps(value, indent=2) + "\n"))
            env = dict(env, GOCACHE=self.go_cache)
        module_steps, packages = run_module_gate(directory, env, job.get("timeout", 3600), job["module"],
                                                  self.execute, self.note)
        job["race_packages"] = packages
        steps.extend(module_steps)
        return steps

    def note(self, label, text):
        self.counter += 1
        name = "%03d-%s.txt" % (self.counter, re.sub(r"[^A-Za-z0-9._-]+", "_", label)[:80])
        self.declare_log('logs/' + name)
        (self.logs / name).write_text(text, encoding="utf-8")
        return "logs/" + name

    # -- workflow --
    def preserve_windows_sdk(self, step, job, workspace, runner_temp, env, context):
        """Retain the reviewed SDK upload's exact evidence locally, without a hosted upload."""
        with_ = step.get("with") or {}
        if self.name != "windows" or step.get("uses") != SDK_UPLOAD or \
                step.get("name") != "preserve Windows Go SDK source identity and smoke" or \
                step.get("if") != "always() && runner.os == 'Windows'" or \
                set(step) != {"name", "if", "uses", "with"} or \
                set(with_) != {"name", "path", "if-no-files-found"} or \
                with_.get("name") != SDK_UPLOAD_NAME or with_.get("if-no-files-found") != "error" or \
                tuple(str(with_.get("path", "")).splitlines()) != SDK_UPLOAD_PATHS:
            raise Unsupported("unreviewed Windows SDK proof-upload shape")
        sdk = windows_sdk_module()
        paths = [workspace / "windows-go-sdk-proof.json", runner_temp / "windows-go-smoke/named-pipe-race.log",
                 runner_temp / "windows-go-smoke/smoke-receipt.json"]
        try:
            for path in paths:
                sdk._unlinked(path)
                if not path.is_file():
                    raise ValueError("missing SDK evidence " + str(path))
            raw = [path.read_bytes() for path in paths]
            proof, smoke = json.loads(raw[0]), json.loads(raw[2])
            receipt = sdk.validate_sdk_receipt(proof["receipt"])
            linked = Path(env["OA_WINDOWS_GO_SDK_RECEIPT"])
            sdk._unlinked(linked)
            if json.loads(linked.read_bytes()) != receipt or Path(receipt["receipt_path"]) != linked:
                raise ValueError("SDK proof differs from selected receipt")
            expected_argv = [receipt["go"], "test", "-overlay=" + str(runner_temp / "windows-go-smoke/overlay.json"),
                             "-race", "-count=1", "-timeout=60s", "-run=^TestNamedPipeConcurrentReadWrite$", "os"]
            if proof["smoke"] != smoke or smoke["source_identity"] != receipt["source_identity"] or \
                    smoke["regression_sha256"] != sdk.REGRESSION_SHA256 or smoke["argv"] != expected_argv or \
                    Path(smoke["log"]) != paths[1] or smoke["log_sha256"] != hashlib.sha256(raw[1]).hexdigest() or \
                    type(smoke["exit"]) is not int or type(smoke["seconds"]) not in (int, float) or \
                    not 0 <= smoke["seconds"] < float("inf"):
                raise ValueError("SDK smoke evidence differs from its owning invocation")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            raise Unsupported("Windows SDK evidence refused: " + str(error)) from error
        # A local leg has one workflow attempt. This namespace is not a GitHub run identifier.
        name = substitute(with_["name"], context)
        target = self.results / "artifacts" / ("%03d-" % (self.counter + 1) + re.sub(r"[^A-Za-z0-9._-]+", "_", job["id"]))
        sdk._unlinked(target)
        target.mkdir(parents=True, exist_ok=False)
        files = []
        for path, data in zip(paths, raw):
            destination = target / path.name
            destination.write_bytes(data)
            files.append({"path": path.name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        manifest = {"kind": "local-sdk-proof-retention", "name": name, "local_workflow_attempt": 1,
                    "source": self.plan["source"], "repository": job["repo"],
                    "plan_sha256": hashlib.sha256(json.dumps(self.plan, sort_keys=True).encode()).hexdigest(),
                    "commit": self.plan["repos"][job["repo"]]["commit"], "job": job["id"],
                    "step_sha256": hashlib.sha256(json.dumps(step, sort_keys=True).encode()).hexdigest(),
                    "source_identity": receipt["source_identity"], "smoke_exit": smoke["exit"], "files": files}
        (target / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return {"exit": 0, "seconds": 0, "evidence": target.relative_to(self.results).as_posix(),
                "log": self.note("retained Windows SDK proof " + job["id"], json.dumps(manifest, sort_keys=True) + "\n")}

    def workflow(self, job, job_dir, env):
        steps, outputs = [], {}
        workspace = job_dir / "w"
        runner_temp = job_dir / "t"
        workspace.mkdir(parents=True, exist_ok=True)
        runner_temp.mkdir(parents=True, exist_ok=True)
        org_repo = self.plan["org"] + "/" + job["repo"]
        commit = self.plan["repos"][job["repo"]]["commit"]
        summary = job_dir / "summary.md"
        summary.write_text("", encoding="utf-8")
        github = {"sha": commit, "repository": org_repo, "workspace": workspace.as_posix(), "event_name": self.github_context(job["repo"])["event_name"],
                  "ref": self.github_context(job["repo"])["ref"], "ref_name": self.github_context(job["repo"])["ref_name"], "workflow": job["workflow_name"], "job": job["job"],
                  "server_url": "https://github.com", "repository_owner": self.plan["org"], "run_attempt": "1",
                  "event": {"repository": {"name": job["repo"], "full_name": org_repo}}}
        runner = {"os": RUNNER_OS[self.name], "arch": "ARM64" if host_platform.machine().lower() in ("arm64", "aarch64") else "X64",
                  "temp": runner_temp.as_posix()}
        job_env = dict(env)
        # Workflow scripts can build external C libraries invisible to Go's action keys.
        # Their mutable native inputs keep the existing current-leg cache.
        if self.go_build_cache:
            job_env["GOCACHE"] = str(self.work / "gocache")
        job_env.update(CI="true", GITHUB_ACTIONS="true", GITHUB_SHA=commit, GITHUB_REPOSITORY=org_repo,
                       GITHUB_WORKSPACE=str(workspace), GITHUB_STEP_SUMMARY=str(summary), GITHUB_REF=github["ref"],
                       GITHUB_EVENT_NAME=github["event_name"], GITHUB_JOB=job["job"], GITHUB_RUN_ATTEMPT="1", RUNNER_OS=runner["os"], RUNNER_ARCH=runner["arch"],
                       RUNNER_TEMP=str(runner_temp))
        status = "success"
        context = {"github": github, "runner": runner, "matrix": job.get("matrix", {}), "steps": outputs, "env": {},
                   "secrets": {}, "inputs": {}, "__status": status}
        declared = {}
        for scope in (job.get("workflow_env") or {}, job.get("env") or {}):
            for key, value in scope.items():
                declared[key] = substitute(str(value), context)
        job_env.update(declared)
        context["env"] = dict(declared)
        for number, step in enumerate(job["steps"], 1):
            context["__status"] = status
            label = step.get("name") or step.get("uses") or "step " + str(number)
            try:
                if not condition(step.get("if"), context):
                    steps.append({"name": label, "exit": None, "status": "skipped", "seconds": 0})
                    continue
                step_env = dict(job_env)
                for key, value in (step.get("env") or {}).items():
                    step_env[key] = substitute(str(value), context)
                uses = step.get("uses")
                if uses:
                    action = uses.split("@", 1)[0]
                    with_ = {k: substitute(str(v), context) for k, v in (step.get("with") or {}).items()}
                    if action == "actions/checkout":
                        repository = with_.get("repository") or org_repo
                        owner, _, name = repository.partition("/")
                        if owner != self.plan["org"]:
                            raise Unsupported("checkout of " + repository + " outside " + self.plan["org"])
                        target = workspace / with_["path"] if with_.get("path") else workspace
                        result = self.clone(name, target, step_env)
                    elif action == "actions/setup-go":
                        result = self.execute(["go", "version"], workspace, step_env, 60, "setup-go uses local go")
                    elif action == "actions/upload-artifact":
                        result = self.preserve_windows_sdk(step, job, workspace, runner_temp, step_env, context)
                    else:
                        raise Unsupported("action " + action)
                else:
                    script = substitute(step["run"], context)
                    shell_name = step.get("shell") or job.get("shell") or "bash"
                    if shell_name != "bash":
                        raise Unsupported("shell " + shell_name)
                    workdir = substitute(step.get("working-directory") or job.get("working-directory") or "", context)
                    cwd = workspace / workdir if workdir else workspace
                    output_file = job_dir / ("output-%d" % number)
                    env_file = job_dir / ("env-%d" % number)
                    path_file = job_dir / ("path-%d" % number)
                    for f in (output_file, env_file, path_file):
                        f.write_text("", encoding="utf-8")
                    step_env.update(GITHUB_OUTPUT=str(output_file), GITHUB_ENV=str(env_file), GITHUB_PATH=str(path_file))
                    script_file = job_dir / ("step-%d.sh" % number)
                    write_lf(script_file, script)
                    if not cwd.is_dir():
                        raise Unsupported("working-directory " + workdir + " does not exist")
                    result = self.execute([bash(), "--noprofile", "--norc", "-eo", "pipefail", str(script_file)], cwd, step_env,
                                          job.get("timeout", 3600), job["id"] + " " + label, script)
                    if step.get("id"):
                        outputs[step["id"]] = {"outputs": read_pairs(output_file), "outcome": "success" if result["exit"] == 0 else "failure"}
                    job_env.update(read_pairs(env_file))
                    added = [line.strip() for line in path_file.read_text(encoding="utf-8").splitlines() if line.strip()]
                    if added:
                        job_env["PATH"] = os.pathsep.join(added + [job_env["PATH"]])
            except Unsupported as problem:
                result = {"exit": "unsupported", "seconds": 0, "log": self.note("unsupported " + label, str(problem) + "\n")}
            steps.append(dict(result, name=label))
            if result["exit"] != 0:
                status = "failure"
        return steps

    def run(self):
        self.prepare()
        started = time.time()
        host = {"platform": host_platform.platform(), "machine": host_platform.machine(), "python": sys.version.split()[0]}
        try:
            host["go"] = subprocess.run(["go", "version"], stdout=subprocess.PIPE, env=self.base_env(self.work), timeout=60).stdout.decode().strip()
        except (OSError, subprocess.SubprocessError) as error:
            host["go"] = "unavailable: " + str(error)
        jobs = []
        self.log("preflight")
        checks = self.preflight(None)
        jobs.append({"id": "preflight", "kind": "preflight", "steps": checks,
                     "status": "pass" if all(c["exit"] == 0 for c in checks) else "fail"})
        preflight_passed = jobs[-1]["status"] == "pass"
        self.log(("ok    " if jobs[-1]["status"] == "pass" else "FAIL  ") + "preflight")
        passed = {}
        for index, job in enumerate(self.plan["jobs"], 1):
            if self.name not in job["platforms"]:
                continue
            job_dir = self.work / "jobs" / str(index)
            remove_tree(job_dir)
            job_dir.mkdir(parents=True)
            env = self.base_env(job_dir)
            record = {"id": job["id"], "kind": job["kind"], "repo": job["repo"]}
            started_job = time.time()
            needs = job.get("needs") or []
            if not preflight_passed:
                record.update(status="skipped", steps=[], reason="preflight failed")
            elif job["kind"] == "workflow" and needs and not re.search(r"\balways\s*\(", str(job.get("if") or "")) \
                    and not all(passed.get((job["repo"], job["workflow"], n), True) for n in needs):
                record.update(status="skipped", steps=[], reason="a needed job failed")
            else:
                try:
                    if job["kind"] == "workflow" and job.get("if") is not None:
                        context = {"github": self.github_context(job["repo"]),
                                   "matrix": job.get("matrix", {}), "runner": {"os": RUNNER_OS[self.name]}, "__status": "success"}
                        if not condition(job["if"], context):
                            record.update(status="skipped", steps=[], reason="if: " + str(job["if"]))
                    if "status" not in record:
                        steps = self.module(job, job_dir, env) if job["kind"] == "module" else self.workflow(job, job_dir, env)
                        record.update(steps=steps, status="pass" if all(s["exit"] in (0, None) for s in steps) else "fail")
                        if job.get("race_packages") is not None:
                            record["race_packages"] = job["race_packages"]
                except Unsupported as problem:
                    record.update(status="fail", steps=[{"name": "plan", "exit": "unsupported", "seconds": 0,
                                                         "log": self.note("unsupported " + job["id"], str(problem) + "\n")}])
            if job["kind"] == "workflow":
                passed[(job["repo"], job["workflow"], job["job"])] = passed.get((job["repo"], job["workflow"], job["job"]), True) and record["status"] != "fail"
                summary = job_dir / "summary.md"
                if summary.is_file() and summary.stat().st_size:
                    record["summary"] = self.note("summary " + job["id"], summary.read_text(encoding="utf-8", errors="replace"))
            record["seconds"] = round(time.time() - started_job, 1)
            jobs.append(record)
            self.log({"pass": "ok    ", "fail": "FAIL  ", "skipped": "skip  "}[record["status"]] + job["id"] + " (" + str(record["seconds"]) + " s)")
            remove_tree(job_dir)
        failed = [j["id"] for j in jobs if j["status"] == "fail"]
        if self.name == "windows":
            windows_sdk_module().validate_sdk_receipt(self.windows_sdk)
            host["windows_go_sdk"] = self.windows_sdk
        results = {"platform": self.name, "source": self.plan["source"], "host": host, "status": "fail" if failed else "pass",
                   "failed": failed, "jobs": jobs, "seconds": round(time.time() - started, 1)}
        self.write_results(results)
        self.log(("PASS " if not failed else "FAIL ") + str(len(jobs) - len(failed)) + "/" + str(len(jobs)) + " jobs in " + str(results["seconds"]) + " s")
        return 0 if not failed else 1

    def write_results(self, results):
        # All execute/note streams have closed before this existing terminal
        # writer records their original bytes. Historical results stay intact.
        if (self.results / 'results.json').exists() and self.output_marker is None:
            raise Unsupported('terminal results already exist; original evidence cannot be repinned')
        seen = set()
        for job in results['jobs']:
            rows = [step for step in job.get('steps', []) if step.get('log')]
            if job.get('summary'):
                rows.append({'log': job['summary']})
            for row in rows:
                path = result_log_path(self.results, row['log'])
                identity = (path.stat().st_dev, path.stat().st_ino)
                if identity in seen:
                    raise Unsupported('duplicate result log identity')
                seen.add(identity)
                raw = path.read_bytes()
                row['log_sha256'], row['log_bytes'] = hashlib.sha256(raw).hexdigest(), len(raw)
                if row not in job.get('steps', []):
                    job['summary_log'] = row
        results['log_evidence'] = 1
        results['workflow_context'] = execution_context(self.plan)
        results['output_roster'] = {'invocation_id': self.output_invocation, 'complete': False,
                                  'work_root': str(self.work), 'logs': list(self.output_logs)}
        self.publish_output(results)
        # A terminal record can never be replaced by this writer again.
        self.output_marker = None
        self.output_marker_identity = None


def read_pairs(path):
    """name=value lines and name<<DELIMITER blocks, as runners read GITHUB_OUTPUT and GITHUB_ENV."""
    pairs, lines = {}, path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    i = 0
    while i < len(lines):
        line = lines[i]
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            name, delimiter = line.split("<<", 1)
            block, i = [], i + 1
            while i < len(lines) and lines[i] != delimiter:
                block.append(lines[i])
                i += 1
            pairs[name] = "\n".join(block)
        elif "=" in line:
            name, value = line.split("=", 1)
            pairs[name] = value
        i += 1
    return pairs


def concurrent_packages(listing):
    """Import paths whose Go, cgo or test files start a goroutine or import sync."""
    found = []
    for line in listing.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        path, directory, files = parts
        for name in filter(None, files.split(",")):
            try:
                text = Path(directory, name).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if CONCURRENT.search(text):
                found.append(path)
                break
    return found


def module_gate_commands(module=None):
    """Commands shared by staged qualification and local module checks."""
    test = ["go", "test", "-v", "-count=1", "./..."]
    if module == "github.com/openabstractions/abstractions/serve":
        test[-1:-1] = ["-timeout=" + SERVE_TEST_TIMEOUT]
    return (["go", "build", "./..."], test,
            ["go", "list", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \",\"}},{{join .CgoFiles \",\"}},{{join .TestGoFiles \",\"}},{{join .XTestGoFiles \",\"}}", "./..."])


def module_race_command(module, packages):
    timeout = ["-timeout=" + SERVE_TEST_TIMEOUT] if module == "github.com/openabstractions/abstractions/serve" else []
    return ["go", "test", "-race", "-v", "-count=1", *timeout, *packages]


def run_module_gate(directory, env, timeout, module, execute, note):
    """Run the staged module gate; execute and note retain caller-owned logs."""
    env = dict(env, GOWORK="off", GOFLAGS="-mod=readonly")
    build, test, listing_command = module_gate_commands(module)
    steps = []
    for label, args in (("build", build), ("test", test)):
        result = execute(args, directory, env, timeout, module + " " + label)
        # Evidence names are stable reuse keys; verbosity belongs to argv/logs.
        name = "go build ./..." if label == "build" else "go test -count=1 ./..."
        steps.append(dict(result, name=name, command=args))
    started = time.monotonic()
    try:
        listing = subprocess.run(listing_command, cwd=str(directory), env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=min(timeout, 600))
    except (OSError, subprocess.TimeoutExpired) as error:
        steps.append({"name": "go list for -race", "command": listing_command, "exit": "timeout" if isinstance(error, subprocess.TimeoutExpired) else "unavailable",
                      "seconds": round(time.monotonic() - started, 3), "log": note("race list " + module, str(error) + "\n")})
        return steps, []
    if listing.returncode != 0:
        steps.append({"name": "go list for -race", "command": listing_command, "exit": listing.returncode,
                      "seconds": round(time.monotonic() - started, 3),
                      "log": note("race list " + module, listing.stdout.decode(errors="replace"))})
        return steps, []
    steps.append({"name": "go list for -race", "command": listing_command, "exit": 0,
                  "seconds": round(time.monotonic() - started, 3),
                  "log": note("race list " + module, listing.stdout.decode(errors="replace"))})
    packages = concurrent_packages(listing.stdout.decode(errors="replace"))
    if packages:
        args = module_race_command(module, packages)
        result = execute(args, directory, env, timeout, module + " race")
        steps.append(dict(result, name="go test -race -count=1 (" + str(len(packages)) + " concurrent packages)", command=args))
    return steps, packages


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")
    run = sub.add_parser("run", help="run every job of the bundle's plan for one platform")
    run.add_argument("--bundle", required=True)
    run.add_argument("--work", required=True)
    run.add_argument("--platform", required=True, choices=PLATFORMS)
    run.add_argument("--path-prefix", default="", help="directories put ahead of PATH, joined by the host's path separator")
    run.add_argument("--go-build-cache", help="owned persistent Go compilation cache root; module and test execution stay isolated")
    run.add_argument("--output-invocation", help="private parent-owned output declaration identity")
    args = parser.parse_args(argv)
    if args.command != "run":
        parser.print_help()
        return 0
    try:
        leg = Leg(args.bundle, args.work, args.platform, args.path_prefix, args.go_build_cache, args.output_invocation)
    except (OSError, ValueError, KeyError) as error:
        print("REFUSED: cannot read the bundle: " + str(error), file=sys.stderr)
        return 2
    try:
        return leg.run()
    except (OSError, ValueError, KeyError) as error:
        print("REFUSED: platform SDK/input verification failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
