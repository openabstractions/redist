"""Environment helpers for Git commands rooted at an explicit repository."""
import os


_REPOSITORY_OVERRIDES = {
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_REPLACE_REF_BASE",
    "GIT_GRAFT_FILE",
    "GIT_SHALLOW_FILE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_PREFIX",
}


def clean_git_environment(environment=None):
    """Drop ambient repository/index redirection while preserving auth/config."""
    source = os.environ if environment is None else environment
    return {key: value for key, value in source.items()
            if key.upper() not in _REPOSITORY_OVERRIDES}


def with_git_environment(environment=None, **overrides):
    result = clean_git_environment(environment)
    result.update(overrides)
    return result


def source_git_environment(environment=None):
    """Isolate fixed source reads/preparation from ambient Git execution config.

    Source owners pass this environment to every Git invocation. Fixed config
    entries override repository-local fsmonitor/hooks settings as well. Ordinary
    authenticated Git consumers retain clean_git_environment's existing policy.
    """
    result = {key: value for key, value in clean_git_environment(environment).items()
              if not key.upper().startswith('GIT_CONFIG')}
    result.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                  GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_COUNT='2',
                  GIT_CONFIG_KEY_0='core.fsmonitor', GIT_CONFIG_VALUE_0='false',
                  GIT_CONFIG_KEY_1='core.hooksPath', GIT_CONFIG_VALUE_1=os.devnull)
    return result


SOURCE_BASELINE_CONTEXT = 'OA_SOURCE_BASELINE_CONTEXT'


def source_baseline_ref(root, ref):
    """Receive one baseline from this source invocation's normal journal.

    This is baseline input plumbing, not a Git command override. Independent
    fixture repositories retain their own floors; another worktree in the same
    repository cannot impersonate the admitted source root.
    """
    import json
    import re
    import subprocess
    from pathlib import Path
    raw = os.environ.get(SOURCE_BASELINE_CONTEXT)
    if not raw:
        return ref
    context = json.loads(raw)
    if (not isinstance(context, dict) or set(context) != {'root', 'git_common_dir', 'journal', 'invocation_id'}
            or not all(isinstance(v, str) for v in context.values())
            or not re.fullmatch('[0-9a-f]{32}', context['invocation_id'])):
        raise ValueError('invalid source baseline context')
    if any(not Path(context[key]).is_absolute() for key in ('root','git_common_dir','journal')):
        raise ValueError('source baseline context paths are not absolute')
    root = Path(root).resolve()
    common = subprocess.check_output(['git', '-C', str(root), 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                                    env=source_git_environment(), text=True).strip()
    if Path(common).resolve() != Path(context['git_common_dir']).resolve():
        if root == Path(context['root']).resolve():
            raise ValueError('source baseline Git identity changed')
        return ref  # An independent test repository has no inherited source floor.
    if root != Path(context['root']).resolve():
        raise ValueError('source baseline context belongs to another worktree')
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    from release.metrics import _verified_local_receipt, receipt_root
    path = Path(context['journal'])
    primary = receipt_root(root).resolve()
    ordinary = path.parent.name == context['invocation_id'] and path.parent.parent.resolve() == primary
    nested = (path.parent.name == 'gate-'+context['invocation_id'] and path.parent.parent.parent.resolve() == primary
              and re.fullmatch('[0-9a-f]{32}',path.parent.parent.name))
    if path.name != 'check.json' or not (ordinary or nested):
        raise ValueError('source baseline journal is outside its invocation')
    # check.json and its digest are atomic files published in sequence.
    # Bound the read across that existing pair's brief publication window.
    from release.metrics import MetricsError
    import time
    for attempt in range(3):
        try:
            record = _verified_local_receipt(path)
            break
        except MetricsError:
            if attempt == 2: raise
            time.sleep(0.01)
    capture = record.get('baseline_capture')
    head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', '--verify', 'HEAD^{commit}'],
                                   env=source_git_environment(), text=True).strip()
    if (record.get('operation') != 'selected_gate' or record.get('status') != 'running'
            or record.get('invocation_id') != context['invocation_id'] or not isinstance(capture, dict)
            or capture.get('root') != str(root) or capture.get('git_common_dir') != str(Path(common).resolve())
            or capture.get('source') != head or record.get('source',{}).get('source_sha') != head
            or not isinstance(capture.get('refs'), dict)
            or set(capture) != {'root','git_common_dir','source','selection_base','refs'}):
        raise ValueError('source baseline journal binding differs')
    from release.testing.source_check import source_job_baselines, SOURCE_CHECK_RECEIPT
    if record.get('source_job_receipt') != os.environ.get(SOURCE_CHECK_RECEIPT) or source_job_baselines(root) != capture:
        raise ValueError('checker has no admitted source Job custody')
    refs = capture['refs']
    if any(not isinstance(k, str) or (v is not None and (not isinstance(v, str) or not re.fullmatch('[0-9a-f]{40}', v))) for k,v in refs.items()):
        raise ValueError('source baseline object binding differs')
    required={'origin/main','origin/next','refs/remotes/origin/main','refs/remotes/origin/next','refs/heads/main','HEAD',capture['selection_base']}
    if (set(refs)!=required or refs['HEAD']!=head or refs['origin/main']!=refs['refs/remotes/origin/main']
            or refs['origin/next']!=refs['refs/remotes/origin/next'] or refs[capture['selection_base']] is None):
        raise ValueError('source baseline roster differs')
    if ref not in refs:
        if not (isinstance(ref, str) and re.fullmatch('[0-9a-f]{40}', ref) and ref in refs.values()):
            raise ValueError('baseline was not admitted: ' + str(ref))
        value = ref
    else:
        value = refs[ref]
    if value is not None:
        kind = subprocess.check_output(['git', '-C', str(root), 'cat-file', '-t', value],
                                       env=source_git_environment(), text=True).strip()
        if kind != 'commit':
            raise ValueError('source baseline is not a commit')
    return value
