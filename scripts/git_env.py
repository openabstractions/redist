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
