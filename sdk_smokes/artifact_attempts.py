"""Choose the successful producer attempt for each installed SDK input."""

import argparse
import json
from pathlib import Path


PRODUCERS = {
    "SDK_NPM_ARTIFACT": ("javascript (win32-x64)", "abstraction-npm-win32-x64-"),
    "SDK_PYPI_ARTIFACT": ("python (win32-x64)", "abstraction-pypi-win32-x64-"),
    "SDK_PROVENANCE_ARTIFACT": ("windows", "module-provenance-Windows-"),
}


def select(jobs, artifacts, source, run_id, current_attempt):
    result = {}
    for variable, (job_name, prefix) in PRODUCERS.items():
        matching = [job for job in jobs if job.get("name") == job_name]
        if not matching or any(type(job.get("run_attempt")) is not int for job in matching):
            raise ValueError("missing producing job attempt: " + job_name)
        attempt = max(job["run_attempt"] for job in matching)
        latest = [job for job in matching if job["run_attempt"] == attempt]
        if (attempt > current_attempt or len(latest) != 1
                or latest[0].get("head_sha") != source
                or latest[0].get("status") != "completed"
                or latest[0].get("conclusion") != "success"):
            raise ValueError("ambiguous or unsuccessful producing job: " + job_name)
        name = prefix + str(attempt)
        found = [artifact for artifact in artifacts if artifact.get("name") == name]
        if (len(found) != 1 or found[0].get("expired") is not False
                or found[0].get("workflow_run", {}).get("id") != run_id
                or found[0].get("workflow_run", {}).get("head_sha") != source):
            raise ValueError("missing or mismatched producer artifact: " + name)
        result[variable] = name
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    parser.add_argument("--shell-env", type=Path, required=True)
    args = parser.parse_args()
    jobs = json.loads(args.jobs.read_text(encoding="utf-8"))["jobs"]
    artifacts = json.loads(args.artifacts.read_text(encoding="utf-8"))["artifacts"]
    names = select(jobs, artifacts, args.source, args.run_id, args.attempt)
    with args.github_env.open("a", encoding="utf-8") as output:
        for key, value in names.items():
            output.write(f"{key}={value}\n")
    args.shell_env.write_text("".join(f"{key}={value}\n" for key, value in names.items()), encoding="utf-8")


if __name__ == "__main__":
    main()
