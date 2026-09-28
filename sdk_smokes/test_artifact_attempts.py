import unittest

from artifact_attempts import PRODUCERS, select


class ArtifactAttempts(unittest.TestCase):
    def test_successful_producer_attempt_survives_verify_retry(self):
        source = "a" * 40
        jobs = []
        artifacts = []
        for job_name, prefix in PRODUCERS.values():
            jobs.append({"name": job_name, "run_attempt": 1, "head_sha": source,
                         "status": "completed", "conclusion": "success"})
            artifacts.append({"name": prefix + "1", "expired": False,
                              "workflow_run": {"id": 73, "head_sha": source}})
        chosen = select(jobs, artifacts, source, 73, 2)
        self.assertEqual(set(chosen.values()), {prefix + "1" for _, prefix in PRODUCERS.values()})

        jobs[0] = dict(jobs[0], run_attempt=2, conclusion="failure")
        with self.assertRaisesRegex(ValueError, "unsuccessful"):
            select(jobs, artifacts, source, 73, 2)

    def test_wrong_source_artifact_is_refused(self):
        source = "a" * 40
        jobs = [{"name": name, "run_attempt": 1, "head_sha": source,
                 "status": "completed", "conclusion": "success"}
                for name, _ in PRODUCERS.values()]
        artifacts = [{"name": prefix + "1", "expired": False,
                      "workflow_run": {"id": 73, "head_sha": "b" * 40}}
                     for _, prefix in PRODUCERS.values()]
        with self.assertRaisesRegex(ValueError, "mismatched"):
            select(jobs, artifacts, source, 73, 1)


if __name__ == "__main__":
    unittest.main()
