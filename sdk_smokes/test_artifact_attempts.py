import unittest

from artifact_attempts import PRODUCERS, select


class ArtifactAttempts(unittest.TestCase):
    def inputs(self, attempt=1):
        source = 'a' * 40
        jobs = [dict(name=name, run_id=73, run_attempt=attempt, head_sha=source,
                     status='completed', conclusion='success') for name, _ in PRODUCERS.values()]
        artifacts = [dict(name=prefix + str(attempt), id=index + 100, expired=False,
                          digest='sha256:' + str(index) * 64,
                          workflow_run=dict(id=73, head_sha=source))
                     for index, (_, prefix) in enumerate(PRODUCERS.values())]
        return jobs, artifacts

    def test_local_provenance_still_requires_same_run_language_artifacts(self):
        source = "a" * 40
        roles = [key for key in PRODUCERS if key != "SDK_PROVENANCE_ARTIFACT"]
        jobs, artifacts = self.inputs(2)
        jobs.pop(); artifacts.pop()
        self.assertEqual(set(select(jobs, artifacts, source, 73, 2, local_provenance=True)), set(roles))
        with self.assertRaisesRegex(ValueError, "missing producing job"):
            select(jobs, artifacts, source, 73, 2)
        artifacts[0]["workflow_run"]["id"] = 74
        with self.assertRaisesRegex(ValueError, "mismatched producer artifact"):
            select(jobs, artifacts, source, 73, 2, local_provenance=True)

    def test_successful_producer_attempt_survives_verify_retry(self):
        source = "a" * 40
        jobs, artifacts = self.inputs()
        chosen = select(jobs, artifacts, source, 73, 2)
        self.assertEqual(set(chosen.values()), {prefix + "1" for _, prefix in PRODUCERS.values()})

        jobs[0] = dict(jobs[0], run_attempt=2, conclusion="failure")
        with self.assertRaisesRegex(ValueError, "unsuccessful"):
            select(jobs, artifacts, source, 73, 2)

    def test_wrong_source_artifact_is_refused(self):
        source = "a" * 40
        jobs, artifacts = self.inputs()
        artifacts[0]['workflow_run']['head_sha'] = 'b' * 40
        with self.assertRaisesRegex(ValueError, "mismatched"):
            select(jobs, artifacts, source, 73, 1)

    def test_latest_successful_retained_attempt_wins_after_later_reruns(self):
        jobs, artifacts = self.inputs()
        newer, newer_artifacts = self.inputs(2)
        expected = {prefix + '1' for _, prefix in PRODUCERS.values()}
        for conclusion in ('skipped', 'failure', 'cancelled', 'success'):
            with self.subTest(conclusion=conclusion):
                later = [dict(job, conclusion=conclusion) for job in newer]
                self.assertEqual(set(select(jobs + later, artifacts, 'a' * 40, 73, 3).values()), expected)
        expired = [dict(row, expired=True) for row in newer_artifacts]
        self.assertEqual(set(select(jobs + newer, artifacts + expired, 'a' * 40, 73, 3).values()), expected)
        chosen = select(jobs + newer, artifacts + newer_artifacts, 'a' * 40, 73, 3)
        self.assertEqual(set(chosen.values()), {prefix + '2' for _, prefix in PRODUCERS.values()})

    def test_retained_artifact_identity_and_ambiguity_remain_closed(self):
        for field, value in (('id', 0), ('id', True), ('digest', None), ('digest', 'sha256:' + 'z' * 64),
                             ('workflow_run', dict(id=74, head_sha='a' * 40))):
            jobs, artifacts = self.inputs()
            artifacts[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'mismatched'):
                select(jobs, artifacts, 'a' * 40, 73, 2)
        jobs, artifacts = self.inputs()
        for duplicate_jobs, duplicate_artifacts in ((jobs + [jobs[0]], artifacts),
                                                    (jobs, artifacts + [artifacts[0]])):
            with self.assertRaisesRegex(ValueError, 'mismatched'):
                select(duplicate_jobs, duplicate_artifacts, 'a' * 40, 73, 2)
        with self.assertRaisesRegex(ValueError, 'invalid producing job attempt'):
            select(jobs + [dict(jobs[0], run_attempt=3)], artifacts, 'a' * 40, 73, 2)
        jobs[0]['run_id'] = 74
        with self.assertRaisesRegex(ValueError, 'unsuccessful'):
            select(jobs, artifacts, 'a' * 40, 73, 2)

    def test_producers_beyond_first_api_page_are_selected(self):
        jobs, artifacts = self.inputs()
        # The workflow's paginated API objects flatten all pages into these
        # same arrays. A large run must retain producers beyond page 1.
        jobs = [dict(name='unrelated-' + str(i)) for i in range(120)] + jobs
        artifacts = [dict(name='unrelated-' + str(i)) for i in range(120)] + artifacts
        self.assertEqual(len(select(jobs, artifacts, 'a' * 40, 73, 2)), len(PRODUCERS))


if __name__ == "__main__":
    unittest.main()
