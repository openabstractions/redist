"""Offline readiness checks for the Linux installer qualification fixture."""
import json
from types import SimpleNamespace
import unittest

from qualify_linux import DEFAULT_CONTRACTS, PROBE, Qualification


def status_report(contracts=DEFAULT_CONTRACTS, endpoint="/run/user/1000/abstraction/runtime.sock"):
    return {"capabilities": [
        {"capability": contract.split("/", 1)[0], "contract": contract, "status": "resolved",
         "result": {"status": "resolved", "reference": {"endpoint": endpoint}}}
        for contract in contracts
    ]}


def description(contracts=DEFAULT_CONTRACTS):
    return {"Outcome": "described", "Services": [
        {"Contract": contract, "Readiness": "ready", "Why": "", "Guarantees": [], "Capabilities": {}}
        for contract in contracts
    ]}


class FakeQualification(Qualification):
    def __init__(self, report=None, described=None):
        super().__init__(SimpleNamespace(account="fixture"))
        self.report = status_report() if report is None else report
        self.described = description() if described is None else described
        self.calls = []

    def user(self, argv, timeout=60, check=True, extra=None):
        self.calls.append((list(argv), timeout))
        value = self.described if argv[1:3] == ["status", "describe"] else self.report
        return SimpleNamespace(returncode=0, stdout=json.dumps(value) + "\n", stderr="")

    def wait(self, predicate, seconds, interval=0.2):
        return predicate()


class InstallerDescribeReadiness(unittest.TestCase):
    def test_probe_uses_scope_enum_for_every_facade_call(self):
        self.assertEqual(PROBE.count("scope=Scope.LOCAL"), 3)
        self.assertNotIn('scope="local"', PROBE)

    def test_describe_runs_once_after_resolved_status(self):
        fixture = FakeQualification()
        ready, detail = fixture.ready_status(20)
        self.assertTrue(ready, detail)
        self.assertEqual(detail["described"], {contract: "ready" for contract in DEFAULT_CONTRACTS})
        self.assertEqual([call[0][1:3] for call in fixture.calls],
                         [["status", "--json"], ["status", "describe"]])
        self.assertEqual(fixture.calls[1][1], 10)

    def test_missing_or_duplicate_status_contract_never_reaches_describe(self):
        for contracts in (DEFAULT_CONTRACTS[:-1], DEFAULT_CONTRACTS + (DEFAULT_CONTRACTS[0],)):
            with self.subTest(contracts=contracts):
                fixture = FakeQualification(report=status_report(contracts))
                ready, _ = fixture.ready_status(20)
                self.assertFalse(ready)
                self.assertEqual(len(fixture.calls), 1)

    def test_missing_or_not_ready_described_contract_fails(self):
        for changed in ("missing", "not_ready"):
            with self.subTest(changed=changed):
                body = description()
                if changed == "missing":
                    body["Services"].pop()
                else:
                    body["Services"][-1]["Readiness"] = "not_ready"
                    body["Services"][-1]["Why"] = "journal unavailable"
                fixture = FakeQualification(described=body)
                ready, detail = fixture.ready_status(20)
                self.assertFalse(ready)
                self.assertEqual(detail["contract"], DEFAULT_CONTRACTS[-1])
                self.assertEqual(len(fixture.calls), 2)


if __name__ == "__main__":
    unittest.main()
