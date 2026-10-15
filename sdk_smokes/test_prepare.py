"""Pinned SDK sources come from the exact installed service module graph."""
import json
from pathlib import Path
import tempfile
import unittest

import prepare


SERVE = prepare.SERVICE_MODULE
IDENTITY = prepare.MODULES["abstraction-identity"]
FACADE = prepare.MODULES["abstraction-facade"]
CONFIG = prepare.MODULES["abstraction-config"]
CORE = prepare.GO_CORE


def row(path, version, commit="a" * 40):
    return {"path": path, "version": version, "expected_commit": commit,
            "origin_hash": commit, "repository": "https://github.com/openabstractions/example",
            "tag": version}


def fixture():
    service = row(SERVE, "v0.3.0")
    selected = [service, row(IDENTITY, "v0.4.2"), row(FACADE, "v0.6.1"),
                row(CONFIG, "v0.5.0"), row(CORE, "v0.3.0"),
                {"path": "github.com/openabstractions/websocket",
                 "version": "v0.0.0-20260926143434-ce87d3641bd1",
                 "expected_commit": "ce87d3641bd1e04e7acfd4a848d193951d5da73f"}]
    return {"schema": 1, "modules": [
        {"input": {"path": "github.com/openabstractions/abstraction-provider-modelhost/go",
                   "version": "v0.1.0"}, "selected": [row(IDENTITY, "v0.4.0")]},
        {"input": {"path": SERVE, "version": "v0.3.0", "expected_commit": service["expected_commit"]},
         "selected": selected}]}


class SDKPrepare(unittest.TestCase):
    def check(self, evidence, tools_version="v0.3.0"):
        with tempfile.TemporaryDirectory(prefix="oa-sdk-pins-") as folder:
            directory = Path(folder)
            record = directory / "module-provenance.json"
            record.write_text(json.dumps(evidence), encoding="utf-8")
            tools = directory / "tools.tsv"
            tools.write_text("path\tmodule\tpackage\tfeature\tsubsystem\n" +
                             "".join(f"{program}\t{SERVE}@{tools_version}\t.\tservice\twindows\n"
                                     for program in sorted(prepare.SERVICE_PROGRAMS)), encoding="utf-8")
            return prepare.provenance_rows(record, tools)

    def test_uses_service_graph_with_independent_older_identity_graph(self):
        rows = self.check(fixture())
        self.assertEqual(rows[IDENTITY]["version"], "v0.4.2")
        self.assertEqual(rows[FACADE]["version"], "v0.6.1")
        self.assertEqual(rows[CONFIG]["version"], "v0.5.0")
        self.assertEqual(rows[CORE]["version"], "v0.3.0")
        self.assertIn("github.com/openabstractions/websocket", rows)

    def test_wrong_installed_service_version_refuses(self):
        with self.assertRaisesRegex(RuntimeError, "exact installed service graph"):
            self.check(fixture(), tools_version="v0.3.1")

    def test_duplicate_service_graph_refuses(self):
        evidence = fixture()
        evidence["modules"].append(evidence["modules"][-1])
        with self.assertRaisesRegex(RuntimeError, "exact installed service graph"):
            self.check(evidence)

    def test_duplicate_module_inside_service_graph_refuses(self):
        evidence = fixture()
        evidence["modules"][-1]["selected"].append(row(IDENTITY, "v0.4.0"))
        with self.assertRaisesRegex(RuntimeError, "duplicate module"):
            self.check(evidence)

    def test_service_row_contradiction_refuses(self):
        evidence = fixture()
        evidence["modules"][-1]["selected"][0]["expected_commit"] = "b" * 40
        with self.assertRaisesRegex(RuntimeError, "contradicts"):
            self.check(evidence)

    def test_missing_sdk_source_tag_refuses(self):
        evidence = fixture()
        evidence["modules"][-1]["selected"][2].pop("tag")
        with self.assertRaisesRegex(RuntimeError, "verified published tag"):
            self.check(evidence)

    def test_composed_go_sdk_keeps_verified_service_versions(self):
        rows = self.check(fixture())
        graph = "\n".join(f"{path}@{rows[path]['version']}"
                          for path in set(prepare.MODULES.values()) | {CORE})
        prepare.check_go_selection(graph, rows)
        with self.assertRaisesRegex(RuntimeError, "composed Go SDK selects"):
            prepare.check_go_selection(graph.replace(f"{IDENTITY}@v0.4.2", f"{IDENTITY}@v0.4.0"), rows)


if __name__ == "__main__":
    unittest.main()
