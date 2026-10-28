"""Pinned SDK sources come from the exact installed service module graph."""
import json
from pathlib import Path
import tempfile
import unittest
import copy
import os
from unittest.mock import patch

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
                row(prepare.MODULES['abstraction-inference'], 'v0.8.0'),
                row(prepare.MODULES['abstraction-router'], 'v0.8.0'),
                {"path": "github.com/openabstractions/websocket",
                 "version": "v0.0.0-20260926143434-ce87d3641bd1",
                 "expected_commit": "ce87d3641bd1e04e7acfd4a848d193951d5da73f"}]
    return {"schema": 1, "modules": [
        {"input": {"path": "github.com/openabstractions/abstraction-provider-modelhost/go",
                   "version": "v0.1.0"}, "selected": [row(IDENTITY, "v0.4.0")]},
        {"input": {"path": SERVE, "version": "v0.3.0", "expected_commit": service["expected_commit"]},
         "selected": selected}]}


class SDKPrepare(unittest.TestCase):
    def test_projection_scanner_distinguishes_generated_go_files_from_missing_inputs(self):
        import ast
        scanner = Path(__file__).resolve().parents[2] / 'scripts' / 'oa.py'
        if not scanner.is_file():
            self.skipTest('organization projection scanner is private input; private gate runs this check')
        source = scanner.read_text(encoding='utf-8')
        tree = ast.parse(source)
        nodes = [node for node in tree.body
                 if (isinstance(node, ast.FunctionDef) and node.name in
                     ('fixture_reads', 'path_suffixes', 'published_test', 'unpublished_fixtures_in'))
                 or (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name)
                     and t.id in ('FIXTURE_PATH', 'FIXTURE_READS') for t in node.targets))]
        import re
        namespace = {'re': re}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(scanner), 'exec'), namespace)
        go_mod = '/'.join(('go', 'go.mod'))
        go_main = '/'.join(('go', 'main.go'))
        missing = '/'.join(('required', 'missing.json'))
        generated = f'''with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    (root / "{go_mod}").read_text()
    (root / "{go_main}").read_bytes()
    Path("{missing}").read_text()
'''
        self.assertEqual(namespace['fixture_reads'](generated), {'required/missing.json'})
        with tempfile.TemporaryDirectory() as private:
            required = Path(private) / missing
            required.parent.mkdir()
            required.write_bytes(b'actual private input')
            findings = namespace['unpublished_fixtures_in'](
                'fixture', ['test_generated.py'], lambda _: generated,
                namespace['path_suffixes']([required.relative_to(private).as_posix()]))
            for note in ('', '\u03a9' * 4, '\u03a9' * 12, '\u03a9' * 40, '\U0001f9ea' * 12):
                with self.subTest(same_line_prefix=note):
                    same_line = ('with tempfile.TemporaryDirectory() as temporary:\n'
                                 '    root = Path(temporary)\n'
                                 f'    note = {note!r}; (root / {go_main!r}).read_text(); '
                                 f'Path({missing!r}).read_text()\n')
                    self.assertEqual(namespace['fixture_reads'](same_line), {missing})
                    actual = namespace['unpublished_fixtures_in'](
                        'fixture', ['test_generated.py'], lambda _: same_line,
                        namespace['path_suffixes']([required.relative_to(private).as_posix()]))
                    self.assertEqual(len(actual), 1)
                    self.assertIn(missing, actual[0])
        self.assertEqual(len(findings), 1)
        self.assertIn(missing, findings[0])
        self.assertEqual(namespace['fixture_reads'](generated.replace('Path(temporary)', 'Path("repository")')),
                         {'go/go.mod', 'go/main.go', 'required/missing.json'})
        reassigned = generated.replace('    (root /', '    root = Path("repository")\n    (root /', 1)
        self.assertIn('go/go.mod', namespace['fixture_reads'](reassigned))
        before_assignment = generated.replace('    root = Path(temporary)\n', '')
        before_assignment += '    root = Path(temporary)\n'
        self.assertIn(go_mod, namespace['fixture_reads'](before_assignment))
        rebound_temporary = generated.replace('    root = Path(temporary)',
                                             '    temporary = "repository"\n    root = Path(temporary)')
        self.assertIn(go_mod, namespace['fixture_reads'](rebound_temporary))
        actual_reads = namespace['fixture_reads'](Path(__file__).read_text(encoding='utf-8'))
        self.assertNotIn(go_mod, actual_reads)
        self.assertNotIn(go_main, actual_reads)

    def test_go_file_identity_adapter_selects_exact_candidate_owner(self):
        rows = self.check(fixture())
        selected = prepare.pins(rows)
        graph = "\n".join(f"{path}@{rows[path]['version']}"
                          for path in set(prepare.MODULES.values()) | {CORE})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(prepare, "checked") as checked, \
                    patch.object(prepare.subprocess, "check_output", return_value=graph):
                prepare.prepare_go(root / "out", selected, rows, root)
            go_mod = (root / "go/go.mod").read_text(encoding="utf-8")
            self.assertIn(f" {IDENTITY} v0.4.2\n", go_mod)
            self.assertIn(f" {FACADE} v0.6.1\n", go_mod)
            self.assertIn(f" {CORE} v0.3.0\n", go_mod)
            self.assertEqual((root / "go/main.go").read_bytes(), (prepare.HERE / "go_probe.go").read_bytes())
            self.assertEqual(checked.call_args_list[-1].args[:4],
                             ("go", "build", "-o", root / "out/go_probe.exe"))
            self.assertEqual(checked.call_args_list[-1].kwargs["env"]["GOWORK"], "off")
        selected = copy.deepcopy(selected)
        selected["abstraction-identity"]["version"] = "v0.4.0"
        with tempfile.TemporaryDirectory() as temporary, patch.object(prepare, "checked") as checked:
            with self.assertRaisesRegex(RuntimeError, "candidate identity pin"):
                prepare.prepare_go(Path(temporary)/"out", selected, rows, Path(temporary))
            checked.assert_not_called()

    def test_msvc_owner_exposes_same_selected_instance_and_existing_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program_files = root / 'program-files'
            vswhere = program_files / 'Microsoft Visual Studio/Installer/vswhere.exe'
            vswhere.parent.mkdir(parents=True)
            vswhere.write_bytes(b'inert selector')
            instance = root / 'vs-instance'
            cmake = instance / 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
            msbuild = instance / 'MSBuild/Current/Bin/MSBuild.exe'
            for tool in (cmake, msbuild):
                tool.parent.mkdir(parents=True, exist_ok=True)
                tool.write_bytes(b'inert tool')
            with patch.dict(os.environ, {'ProgramFiles(x86)': str(program_files)}), \
                    patch.object(prepare.subprocess, 'check_output', side_effect=[str(instance), '17.14.0']) as queried:
                selected = prepare.msvc_toolchain()
            self.assertEqual(selected, {'installation_path': instance, 'installation_version': '17.14.0',
                                         'cmake': cmake, 'msbuild': msbuild, 'generator': 'Visual Studio 17 2022'})
            self.assertEqual(queried.call_count, 2)
            with patch.object(prepare, 'msvc_toolchain', return_value=selected):
                self.assertEqual(prepare.msvc_cmake(), (cmake, selected['generator']))
            msbuild.unlink()
            with patch.dict(os.environ, {'ProgramFiles(x86)': str(program_files)}), \
                    patch.object(prepare.subprocess, 'check_output', side_effect=[str(instance), '17.14.0']):
                with self.assertRaisesRegex(RuntimeError, 'CMake/MSBuild'):
                    prepare.msvc_toolchain()

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
        self.assertEqual(rows[prepare.MODULES['abstraction-inference']]['version'], 'v0.8.0')
        self.assertEqual(rows[prepare.MODULES['abstraction-router']]['version'], 'v0.8.0')
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


class PreparedSDKPrepare(unittest.TestCase):
    def evidence(self):
        rows = []
        for module in sorted(set(prepare.MODULES.values()) | {CORE, SERVE}):
            rest = module.removeprefix('github.com/openabstractions/'); repo, _, subdir = rest.partition('/')
            rows.append(dict(module=module, version='v0.8.0', repository='https://github.com/openabstractions/' + repo,
                subdir=subdir, tag=(subdir + '/' if subdir else '') + 'v0.8.0', commit='a' * 40,
                sum='h1:' + 'A' * 43 + '=', gomodsum='h1:' + 'B' * 43 + '='))
        graph = dict(schema=2, kind='unpublished-go-graph', source='b' * 40, version='v0.8.0', modules=rows, dependencies=[], files=[])
        verified = dict(schema=1, source=graph['source'], version=graph['version'], modules=[{k:r[k] for k in ('module','version','sum','gomodsum','commit')} for r in rows])
        return dict(schema=2, kind='prepared-module-provenance', graph=graph, verification=verified,
            archive=dict(bytes=1234, sha256='c' * 64), producer=dict(source='d' * 40, run_id=17, run_attempt=2), publication_admitted=False)

    def files(self, root, evidence):
        record = root / 'provenance.json'; record.write_text(json.dumps(evidence))
        tools = root / 'tools.tsv'; tools.write_text('path\tmodule\tpackage\tfeature\tsubsystem\n' + ''.join(f'{program}\t{SERVE}@v0.8.0\t.\tservice\twindows\n' for program in sorted(prepare.SERVICE_PROGRAMS)))
        return record, tools

    def test_actual_sdk_entrypoint_uses_exact_prepared_commits_without_published_tags(self):
        evidence = self.evidence()
        with tempfile.TemporaryDirectory(prefix='oa-sdk-prepared-') as tmp:
            root = Path(tmp); record, tools = self.files(root, evidence)
            argv = ['prepare.py','--out',str(root/'out'),'--npm',str(root/'npm'),'--pypi',str(root/'pypi'),'--provenance',str(record),'--tools',str(tools)]
            with patch('sys.argv', argv), patch.dict(os.environ, {'GITHUB_SHA':'d'*40,'GITHUB_RUN_ID':'17','SDK_PROVENANCE_ARTIFACT':'module-provenance-Windows-2'}), \
                    patch.object(prepare, 'checked') as checked, patch.object(prepare.subprocess, 'check_output', return_value='a'*40+'\n'), patch.object(prepare, 'prepare_python'), patch.object(prepare, 'prepare_javascript'), \
                    patch.object(prepare, 'prepare_go'), patch.object(prepare, 'prepare_cpp'), patch.object(prepare, 'prepare_rust'), patch.object(prepare, 'copy_probe'), patch.object(prepare, 'hash_files'):
                prepare.main()
            selected = prepare.pins(prepare.provenance_rows(record,tools,expected_producer=evidence['producer']))
            checkouts = [call.args for call in checked.call_args_list if 'checkout' in call.args]
            self.assertEqual(len(checkouts),len(prepare.MODULES))
            self.assertTrue(all(call[-1]=='a'*40 for call in checkouts))
            self.assertFalse(any('tag' in call for call in checkouts))
            self.assertTrue(all(r['provenance_kind']=='prepared-public-commit' and 'tag' not in r for r in selected.values()))

    def test_prepared_sdk_refuses_wrong_attempt_missing_verification_or_published_relabel(self):
        original = self.evidence()
        variants = []
        value = copy.deepcopy(original); value['producer']['run_attempt']=3; variants.append(value)
        value = copy.deepcopy(original); value['verification']['modules'].pop(); variants.append(value)
        value = copy.deepcopy(original); value['kind']='published-module-provenance'; variants.append(value)
        value = copy.deepcopy(original); value['verification']['modules'][0]['sum']='h1:'+'C'*43+'='; variants.append(value)
        for value in variants:
            with self.subTest(value=value), tempfile.TemporaryDirectory(prefix='oa-sdk-prepared-refuse-') as tmp:
                record, tools = self.files(Path(tmp), value)
                with self.assertRaises(RuntimeError):
                    prepare.provenance_rows(record, tools, expected_producer=original['producer'])


if __name__ == "__main__":
    unittest.main()
