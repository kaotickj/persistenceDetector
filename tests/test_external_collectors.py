import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import external_collectors as external


def row(name='Example'):
    return {'TaskPath': '\\Folder\\', 'TaskName': name, 'State': 'Ready', 'Enabled': True,
            'Principal': 'EXAMPLE\\User', 'Actions': '[{"Execute":"do not execute.exe"}]'}


class TasksTests(unittest.TestCase):
    def test_tasks_are_data_with_provenance(self):
        report = external.collect_tasks(lambda: json.dumps([row()]))
        self.assertEqual(report['collector_coverage'][0]['status'], 'scanned')
        value = report['observations'][0]
        self.assertEqual(value['identity'], '\\Folder\\Example')
        self.assertEqual(value['target'], 'local-visible-tasks')
        self.assertEqual(value['data']['Actions'], row()['Actions'])
        self.assertIn('visible', report['collector_coverage'][0]['detail'])

    def test_empty_is_valid_but_not_all_users_claim(self):
        report = external.collect_tasks(lambda: '[]')
        self.assertEqual(report['observations'], [])
        self.assertIn('not proof', report['collector_coverage'][0]['detail'])

    def test_malformed_duplicate_and_bad_types_are_errors(self):
        duplicate = row('EXAMPLE')
        bad = row()
        bad['Enabled'] = 'true'
        for raw in ('garbage', '{}', 'null', json.dumps([bad]),
                    json.dumps([row(), duplicate]), '[{"TaskPath":1,"TaskPath":2}]'):
            with self.subTest(raw=raw):
                report = external.collect_tasks(lambda: raw)
                self.assertEqual(report['collector_coverage'][0]['status'], 'error')
        # A good row before the malformed row remains with explicit partial error.
        partial = external.collect_tasks(lambda: json.dumps([row(), bad]))
        self.assertEqual(len(partial['observations']), 1)
        self.assertEqual(partial['collector_coverage'][0]['status'], 'error')

    def test_runner_failure_and_size_count_bounds(self):
        def denied():
            raise OSError('access denied')
        self.assertEqual(external.collect_tasks(denied)['collector_coverage'][0]['status'], 'error')
        with patch.object(external, 'MAX_OUTPUT', 8):
            self.assertEqual(external.collect_tasks(lambda: ' ' * 9)['collector_coverage'][0]['status'], 'error')
        with patch.object(external, 'MAX_ITEMS', 1):
            report = external.collect_tasks(lambda: json.dumps([row('A'), row('B')]))
            self.assertEqual(report['collector_coverage'][0]['status'], 'error')

    def test_native_runner_uses_only_fixed_code_and_no_shell(self):
        process = SimpleNamespace(stdout=io.BytesIO(b'[]'), returncode=0,
                                  wait=lambda timeout=None: 0, kill=lambda: None)
        with patch.object(external, '_system_directory', return_value='/trusted/System32'), \
                patch.object(external.subprocess, 'Popen', return_value=process) as popen:
            self.assertEqual(external.run_task_query(), '[]')
        args, kwargs = popen.call_args
        self.assertEqual(args[0][-1], external.TASK_QUERY)
        self.assertIn('-NoProfile', args[0])
        self.assertFalse(kwargs['shell'])
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['env']['PSModulePath'], '/trusted/System32/WindowsPowerShell/v1.0/Modules')

    def test_native_runner_output_timeout_and_exit_bounds(self):
        for mode in ('output', 'timeout', 'exit'):
            killed = []
            calls = []
            def wait(timeout=None):
                calls.append(timeout)
                if mode == 'timeout' and len(calls) == 1:
                    raise subprocess.TimeoutExpired('fixed query', timeout)
                return 0
            process = SimpleNamespace(stdout=io.BytesIO(b'x' * 20),
                                      returncode=1 if mode == 'exit' else 0,
                                      wait=wait, kill=lambda: killed.append(True))
            with self.subTest(mode=mode), \
                    patch.object(external, '_system_directory', return_value='/trusted'), \
                    patch.object(external.subprocess, 'Popen', return_value=process), \
                    self.assertRaises(OSError):
                external.run_task_query(max_output=10 if mode == 'output' else 100)
            if mode in ('output', 'timeout'):
                self.assertTrue(killed)


class StartupTests(unittest.TestCase):
    def test_known_folder_ids_match_microsoft_documented_startup_folders(self):
        self.assertEqual(external.FOLDERS['current-user-startup'], 'B97D20BB-F46A-4C97-BA10-5E3608430854')
        self.assertEqual(external.FOLDERS['common-startup'], '82A5EA35-D9CD-47C5-9629-E15D2F714E6E')

    def test_coverage_binds_resolved_location_even_if_missing_or_redirected(self):
        with tempfile.TemporaryDirectory() as root:
            first = str(Path(root, 'first'))
            second = str(Path(root, 'second'))
            before = external.collect_startup(lambda target: first)
            after = external.collect_startup(lambda target: second)
            self.assertEqual(before['collector_coverage'][0]['location'], os.path.normcase(first))
            self.assertEqual(after['collector_coverage'][0]['location'], os.path.normcase(second))
            self.assertNotEqual(before['collector_coverage'][0]['location'], after['collector_coverage'][0]['location'])
            self.assertEqual(before['collector_coverage'][0]['status'], 'missing')
        def unresolved(target):
            raise OSError('resolution failed')
        self.assertEqual(external.collect_startup(unresolved)['collector_coverage'][0]['location'], '')
        self.assertEqual(external.collect_tasks(lambda: '[]')['collector_coverage'][0]['location'], '')

    def test_metadata_only_no_shortcut_resolution_or_file_reads(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'example.lnk').write_bytes(b'not a real shortcut; never opened')
            Path(root, 'nested').mkdir()
            Path(root, 'nested', 'unseen.exe').write_bytes(b'not executed')
            report = external.collect_startup(lambda target: root)
            self.assertEqual(len(report['observations']), 4)
            self.assertTrue(all(c['status'] == 'scanned' for c in report['collector_coverage']))
            self.assertTrue(all(v['data']['content_inspected'] is False for v in report['observations']))
            self.assertFalse(any(v['identity'] == 'unseen.exe' for v in report['observations']))

    def test_entry_symlink_recorded_without_following(self):
        with tempfile.TemporaryDirectory() as root:
            os.symlink('/does-not-exist', Path(root, 'link'))
            report = external.collect_startup(lambda target: root)
            self.assertTrue(all(v['data']['kind'] == 'reparse-point' for v in report['observations']))
            self.assertTrue(all(c['status'] == 'scanned' for c in report['collector_coverage']))

    def test_reparse_root_and_ancestor_rejected(self):
        def forbidden_scandir(path):
            self.fail('Must not enumerate reparse root')
        for root in ('/fixture', '/fixture/nested'):
            def lstat(path):
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400 if path == '/fixture' else 0)
            report = external.collect_startup(lambda target: root, scandir=forbidden_scandir, lstat=lstat)
            self.assertTrue(all(c['status'] == 'error' for c in report['collector_coverage']))
            self.assertEqual(report['observations'], [])

    def test_reparse_ancestor_rejected_before_descendant_metadata_access(self):
        calls = []
        def lstat(path):
            calls.append(path)
            if path.startswith('/junction/'):
                self.fail('Descendant metadata must not traverse known reparse ancestor')
            return SimpleNamespace(st_mode=stat.S_IFDIR,
                                   st_file_attributes=0x400 if path == '/junction' else 0)
        report = external.collect_startup(lambda target: '/junction/descendant/startup', lstat=lstat,
                                         scandir=lambda path: self.fail('No enumeration allowed'))
        self.assertEqual(calls, ['/', '/junction', '/', '/junction'])
        self.assertTrue(all(item['status'] == 'error' for item in report['collector_coverage']))

    def test_missing_and_denied_are_distinct(self):
        def resolve(target):
            if target == 'current-user-startup':
                raise FileNotFoundError('absent')
            raise PermissionError('denied')
        report = external.collect_startup(resolve)
        self.assertEqual([c['status'] for c in report['collector_coverage']], ['missing', 'error'])

    def test_limits_and_partial_reads(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'one').touch()
            Path(root, 'two').touch()
            report = external.collect_startup(lambda target: root, max_items=1)
            self.assertEqual(len(report['observations']), 2)
            self.assertTrue(all(c['status'] == 'error' for c in report['collector_coverage']))
            ticks = iter([0, 21, 30, 51])
            timed = external.collect_startup(lambda target: root, clock=lambda: next(ticks))
            self.assertTrue(all(c['status'] == 'error' for c in timed['collector_coverage']))

    def test_invalid_and_network_paths_never_enumerated(self):
        for value in ('relative', '', '\\\\server\\share'):
            with self.subTest(value=value):
                report = external.collect_startup(lambda target: value,
                    scandir=lambda path: self.fail('Unsafe path enumeration'))
                self.assertTrue(all(c['status'] == 'error' for c in report['collector_coverage']))

    def test_duplicate_identity_keeps_partial_evidence_with_error(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG, st_size=0, st_mtime_ns=0)
        class Entries:
            def __enter__(self):
                return iter([SimpleNamespace(name='Name', stat=lambda **kwargs: info),
                             SimpleNamespace(name='NAME', stat=lambda **kwargs: info)])
            def __exit__(self, *args):
                pass
        report = external.collect_startup(lambda target: '/fixture',
                    lstat=lambda path: SimpleNamespace(st_mode=stat.S_IFDIR),
                    scandir=lambda path: Entries())
        self.assertEqual(len(report['observations']), 2)
        self.assertTrue(all(c['status'] == 'error' for c in report['collector_coverage']))
        self.assertTrue(all('Duplicate' in c['detail'] for c in report['collector_coverage']))

    def test_disappearing_entry_is_error_not_absent_folder(self):
        class Entries:
            def __enter__(self):
                return iter([SimpleNamespace(name='gone', stat=self.gone)])
            def __exit__(self, *args):
                pass
            @staticmethod
            def gone(**kwargs):
                raise FileNotFoundError('entry disappeared')
        report = external.collect_startup(lambda target: '/fixture',
                    lstat=lambda path: SimpleNamespace(st_mode=stat.S_IFDIR),
                    scandir=lambda path: Entries())
        self.assertTrue(all(c['status'] == 'error' for c in report['collector_coverage']))


if __name__ == '__main__':
    unittest.main()
