import unittest
from unittest.mock import patch

import persistence_core as core
from test_persistence_core import FakeRegistry


class RegistryExpansionTests(unittest.TestCase):
    def setUp(self):
        self.registry = FakeRegistry()
        self.registry.add(2, core.SERVICES_PATH)

    def test_winlogon_pertinent_values_only(self):
        self.registry.add(2, core.WINLOGON_PATH,
                          [('Shell', 'explorer.exe', 1), ('Userinit', 'userinit.exe,', 1),
                           ('Unrelated', 'pwsh', 1)])
        self.registry.add(1, core.WINLOGON_PATH, [('Shell', 'pwsh -File profile.ps1', 1),
                                                ('Userinit', 'not-in-scope', 1)])
        report = core.scan_registry(self.registry, '32-bit')
        self.assertEqual([v.name for v in report.entries], ['Shell', 'Userinit', 'Shell'])
        self.assertEqual(len(report.findings), 1)
        self.assertTrue(all(v.view == '32-bit' for v in report.entries))

    def test_ifeo_is_one_level_and_does_not_execute_debugger(self):
        self.registry.add(2, core.IFEO_PATH, children=['example.exe'])
        path = core.IFEO_PATH + r'\example.exe'
        self.registry.add(2, path, [('Debugger', 'not-executed.exe', 1), ('GlobalFlag', 512, 4),
                                   ('UseFilter', 1, 4), ('Other', 'pwsh', 1)], ['Filter'])
        self.registry.add(2, path + r'\Filter', [('Debugger', 'not-in-this-build.exe', 1)])
        report = core.scan_registry(self.registry)
        self.assertEqual([v.name for v in report.entries], ['Debugger', 'GlobalFlag', 'UseFilter'])
        self.assertFalse(any(call[1].endswith(r'\Filter') for call in self.registry.calls))

    def test_ifeo_denial_and_disappearing_child_visible(self):
        for error in (PermissionError('denied'), FileNotFoundError('changed')):
            self.registry.add(2, core.IFEO_PATH, children=['gone.exe'])
            self.registry.locations[2, core.IFEO_PATH + r'\gone.exe'] = error
            report = core.scan_registry(self.registry)
            self.assertEqual(len(report.errors), 1)
            self.assertTrue(report.errors[0].path.endswith('gone.exe'))
        self.registry.locations[2, core.IFEO_PATH] = PermissionError('parent denied')
        self.assertEqual(len(core.scan_registry(self.registry).errors), 1)

    def test_ifeo_bounds_keep_partial_evidence(self):
        self.registry.add(2, core.IFEO_PATH, children=['one.exe', 'two.exe'])
        for name in ('one.exe', 'two.exe'):
            self.registry.add(2, core.IFEO_PATH + '\\' + name, [('Debugger', 'fixture.exe', 1)])
        with patch.object(core, 'MAX_REGISTRY_ITEMS', 1):
            report = core.scan_registry(self.registry)
        self.assertEqual(len(report.entries), 1)
        self.assertEqual(len(report.errors), 1)
        self.assertIn('limit', report.errors[0].detail)

    def test_value_bound_duplicate_and_time_errors(self):
        self.registry.add(2, core.WINLOGON_PATH, [('Shell', 'first', 1), ('Userinit', 'second', 1)])
        with patch.object(core, 'MAX_REGISTRY_ITEMS', 1):
            report = core.scan_registry(self.registry)
        self.assertEqual(len(report.entries), 1)
        self.assertTrue(any('limit' in item.detail for item in report.errors))
        self.registry.add(2, core.WINLOGON_PATH, [('Shell', 'first', 1), ('SHELL', 'second', 1)])
        report = core.scan_registry(self.registry)
        self.assertEqual(len(report.entries), 1)
        self.assertTrue(any('Duplicate' in item.detail for item in report.errors))
        with patch.object(core, 'REGISTRY_BUDGET_SECONDS', -1):
            report = core.scan_registry(self.registry)
        self.assertTrue(any('limit' in item.detail for item in report.errors))
