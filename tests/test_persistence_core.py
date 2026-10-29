import ast
import base64
from dataclasses import FrozenInstanceError
from pathlib import Path
import unittest

from persistence_core import RUN_PATHS, SERVICES_PATH, indicators, scan_registry


class Key:
    def __init__(self, data):
        self.data = data
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class FakeRegistry:
    HKEY_CURRENT_USER = 1
    HKEY_LOCAL_MACHINE = 2
    KEY_READ = 0x20019
    KEY_WOW64_32KEY = 0x200
    KEY_WOW64_64KEY = 0x100

    def __init__(self):
        self.locations = {}
        self.calls = []
        self.handles = []

    def add(self, hive, path, values=(), children=()):
        self.locations[hive, path] = (list(values), list(children))

    def OpenKey(self, hive, path, reserved, access):
        self.calls.append((hive, path, access))
        item = self.locations.get((hive, path), FileNotFoundError(path))
        if isinstance(item, Exception):
            raise item
        key = Key(item)
        self.handles.append(key)
        return key

    def QueryInfoKey(self, key):
        return len(key.data[1]), len(key.data[0]), 0

    def EnumValue(self, key, index):
        value = key.data[0][index]
        if isinstance(value, Exception):
            raise value
        return value

    def EnumKey(self, key, index):
        value = key.data[1][index]
        if isinstance(value, Exception):
            raise value
        return value


class IndicatorTests(unittest.TestCase):
    def test_benign_values_are_not_malware_verdicts(self):
        for value in ('', 'YWJjZA==', 'virus scanner', 'powershell-notes.txt',
                      'app.exe -enc password', 'notpowershell.exe', b'pwsh', 5, ['pwsh']):
            with self.subTest(value=value):
                self.assertEqual(indicators(value), ())

    def test_powershell_is_an_explained_signal_not_verdict(self):
        for value in ('powershell.exe -File health.ps1', 'pwsh -NoProfile',
                      r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File x.ps1'):
            self.assertIn('legitimate', indicators(value)[0])

    def test_encoded_utf16_and_switch_options(self):
        token = base64.b64encode('Write-Host hello'.encode('utf-16le')).decode()
        command = 'powershell.exe -EncodedCommand ' + token
        self.assertEqual(len(indicators(command)), 2)
        self.assertEqual(len(indicators(command, powershell=False)), 1)
        self.assertEqual(len(indicators(command, encoded=False)), 1)
        self.assertEqual(indicators(command, False, False), ())
        self.assertEqual(indicators(token), ())

    def test_malformed_and_large_encoded_arguments(self):
        self.assertIn('malformed', indicators('pwsh -enc AAA')[1])
        for command in ('pwsh -enc !!!', 'pwsh -enc', 'pwsh -enc \"'):
            self.assertIn('malformed', indicators(command, powershell=False)[0])
        self.assertIn('limit', indicators('pwsh -enc ' + 'A' * 20000)[1])


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.reg = FakeRegistry()
        self.reg.add(2, SERVICES_PATH)

    def test_missing_optional_locations_and_required_root_error(self):
        self.reg.locations.clear()
        report = scan_registry(self.reg)
        self.assertEqual(len(report.coverage), 5)
        self.assertEqual(sum(item.status == 'missing' for item in report.coverage), 4)
        self.assertFalse(report.findings)
        self.assertEqual(len(report.errors), 1)

    def test_service_subkeys_and_dll_not_parent_only(self):
        self.reg.add(2, SERVICES_PATH, [('Ignored', 'pwsh', 1)], ['Example'])
        self.reg.add(2, SERVICES_PATH + r'\Example',
                     [('ImagePath', 'pwsh -File example.ps1', 2), ('DisplayName', 'pwsh', 1)])
        self.reg.add(2, SERVICES_PATH + r'\Example\Parameters',
                     [('ServiceDll', r'C:\example.dll', 2)])
        report = scan_registry(self.reg)
        self.assertEqual([v.name for v in report.entries], ['ImagePath', 'ServiceDll'])
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.entries[1].category, 'Service DLL')
        self.assertTrue(all(k.closed for k in self.reg.handles))

    def test_access_denied_visible_and_scan_continues(self):
        self.reg.locations[1, RUN_PATHS[0]] = PermissionError('denied')
        self.reg.add(2, RUN_PATHS[1], [('value', 'pwsh', 1)])
        report = scan_registry(self.reg)
        self.assertEqual(len(report.errors), 1)
        self.assertIn('denied', report.errors[0].detail)
        self.assertEqual(len(report.findings), 1)

    def test_partial_enumeration_preserved_and_missing_during_read_is_error(self):
        self.reg.add(1, RUN_PATHS[0], [('first', 'pwsh', 1), FileNotFoundError('changed')])
        report = scan_registry(self.reg)
        self.assertEqual(len(report.entries), 1)
        self.assertEqual(len(report.errors), 1)
        self.assertTrue(all(k.closed for k in self.reg.handles))

    def test_disappearing_enumerated_service_is_error(self):
        self.reg.add(2, SERVICES_PATH, children=['Vanished'])
        report = scan_registry(self.reg)
        self.assertEqual(len(report.errors), 1)
        self.assertTrue(report.errors[0].path.endswith('Vanished'))

    def test_service_enumeration_error_is_reported(self):
        self.reg.add(2, SERVICES_PATH, children=[PermissionError('enumeration denied')])
        self.assertEqual(len(scan_registry(self.reg).errors), 1)

    def test_finding_identity_retains_hive_path_view_type_and_data(self):
        self.reg.add(1, RUN_PATHS[0], [('first', 'pwsh', 2)])
        report = scan_registry(self.reg, '32-bit')
        value = report.findings[0].value
        scan_registry(self.reg, '64-bit')
        self.assertEqual((value.hive, value.path, value.view, value.name, value.data, value.value_type),
                         ('HKEY_CURRENT_USER', RUN_PATHS[0], '32-bit', 'first', 'pwsh', 2))
        with self.assertRaises(FrozenInstanceError):
            value.view = '64-bit'
        self.assertTrue(all(c[2] == self.reg.KEY_READ | self.reg.KEY_WOW64_32KEY
                            for c in self.reg.calls[:5]))

    def test_non_string_values_are_snapshotted_not_classified(self):
        original = ['pwsh']
        self.reg.add(1, RUN_PATHS[0], [('multi', original, 7), ('binary', b'pwsh', 3)])
        report = scan_registry(self.reg)
        original.append('changed')
        self.assertEqual(report.entries[0].data, ('pwsh',))
        self.assertFalse(report.findings)

    def test_invalid_view_rejected_before_any_read(self):
        with self.assertRaises(ValueError):
            scan_registry(self.reg, 'invalid')
        self.assertFalse(self.reg.calls)

    def test_no_registry_mutation_or_subprocess_api_in_sources(self):
        # Regression guard for removal/recursive-deletion and execution paths.
        for filename in ('detectpersist.py', 'persistence_core.py'):
            tree = ast.parse((Path(__file__).resolve().parents[1] / filename).read_text())
            attrs = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
            self.assertFalse(attrs & {'DeleteValue', 'DeleteKey', 'SetValueEx', 'CreateKey', 'Popen', 'system'})


if __name__ == '__main__':
    unittest.main()
