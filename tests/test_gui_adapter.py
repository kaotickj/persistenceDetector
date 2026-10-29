"""Headless adapter checks; not a substitute for a Windows GUI integration test."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_persistence_core import FakeRegistry
from persistence_core import RUN_PATHS


class Text:
    def __init__(self):
        self.content = ''

    def delete(self, *args):
        self.content = ''

    def insert(self, where, content):
        self.content += content


class Combo(dict):
    def set(self, value):
        self.selection = value

    def current(self, index):
        self.selection = index


class Variable:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value


class GuiAdapterTests(unittest.TestCase):
    def setUp(self):
        self.registry = FakeRegistry()
        with patch.dict(sys.modules, {'winreg': self.registry}):
            spec = importlib.util.spec_from_file_location(
                'detector_test_adapter', Path(__file__).resolve().parents[1] / 'detectpersist.py')
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
        self.app = self.module.RegistryCheckerApp.__new__(self.module.RegistryCheckerApp)
        self.app.output_text = Text()
        self.app.combo_box = Combo()
        self.app.registry_view_var = Variable('32-bit')
        self.app.powershell_var = Variable(1)
        self.app.encoded_var = Variable(1)
        self.app.scan_report = None

    def test_repeated_scan_clears_stale_selection_and_retains_identity(self):
        self.registry.add(1, RUN_PATHS[0], [('first', 'pwsh', 1)])
        self.app.check_registry()
        finding = self.app.findings[0]
        self.app.registry_view_var.value = '64-bit'
        self.assertEqual(finding.value.view, '32-bit')
        self.registry.locations.clear()
        self.app.check_registry()
        self.assertEqual(self.app.findings, [])
        self.assertEqual(self.app.combo_box['values'], [])
        self.assertEqual(self.app.combo_box.selection, '')
        self.assertIn('No indicators found', self.app.output_text.content)
        self.assertIn('does not mean clean', self.app.output_text.content)

    def test_no_scan_and_dialog_cancellation_leave_output_unchanged(self):
        with patch.object(self.module.messagebox, 'showinfo') as info:
            self.app.show_inventory()
            info.assert_called_once()
        self.app.check_registry()
        previous = self.app.output_text.content
        with patch.object(self.module.filedialog, 'asksaveasfilename', return_value=''):
            self.app.export_evidence()
        with patch.object(self.module.filedialog, 'askopenfilename', return_value=''):
            self.app.compare_baseline()
        self.assertEqual(previous, self.app.output_text.content)

    def test_export_inventory_and_baseline_import(self):
        import evidence
        self.registry.add(1, RUN_PATHS[0], [('value', b'\x00\xff', 3)])
        self.app.check_registry()
        self.app.show_inventory()
        self.assertIn('FULL INVENTORY', self.app.output_text.content)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'report.json')
            with patch.object(self.module.filedialog, 'asksaveasfilename', return_value=path), patch.object(self.module.messagebox, 'showinfo'):
                self.app.export_evidence()
            document = evidence.loads(Path(path).read_text())
            self.assertEqual(document['entries'][0]['data']['value'], '00ff')
            previous = self.app.output_text.content
            with patch.object(self.module.filedialog, 'askopenfilename', return_value=path), patch.object(self.module.messagebox, 'askyesno', return_value=False):
                self.app.compare_baseline()
            self.assertEqual(previous, self.app.output_text.content)
            with patch.object(self.module.filedialog, 'askopenfilename', return_value=path), patch.object(self.module.messagebox, 'askyesno', return_value=True):
                self.app.compare_baseline()
            self.assertIn('unchanged: 1', self.app.output_text.content)
            Path(path).write_text('{bad json')
            previous = self.app.output_text.content
            with patch.object(self.module.filedialog, 'askopenfilename', return_value=path), patch.object(self.module.messagebox, 'showerror') as error:
                self.app.compare_baseline()
                error.assert_called_once()
            self.assertEqual(previous, self.app.output_text.content)

    def test_all_denied_and_disabled_options_are_explicit(self):
        from persistence_core import SERVICES_PATH
        for hive in (1, 2):
            for path in RUN_PATHS:
                self.registry.locations[hive, path] = PermissionError('denied')
        self.registry.locations[2, SERVICES_PATH] = PermissionError('denied')
        self.app.powershell_var.value = 0
        self.app.encoded_var.value = 0
        self.app.check_registry()
        self.assertEqual(self.app.output_text.content.count('COVERAGE ERROR'), 5)
        self.assertIn('PowerShell=False, encoded=False', self.app.output_text.content)
        self.assertIn('Inventoried 0 values', self.app.output_text.content)
        self.assertIn('Scan incomplete', self.app.output_text.content)

    def test_error_is_visible_and_removal_stays_read_only(self):
        self.registry.locations[1, RUN_PATHS[0]] = PermissionError('denied')
        self.app.check_registry()
        self.assertIn('COVERAGE ERROR [32-bit]', self.app.output_text.content)
        self.assertIn('Scan incomplete', self.app.output_text.content)
        calls = list(self.registry.calls)
        with patch.object(self.module.messagebox, 'showinfo') as info:
            self.app.delete_selected_key()
            info.assert_called_once()
        self.assertEqual(self.registry.calls, calls)


if __name__ == '__main__':
    unittest.main()
