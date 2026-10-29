"""Offscreen Qt tests with injected fixture scans only; never query this host."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import tempfile
import threading
import time
from pathlib import Path
import unittest
from unittest.mock import patch

try:
    from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox
    from PyQt6.QtTest import QTest
    from persistence_gui import AuditWindow
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False

from persistence_core import RUN_PATHS, SERVICES_PATH, scan_registry
from test_persistence_core import FakeRegistry
import evidence


def fixture_report():
    registry = FakeRegistry()
    registry.add(2, SERVICES_PATH)
    registry.add(1, RUN_PATHS[0], [('Health check', 'powershell.exe -File health.ps1', 1),
                                  ('Updater', r'C:\Program Files\Example\updater.exe', 1)])
    return scan_registry(registry)


@unittest.skipUnless(QT_AVAILABLE, 'Install requirements-gui.txt to run offscreen GUI tests')
class QtGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])
        cls.application.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.windows = []
        self.releases = []

    def tearDown(self):
        for event in self.releases:
            event.set()
        for window in self.windows:
            if window.worker is not None:
                window.cancel_scan()
                self.wait_for(lambda: window.worker is None)
            window.close()
        self.application.processEvents()

    def wait_for(self, condition, seconds=5):
        deadline = time.monotonic() + seconds
        while not condition() and time.monotonic() < deadline:
            QTest.qWait(10)
        self.assertTrue(condition(), 'Timed out waiting for Qt condition')

    def window(self, factory=None):
        window = AuditWindow(scan_factory=factory or (lambda options, progress, cancelled: fixture_report()))
        self.windows.append(window)
        window.show()
        self.application.processEvents()
        return window

    def scan(self, window):
        window.start_scan()
        self.wait_for(lambda: window.worker is None)
        self.assertIsNotNone(window.document)

    def test_background_result_filter_selection_and_repeat(self):
        window = self.window()
        self.scan(window)
        self.assertEqual(window.inventory.rowCount(), 2)
        window.search.setText('health')
        self.application.processEvents()
        visible = sum(not window.inventory.isRowHidden(i) for i in range(window.inventory.rowCount()))
        self.assertEqual(visible, 1)
        window.search.clear()
        window.inventory.selectRow(0)
        self.application.processEvents()
        self.scan(window)
        self.assertEqual(window.inventory.rowCount(), 2)
        self.assertTrue(window.scan_button.isEnabled())

    def test_repeated_start_cancel_and_previous_snapshot_retained(self):
        window = self.window()
        self.scan(window)
        old = window.document
        release = threading.Event()
        entered = threading.Event()
        self.releases.append(release)
        calls = []
        def blocked(options, progress, cancelled):
            calls.append(1)
            progress('Fixture collector waiting')
            entered.set()
            release.wait(3)
            return fixture_report()
        window.scan_factory = blocked
        window.start_scan()
        self.wait_for(entered.is_set)
        window.start_scan()
        self.assertEqual(len(calls), 1)
        self.assertFalse(window.scan_button.isEnabled())
        self.assertFalse(window.export_button.isEnabled())
        window.cancel_scan()
        self.assertIsNotNone(window.worker)
        release.set()
        self.wait_for(lambda: window.worker is None)
        self.assertIs(window.document, old)
        self.assertIn('cancel', window.status_label.text().lower())

    def test_close_during_work_defers_destruction_until_finished(self):
        release = threading.Event()
        entered = threading.Event()
        self.releases.append(release)
        def blocked(options, progress, cancelled):
            entered.set()
            release.wait(3)
            return fixture_report()
        window = self.window(blocked)
        window.start_scan()
        self.wait_for(entered.is_set)
        window.close()
        self.application.processEvents()
        self.assertTrue(window.isVisible())
        self.assertIsNotNone(window.worker)
        release.set()
        self.wait_for(lambda: window.worker is None and not window.isVisible())

    def test_factory_error_does_not_replace_previous_result(self):
        window = self.window()
        self.scan(window)
        old = window.document
        def failed(options, progress, cancelled):
            raise RuntimeError('fixture failure')
        window.scan_factory = failed
        with patch.object(window, '_message'):
            window.start_scan()
            self.wait_for(lambda: window.worker is None)
        self.assertIs(window.document, old)
        self.assertTrue(window.scan_button.isEnabled())
        self.assertIn('fail', window.status_label.text().lower())

    def test_terminal_result_cannot_be_relabelled_cancel_requested(self):
        from types import SimpleNamespace
        window = self.window()
        calls = []
        worker = SimpleNamespace(isInterruptionRequested=lambda: False,
                                 requestInterruption=lambda: calls.append('cancel'),
                                 deleteLater=lambda: None)
        window.worker = worker
        report = fixture_report()
        window._accept_result((report, evidence.to_document(report)))
        previous = window.status_label.text()
        window.cancel_scan()
        self.assertEqual(calls, [])
        self.assertEqual(window.status_label.text(), previous)
        window._finished()

    def test_sort_selection_and_changed_controls_preserve_snapshot_identity(self):
        from PyQt6.QtCore import Qt
        import json
        window = self.window()
        self.scan(window)
        window.inventory.sortItems(1, Qt.SortOrder.DescendingOrder)
        window.inventory.selectRow(0)
        self.application.processEvents()
        data = json.loads(window.details.toPlainText())
        self.assertEqual(data['name'], window.inventory.item(0, 1).text())
        window.view.setCurrentText('32-bit')
        window.powershell.setChecked(False)
        self.assertEqual(window.document['scope']['views'], ['64-bit'])
        self.assertTrue(window.document['scope']['signals']['powershell'])
        window.search.setText('matches-no-items')
        self.application.processEvents()
        self.assertEqual(window.inventory.rowCount(), 0)
        self.assertEqual(window.details.toPlainText(), '')

    def test_export_compare_cancel_and_malformed_import(self):
        window = self.window()
        self.scan(window)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'evidence.json')
            with patch.object(QFileDialog, 'getSaveFileName', return_value=(path, 'JSON')), patch.object(window, '_message'):
                window.export_evidence()
            evidence.loads(Path(path).read_text())
            with patch.object(QFileDialog, 'getOpenFileName', return_value=(path, 'JSON')), \
                    patch.object(window, '_message', return_value=False):
                window.compare_baseline()
            with patch.object(QFileDialog, 'getOpenFileName', return_value=(path, 'JSON')), \
                    patch.object(window, '_message', return_value=True):
                window.compare_baseline()
            Path(path).write_text('{invalid')
            with patch.object(QFileDialog, 'getOpenFileName', return_value=(path, 'JSON')), \
                    patch.object(window, '_message') as error:
                window.compare_baseline()
                error.assert_called_once()
