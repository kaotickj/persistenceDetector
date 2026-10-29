"""Read-only PyQt6 audit interface. Native collectors run off the UI thread.

Cancellation is cooperative at collector boundaries. Closing never destroys an
active thread: the window remains alive until the worker finishes naturally.
"""
import json
import sys

from PyQt6.QtCore import QThread, QTimer, Qt, pyqtSignal, QSaveFile, QIODevice
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QTabWidget, QVBoxLayout, QWidget, QAbstractItemView,
)

import evidence
from persistence_core import BUILD

STYLE = """
QWidget { background: #090c12; color: #edf3ff; font-family: 'Segoe UI', sans-serif; font-size: 13px; }
QMainWindow { background: #090c12; }
QLabel#eyebrow { color: #56a4ff; font-size: 11px; font-weight: 700; letter-spacing: 2px; }
QLabel#title { font-size: 29px; font-weight: 700; }
QLabel#muted { color: #94a6bf; }
QLabel#status { color: #b4c9e6; }
QFrame#card { background: #101722; border: 1px solid #233248; border-radius: 10px; }
QFrame#card QLabel { background: transparent; }
QLabel#metric { font-size: 29px; font-weight: 650; color: #f3f7ff; }
QLabel#metricTitle { color: #9ab0ce; font-size: 12px; }
QPushButton { background: #162437; border: 1px solid #2b4260; padding: 10px 16px; border-radius: 6px; font-weight: 600; }
QPushButton:hover { background: #1d3552; border-color: #5799e9; }
QPushButton:disabled { background: #101722; color: #53647c; border-color: #202d3f; }
QPushButton#primary { background: #1769dc; border-color: #3289ff; color: white; }
QPushButton#primary:hover { background: #247beb; }
QPushButton#primary:disabled { background: #173354; color: #7088a7; border-color: #254360; }
QLineEdit, QComboBox { background: #101722; border: 1px solid #2c3d55; padding: 9px; border-radius: 5px; selection-background-color: #245fa8; }
QLineEdit:focus, QComboBox:focus { border-color: #4f9cff; }
QComboBox::drop-down { border: 0; width: 23px; }
QComboBox QAbstractItemView { background: #101722; selection-background-color: #1d477d; }
QCheckBox { spacing: 8px; color: #c3d3e9; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid #405775; border-radius: 3px; background: #101722; }
QCheckBox::indicator:checked { background: #2d83ee; border: 2px solid #91bfff; }
QTabWidget::pane { border: 1px solid #243248; border-radius: 6px; background: #0d121b; }
QTabBar::tab { background: #0c111a; color: #8ea6c6; padding: 12px 18px; border-bottom: 2px solid #0c111a; }
QTabBar::tab:selected { color: #f5f8ff; border-bottom: 2px solid #4798ff; background: #111c2b; }
QTableWidget { background: #0d121b; alternate-background-color: #111a27; border: 0; gridline-color: #1d2a3e; selection-background-color: #193e6c; selection-color: #ffffff; }
QTableWidget::item { padding: 8px; }
QHeaderView::section { background: #142033; color: #a9c0df; border: 0; border-bottom: 1px solid #2c4260; padding: 10px 8px; font-weight: 600; }
QPlainTextEdit { background: #0c121c; border: 1px solid #25364d; border-radius: 6px; padding: 12px; color: #c5dbf7; font-family: 'Consolas', monospace; font-size: 12px; }
QSplitter::handle { background: #111b2b; width: 5px; }
QProgressBar { border: 0; border-radius: 2px; background: #142236; max-height: 4px; }
QProgressBar::chunk { background: #3a92ff; }
QScrollBar:vertical { background: #101722; width: 10px; }
QScrollBar::handle:vertical { background: #304965; min-height: 25px; border-radius: 4px; }
"""


def label(text, name=None):
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    if name:
        widget.setObjectName(name)
    return widget


def default_scan_factory(options, progress, cancelled):
    if sys.platform != 'win32':
        raise RuntimeError('Live collection requires Windows. Offline fixture tests do not scan this host.')
    import winreg
    from audit import scan_audit
    return scan_audit(winreg, progress=progress, cancelled=cancelled, **options)


class ScanWorker(QThread):
    progress = pyqtSignal(str)
    result = pyqtSignal(object)
    failed = pyqtSignal(str)
    stopped = pyqtSignal()

    def __init__(self, factory, options, parent=None):
        super().__init__(parent)
        self.factory = factory
        self.options = dict(options)

    def run(self):
        try:
            if self.isInterruptionRequested():
                self.stopped.emit()
                return
            report = self.factory(self.options, self.progress.emit, self.isInterruptionRequested)
            if self.isInterruptionRequested():
                self.stopped.emit()
                return
            # Validate in the worker before replacing the previous visible snapshot.
            document = evidence.to_document(report)
            self.result.emit((report, document))
        except Exception as exc:
            from audit import ScanCancelled
            if isinstance(exc, ScanCancelled) or self.isInterruptionRequested():
                self.stopped.emit()
            else:
                self.failed.emit(str(exc))


class AuditWindow(QMainWindow):
    def __init__(self, scan_factory=None):
        super().__init__()
        self.scan_factory = scan_factory or default_scan_factory
        self.worker = None
        self.report = None
        self.document = None
        self._close_pending = False
        self._outcome = ''
        self._rows = []
        self.setWindowTitle('Persistence Detector | ' + BUILD)
        self.resize(1240, 820)
        self.setMinimumSize(940, 640)
        self.setStyleSheet(STYLE)
        self._build_ui()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(28, 24, 28, 20)
        layout.setSpacing(17)
        heading = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(5)
        titles.addWidget(label('PERSISTENCE DETECTOR  /  READ-ONLY AUDIT', 'eyebrow'))
        titles.addWidget(label('Understand what persists.', 'title'))
        titles.addWidget(label('Evidence, not a clean-machine certificate. Review context before drawing conclusions.', 'muted'))
        heading.addLayout(titles)
        heading.addStretch()
        self.build_label = label(BUILD + '\nSOURCE BUILD · NO REMEDIATION', 'muted')
        self.build_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        heading.addWidget(self.build_label)
        layout.addLayout(heading)

        toolbar = QHBoxLayout()
        self.view = QComboBox()
        self.view.addItems(['64-bit', '32-bit'])
        self.view.setToolTip('Registry view only. Task, startup and WMI inventories are not filtered by this selector.')
        self.powershell = QCheckBox('PowerShell signals')
        self.encoded = QCheckBox('Encoded-command signals')
        self.powershell.setChecked(True)
        self.encoded.setChecked(True)
        toolbar.addWidget(label('Registry view', 'muted'))
        toolbar.addWidget(self.view)
        toolbar.addSpacing(12)
        toolbar.addWidget(self.powershell)
        toolbar.addWidget(self.encoded)
        toolbar.addStretch()
        self.scan_button = QPushButton('Start audit')
        self.scan_button.setObjectName('primary')
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button = QPushButton('Cancel')
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        toolbar.addWidget(self.scan_button)
        toolbar.addWidget(self.cancel_button)
        layout.addLayout(toolbar)

        cards = QHBoxLayout()
        cards.setSpacing(14)
        self.inventory_count = self._card(cards, 'OBSERVATIONS', 'Registry values + tasks, startup, WMI')
        self.indicator_count = self._card(cards, 'REVIEW INDICATORS', 'Heuristic signals, not malware verdicts')
        self.gap_count = self._card(cards, 'COVERAGE ERRORS', 'Unreadable or incomplete locations')
        layout.addLayout(cards)

        status = QHBoxLayout()
        self.status_label = label('Ready. No scan has run.', 'status')
        self.status_label.setWordWrap(True)
        status.addWidget(self.status_label, 1)
        self.export_button = QPushButton('Export JSON')
        self.compare_button = QPushButton('Compare baseline')
        self.export_button.setEnabled(False)
        self.compare_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_evidence)
        self.compare_button.clicked.connect(self.compare_baseline)
        status.addWidget(self.export_button)
        status.addWidget(self.compare_button)
        layout.addLayout(status)
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.tabs = QTabWidget()
        inventory_page = QWidget()
        inventory_layout = QVBoxLayout(inventory_page)
        inventory_layout.setContentsMargins(12, 14, 12, 12)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText('Filter by name, location, command or evidence…')
        self.search.textChanged.connect(self.apply_filter)
        self.type_filter = QComboBox()
        self.type_filter.addItems(['All sources', 'Registry', 'Scheduled tasks', 'Startup folders', 'WMI subscriptions'])
        self.type_filter.currentTextChanged.connect(self.apply_filter)
        self.filtered_label = label('0 shown', 'muted')
        filters.addWidget(self.search, 1)
        filters.addWidget(self.type_filter)
        filters.addWidget(self.filtered_label)
        inventory_layout.addLayout(filters)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.inventory = self._table(['Source', 'Identity / name', 'Scope', 'Review'])
        self.inventory.itemSelectionChanged.connect(self.show_selection)
        splitter.addWidget(self.inventory)
        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(12, 0, 0, 0)
        detail_layout.addWidget(label('EVIDENCE DETAILS', 'eyebrow'))
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText('Select an observation to inspect its original identity, data and provenance.\n\nNo commands or scripts are executed.')
        detail_layout.addWidget(self.details)
        splitter.addWidget(detail)
        splitter.setSizes([740, 380])
        inventory_layout.addWidget(splitter, 1)
        self.tabs.addTab(inventory_page, 'Inventory')
        coverage_page = QWidget()
        coverage_layout = QVBoxLayout(coverage_page)
        coverage_layout.addWidget(label('Missing optional locations are distinct from read errors. Unlisted persistence mechanisms remain unassessed.', 'muted'))
        self.coverage = self._table(['Status', 'Collector / view', 'Location / target', 'Detail'])
        coverage_layout.addWidget(self.coverage)
        self.tabs.addTab(coverage_page, 'Coverage')
        self.comparison = QPlainTextEdit()
        self.comparison.setReadOnly(True)
        self.comparison.setPlaceholderText('Compare a previous JSON report with the current completed snapshot.\n\nSource confirmation is required. Missing visibility does not imply removal.')
        self.tabs.addTab(self.comparison, 'Baseline comparison')
        layout.addWidget(self.tabs, 1)
        self.snapshot_label = label('NO SNAPSHOT  ·  Reports may contain sensitive usernames, paths, commands and scripts.', 'muted')
        self.snapshot_label.setWordWrap(True)
        layout.addWidget(self.snapshot_label)

    def _card(self, parent, title, subtitle):
        frame = QFrame()
        frame.setObjectName('card')
        box = QVBoxLayout(frame)
        box.setContentsMargins(18, 13, 18, 14)
        box.setSpacing(4)
        box.addWidget(label(title, 'metricTitle'))
        number = label('—', 'metric')
        box.addWidget(number)
        box.addWidget(label(subtitle, 'muted'))
        parent.addWidget(frame, 1)
        return number

    def _table(self, headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().hide()
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setDefaultSectionSize(38)
        return table

    def start_scan(self):
        if self.worker is not None or self._close_pending:
            return
        self._outcome = ''
        options = {'view': self.view.currentText(), 'powershell': self.powershell.isChecked(),
                   'encoded': self.encoded.isChecked()}
        self.worker = ScanWorker(self.scan_factory, options, self)
        self.worker.progress.connect(self._show_progress)
        self.worker.result.connect(self._accept_result)
        self.worker.failed.connect(self._failed)
        self.worker.stopped.connect(self._cancelled)
        self.worker.finished.connect(self._finished)
        self._set_busy(True)
        self.status_label.setText('Starting audit… Previous snapshot remains visible until a new scan completes.')
        self.worker.start()

    def _set_busy(self, busy):
        for widget in (self.scan_button, self.view, self.powershell, self.encoded):
            widget.setEnabled(not busy and not self._close_pending)
        self.cancel_button.setEnabled(busy and not self._close_pending)
        self.export_button.setEnabled(not busy and self.document is not None and not self._close_pending)
        self.compare_button.setEnabled(not busy and self.document is not None and not self._close_pending)
        self.progress_bar.setRange(0, 0 if busy else 1)
        if not busy:
            self.progress_bar.setValue(0)

    def _show_progress(self, text):
        if self.worker is not None and not self.worker.isInterruptionRequested() and not self._close_pending:
            self.status_label.setText(str(text))

    def cancel_scan(self):
        if self.worker is None or self._outcome in ('complete', 'partial', 'failed', 'cancelled'):
            return
        self.worker.requestInterruption()
        self.cancel_button.setEnabled(False)
        self.status_label.setText('Cancel requested — waiting for the active collector. Blocking OS calls may take longer; no thread is forcibly terminated.')

    def _accept_result(self, payload):
        if self.worker is None or self.worker.isInterruptionRequested() or self._close_pending:
            self._cancelled()
            return
        self.report, self.document = payload
        self.cancel_button.setEnabled(False)
        self.comparison.clear()
        self._render_document()
        gaps = sum(c['status'] == 'error' for c in self.document['coverage'] + self.document['collector_coverage'])
        self._outcome = 'partial' if gaps else 'complete'
        self.status_label.setText(
            'Audit completed with {} coverage errors — some locations remain unassessed.'.format(gaps)
            if gaps else 'Audit completed within its declared scope. Nothing found does not mean clean.')

    def _failed(self, text):
        self.cancel_button.setEnabled(False)
        self._outcome = 'failed'
        suffix = ' Previous snapshot retained.' if self.document is not None else ' No snapshot produced.'
        self.status_label.setText('Audit failed: ' + text + suffix)

    def _cancelled(self):
        self.cancel_button.setEnabled(False)
        self._outcome = 'cancelled'
        self.status_label.setText('Audit cancelled. ' + ('Previous completed snapshot retained.' if self.document is not None else 'No snapshot produced.'))

    def _finished(self):
        worker = self.worker
        if worker is None:
            return
        # finished is emitted after run() returns; no forceful termination or wait
        # on the GUI thread, and a new scan cannot begin before this point.
        self.worker = None
        worker.deleteLater()
        self._set_busy(False)
        if self._close_pending:
            QTimer.singleShot(0, self.close)

    def _render_document(self):
        doc = self.document
        self._rows = []
        for item in doc['entries']:
            self._rows.append(('Registry', item['name'] or '(Default)',
                               '{} · {}'.format(item['hive'], item['view']),
                               'Review' if item['reasons'] else 'Inventory', item))
        kinds = {'scheduled-tasks': 'Scheduled tasks', 'startup-folders': 'Startup folders',
                 'wmi-subscriptions': 'WMI subscriptions'}
        for item in doc['observations']:
            self._rows.append((kinds[item['collector']], item['identity'], item['target'], 'Inventory', item))
        self.inventory_count.setText(str(len(self._rows)))
        self.indicator_count.setText(str(sum(bool(v['reasons']) for v in doc['entries'])))
        coverage = doc['coverage'] + doc['collector_coverage']
        self.gap_count.setText(str(sum(c['status'] == 'error' for c in coverage)))
        self.coverage.setRowCount(0)
        for item in coverage:
            if 'hive' in item:
                fields = [item['status'].upper(), 'Registry · ' + item['view'],
                          item['hive'] + '\\' + item['path'], item['detail']]
            else:
                fields = [item['status'].upper(), item['collector'],
                          item['target'] + (' · ' + item['location'] if item['location'] else ''), item['detail']]
            row = self.coverage.rowCount()
            self.coverage.insertRow(row)
            for column, value in enumerate(fields):
                cell = QTableWidgetItem(value)
                if column == 0 and item['status'] == 'error':
                    cell.setForeground(QColor('#ffbd83'))
                self.coverage.setItem(row, column, cell)
        for column, width in enumerate((105, 180, 420, 340)):
            self.coverage.setColumnWidth(column, width)
        self.snapshot_label.setText('SCAN {}  ·  {} / {}  ·  Registry {}  ·  Sensitive evidence: share carefully.'.format(
            doc['scan_started_utc'], doc['source']['host_label'], doc['source']['account_label'], ', '.join(doc['scope']['views'])))
        self.apply_filter()

    def apply_filter(self, *args):
        query = self.search.text().casefold()
        kind = self.type_filter.currentText()
        self.inventory.setSortingEnabled(False)
        self.inventory.setRowCount(0)
        self.details.clear()
        for record in self._rows:
            source, name, scope, review, data = record
            if kind != 'All sources' and source != kind:
                continue
            if query and query not in json.dumps(data, ensure_ascii=False).casefold() and query not in source.casefold():
                continue
            row = self.inventory.rowCount()
            self.inventory.insertRow(row)
            for column, value in enumerate((source, name, scope, review)):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, data)
                if review == 'Review' and column == 3:
                    cell.setForeground(QColor('#8cbeff'))
                self.inventory.setItem(row, column, cell)
        for column, width in enumerate((135, 255, 190, 90)):
            self.inventory.setColumnWidth(column, width)
        self.inventory.setSortingEnabled(True)
        self.filtered_label.setText('{} shown / {}'.format(self.inventory.rowCount(), len(self._rows)))

    def show_selection(self):
        selected = self.inventory.selectedItems()
        if selected:
            self.details.setPlainText(json.dumps(selected[0].data(Qt.ItemDataRole.UserRole), indent=2, ensure_ascii=False))
        else:
            self.details.clear()

    def _message(self, title, text, question=False):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(text)
        box.setIcon(QMessageBox.Icon.Question if question else QMessageBox.Icon.Warning)
        box.setStandardButtons((QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                               if question else QMessageBox.StandardButton.Ok)
        if question:
            box.setDefaultButton(QMessageBox.StandardButton.No)
        return box.exec() == QMessageBox.StandardButton.Yes

    def export_evidence(self):
        if self.worker is not None or self.document is None:
            return
        try:
            # Retain scan time and original options; only export time changes.
            document = evidence.to_document(self.report)
            content = evidence.dumps(document).encode('utf-8')
            path, _ = QFileDialog.getSaveFileName(self, 'Export sensitive audit evidence', '', 'JSON evidence (*.json)')
            if not path:
                return
            stream = QSaveFile(path)
            if not stream.open(QIODevice.OpenModeFlag.WriteOnly):
                raise OSError(stream.errorString())
            if stream.write(content) != len(content):
                stream.cancelWriting()
                raise OSError(stream.errorString())
            if not stream.commit():
                raise OSError(stream.errorString())
            self.status_label.setText('Evidence exported. This JSON is not a restorable registry backup.')
        except (OSError, ValueError) as exc:
            self._message('Export failed', str(exc))

    def compare_baseline(self):
        if self.worker is not None or self.document is None:
            return
        try:
            path, _ = QFileDialog.getOpenFileName(self, 'Select previous evidence snapshot', '', 'JSON evidence (*.json)')
            if not path:
                return
            with open(path, 'rb') as stream:
                raw = stream.read(evidence.MAX_BYTES + 1)
            if len(raw) > evidence.MAX_BYTES:
                raise ValueError('Evidence exceeds 10 MiB limit')
            baseline = evidence.loads(raw.decode('utf-8'))
            source = baseline['source']
            if not self._message('Confirm comparable source',
                    'Baseline: {} / {}\nScan: {}\n\nConfirm both snapshots came from the SAME machine, '
                    'SAME Windows account and SAME privilege context. Labels are not authenticated identifiers. '
                    'If uncertain, choose No. The comparison uses the last completed snapshot, not a fresh scan.'.format(
                        source['host_label'], source['account_label'], baseline['scan_started_utc']), question=True):
                return
            changes = evidence.compare(baseline, self.document, same_source_confirmed=True)
            heading = ('BASELINE COMPARISON — inventory differences, not malware verdicts.\n'
                       'Unassessed is not removed; newly observed is not necessarily added.\n'
                       'Baseline scan: {}\nCurrent scan: {}\n\n').format(
                           baseline['scan_started_utc'], self.document['scan_started_utc'])
            summary = '\n'.join('{}: {}'.format(key.replace('_', ' ').upper(), len(value))
                                for key, value in changes.items())
            self.comparison.setPlainText(heading + summary + '\n\n' + json.dumps(changes, indent=2, ensure_ascii=False))
            self.tabs.setCurrentIndex(2)
        except (OSError, ValueError, UnicodeError) as exc:
            self._message('Comparison failed', str(exc))

    def closeEvent(self, event):
        if self.worker is not None:
            self._close_pending = True
            self.cancel_scan()
            self._set_busy(True)
            self.status_label.setText('Closing after the active collector returns. No worker is forcibly terminated.')
            event.ignore()
            return
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Persistence Detector')
    window = AuditWindow()
    window.show()
    return app.exec()


if __name__ == '__main__':
    raise SystemExit(main())
