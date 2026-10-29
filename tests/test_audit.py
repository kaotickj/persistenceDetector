import unittest
from audit import scan_audit
from test_persistence_core import FakeRegistry
from persistence_core import SERVICES_PATH
import evidence


class AuditTests(unittest.TestCase):
    def test_injected_external_provider_integrates_without_host_scan(self):
        registry = FakeRegistry()
        registry.add(2, SERVICES_PATH)
        external = {'observations': [{
            'collector': 'startup-folders', 'target': 'current-user-startup',
            'identity': 'example.lnk', 'data': {'kind': 'file', 'size': 123}}],
            'collector_coverage': [{
                'collector': 'startup-folders', 'target': 'current-user-startup',
                'status': 'scanned', 'detail': 'fixture only', 'location': '/fixture/startup'}]}
        report = scan_audit(registry, external_provider=lambda: external)
        document = evidence.to_document(report)
        self.assertEqual(document['observations'], external['observations'])
        self.assertEqual(document['collector_coverage'], external['collector_coverage'])
        external['observations'][0]['data']['size'] = 999
        self.assertEqual(document['observations'][0]['data']['size'], 123)

    def test_cancel_before_start_performs_no_reads(self):
        from audit import ScanCancelled
        registry = FakeRegistry()
        with self.assertRaises(ScanCancelled):
            scan_audit(registry, cancelled=lambda: True)
        self.assertEqual(registry.calls, [])

    def test_cancel_at_stage_boundary_never_starts_next_collector(self):
        from audit import ScanCancelled
        from unittest.mock import patch
        registry = FakeRegistry()
        stop = [False]
        progress = []
        empty = {'observations': [], 'collector_coverage': []}
        def tasks():
            stop[0] = True
            return empty
        with patch('external_collectors.collect_tasks', side_effect=tasks) as task, \
                patch('external_collectors.collect_startup') as startup, \
                patch('external_collectors.collect_wmi') as wmi:
            with self.assertRaises(ScanCancelled):
                scan_audit(registry, progress=progress.append, cancelled=lambda: stop[0])
        task.assert_called_once()
        startup.assert_not_called()
        wmi.assert_not_called()
        self.assertEqual(progress, ['1/4 · Registry inventory', '2/4 · Scheduled tasks'])

    def test_progress_for_injected_provider_and_copied_snapshot(self):
        registry = FakeRegistry()
        progress = []
        external = {'observations': [], 'collector_coverage': []}
        result = scan_audit(registry, external_provider=lambda: external, progress=progress.append)
        self.assertEqual(progress, ['1/4 · Registry inventory', 'External inventory'])
        external['observations'].append({'unrelated': 'mutated later'})
        self.assertEqual(result.observations, [])
