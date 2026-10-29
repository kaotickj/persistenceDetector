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
