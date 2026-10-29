import copy
import json
import unittest

import evidence
from persistence_core import RUN_PATHS, SERVICES_PATH, scan_registry
from test_persistence_core import FakeRegistry


def compare(old, new):
    return evidence.compare(old, new, same_source_confirmed=True)


class EvidenceTests(unittest.TestCase):
    def doc(self, values=(), view='64-bit', error=None):
        registry = FakeRegistry()
        registry.add(2, SERVICES_PATH)
        registry.add(1, RUN_PATHS[0], values)
        if error:
            registry.locations[1, RUN_PATHS[0]] = error
        return evidence.to_document(scan_registry(registry, view))

    def test_round_trip_typed_data_and_metadata(self):
        document = self.doc([('binary', b'\x00\xff', 3), ('strings', ['a', 'b'], 7),
                             ('integer', 42, 4), ('command', 'pwsh -enc !!!', 2)])
        self.assertEqual(evidence.loads(evidence.dumps(document)), document)
        self.assertEqual(document['schema'], evidence.SCHEMA)
        self.assertEqual(document['build'], '0.2.0+build.2')
        self.assertEqual(document['entries'][0]['data'], {'kind': 'bytes', 'value': '00ff'})
        self.assertEqual(len(document['entries'][3]['reasons']), 2)

    def test_add_change_type_remove_unchanged(self):
        old = self.doc([('same', 'a', 1), ('type', 'a', 1), ('gone', 'x', 1)])
        new = self.doc([('same', 'a', 1), ('type', 'a', 2), ('new', 'x', 1)])
        result = compare(old, new)
        for key in ('added', 'changed', 'removed', 'unchanged'):
            self.assertEqual(len(result[key]), 1)
        self.assertFalse(result['unassessed'])

    def test_failed_coverage_never_claims_removed(self):
        old = self.doc([('value', 'a', 1)])
        for new in (self.doc(error=PermissionError('denied')), self.doc(view='32-bit')):
            result = compare(old, new)
            self.assertFalse(result['removed'])
            self.assertEqual(len(result['unassessed']), 1)
        new = self.doc()
        new['coverage'] = []
        self.assertEqual(len(compare(old, new)['unassessed']), 1)

    def test_absent_optional_key_can_establish_absence(self):
        old = self.doc([('value', 'a', 1)])
        new = self.doc()
        new['coverage'][0]['status'] = 'missing'
        self.assertEqual(len(compare(old, new)['removed']), 1)

    def test_incomplete_baseline_is_newly_observed_not_added(self):
        old = self.doc(error=PermissionError('denied'))
        new = self.doc([('value', 'a', 1)])
        result = compare(old, new)
        self.assertFalse(result['added'])
        self.assertEqual(len(result['newly_observed']), 1)

    def test_case_insensitive_identity_and_signal_changes_not_changes(self):
        old = self.doc([('Value', 'a', 1)])
        new = copy.deepcopy(old)
        new['entries'][0]['name'] = 'VALUE'
        new['entries'][0]['reasons'] = ['different triage rule']
        self.assertEqual(len(compare(old, new)['unchanged']), 1)

    def test_malformed_schema_and_duplicate_fields(self):
        for raw in ('no json', '{}', '[]', '{"schema":1,"schema":2}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                evidence.loads(raw)
        document = self.doc()
        document['schema'] = 'future-schema'
        with self.assertRaises(ValueError):
            evidence.loads(json.dumps(document))

    def test_duplicate_identities_and_bad_binary_rejected(self):
        document = self.doc([('value', b'\xff', 3)])
        duplicate = copy.deepcopy(document['entries'][0])
        duplicate['name'] = 'VALUE'
        document['entries'].append(duplicate)
        with self.assertRaises(ValueError):
            evidence.validate(document)
        document['entries'].pop()
        document['entries'][0]['data']['value'] = 'zz'
        with self.assertRaises(ValueError):
            evidence.validate(document)
        document = self.doc()
        document['coverage'].append(document['coverage'][0])
        with self.assertRaises(ValueError):
            evidence.validate(document)

    def test_invalid_view_and_payload_types(self):
        document = self.doc([('value', 'text', 1)])
        for field, value in (('view', 'native'), ('value_type', True), ('reasons', 'text'),
                             ('data', {'kind': 'integer', 'value': True})):
            bad = copy.deepcopy(document)
            bad['entries'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.validate(bad)

    def test_import_is_data_not_execution(self):
        value = '__import__("os").system("should never execute")'
        document = self.doc([('data', value, 1)])
        self.assertEqual(evidence.loads(evidence.dumps(document))['entries'][0]['data']['value'], value)

    def test_registry_type_kind_range_and_coverage_consistency(self):
        for value_type, data in (
                (4, {'kind': 'string', 'value': 'not a DWORD'}),
                (4, {'kind': 'integer', 'value': -1}),
                (4, {'kind': 'integer', 'value': 2 ** 32}),
                (11, {'kind': 'integer', 'value': 2 ** 64}),
                (7, {'kind': 'bytes', 'value': '00'})):
            bad = self.doc([('value', 'a', 1)])
            bad['entries'][0].update(value_type=value_type, data=data)
            with self.subTest(value_type=value_type, data=data), self.assertRaises(ValueError):
                evidence.validate(bad)
        document = self.doc([('value', 'a', 1)])
        document['coverage'][0]['status'] = 'missing'
        with self.assertRaises(ValueError):
            evidence.validate(document)
        document['coverage'][0]['status'] = 'error'
        evidence.validate(document)  # A partial enumeration may retain values.
        for kind, maximum in ((4, 2 ** 32 - 1), (11, 2 ** 64 - 1)):
            evidence.validate(self.doc([('value', maximum, kind)]))

    def test_cpython_binary_types_and_empty_binary_none_round_trip(self):
        values = [('link', b'link-bytes', 6), ('big-endian', b'\x00\x00\x00\x01', 5),
                  ('empty-binary', None, 3), ('empty-none', None, 0),
                  ('empty-resource', None, 8), ('empty-bytes', b'', 3)]
        document = self.doc(values)
        decoded = evidence.loads(evidence.dumps(document))
        self.assertEqual(decoded, document)
        self.assertEqual(document['entries'][2]['data'], {'kind': 'null', 'value': None})
        self.assertEqual(document['entries'][5]['data'], {'kind': 'bytes', 'value': ''})
        changed = copy.deepcopy(document)
        changed['entries'][2]['data'] = {'kind': 'bytes', 'value': ''}
        self.assertEqual(len(compare(document, changed)['changed']), 1)
        for value_type in (1, 2, 4, 7, 11):
            invalid = copy.deepcopy(document)
            invalid['entries'][2]['value_type'] = value_type
            with self.subTest(value_type=value_type), self.assertRaises(ValueError):
                evidence.validate(invalid)

    def test_source_confirmation_required_and_mismatch_blocked(self):
        old = self.doc([('value', 'a', 1)])
        new = self.doc()
        with self.assertRaisesRegex(ValueError, 'unverified'):
            evidence.compare(old, new)
        for field in ('host_label', 'account_label'):
            bad = copy.deepcopy(new)
            bad['source'][field] = 'different-source'
            with self.assertRaisesRegex(ValueError, 'mismatched'):
                compare(old, bad)
        new['source']['account_label'] = ''
        with self.assertRaisesRegex(ValueError, 'missing'):
            compare(old, new)

    def test_scan_timestamp_is_frozen_and_export_time_is_separate(self):
        from dataclasses import FrozenInstanceError
        from unittest.mock import patch
        registry = FakeRegistry()
        report = scan_registry(registry)
        with self.assertRaises(FrozenInstanceError):
            report.scan_started_utc = 'later'
        first = evidence.to_document(report)
        second = evidence.to_document(report)
        self.assertEqual(first['scan_started_utc'], second['scan_started_utc'])
        self.assertEqual(first['scan_started_utc'], report.scan_started_utc)
        self.assertIn('exported_utc', first)
        first['scan_started_utc'] = 'not-a-time'
        with self.assertRaises(ValueError):
            evidence.validate(first)

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            evidence.loads(' ' * (evidence.MAX_BYTES + 1))


if __name__ == '__main__':
    unittest.main()
