"""Versioned JSON evidence and conservative baseline comparison (data only)."""
import json
from datetime import datetime, timezone

from persistence_core import BUILD

SCHEMA = 'persistence-detector/evidence-v1'
MAX_BYTES = 10 * 1024 * 1024
SCOPE = ['current-user-and-machine-run-runonce', 'services-imagepath-servicedll']


def identity(value):
    return tuple(value[key].casefold() for key in ('hive', 'path', 'view', 'name'))


def _encode(data):
    if data is None:
        return {'kind': 'null', 'value': None}
    if isinstance(data, bytes):
        return {'kind': 'bytes', 'value': data.hex()}
    if isinstance(data, tuple):
        return {'kind': 'strings', 'value': list(data)}
    if isinstance(data, str):
        return {'kind': 'string', 'value': data}
    if type(data) is int:
        return {'kind': 'integer', 'value': data}
    raise ValueError('Unsupported registry data type')


def to_document(report):
    document = {
        'schema': SCHEMA, 'build': BUILD,
        'scan_started_utc': report.scan_started_utc,
        'exported_utc': datetime.now(timezone.utc).isoformat(),
        'source': {'host_label': report.source_labels[0], 'account_label': report.source_labels[1],
                   'verification': 'operator-confirmation-required'},
        'scope': {'collectors': list(SCOPE), 'views': [report.view],
                  'signals': {'powershell': report.powershell, 'encoded': report.encoded}},
        'entries': [], 'coverage': [],
    }
    reasons = {id(item.value): list(item.reasons) for item in report.findings}
    for value in report.entries:
        document['entries'].append({
            'hive': value.hive, 'path': value.path, 'view': value.view,
            'name': value.name, 'value_type': value.value_type,
            'category': value.category, 'data': _encode(value.data),
            'reasons': reasons.get(id(value), []),
        })
    for item in report.coverage:
        document['coverage'].append({
            'hive': item.hive, 'path': item.path, 'view': item.view,
            'status': item.status, 'detail': item.detail,
        })
    validate(document)
    return document


def _keys(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('Invalid evidence object fields')


def _strings(value, keys):
    if any(not isinstance(value[key], str) for key in keys):
        raise ValueError('Expected evidence string')


def validate(document):
    """Reject malformed/ambiguous baselines rather than silently trusting them."""
    _keys(document, ('schema', 'build', 'scan_started_utc', 'exported_utc', 'source', 'scope', 'entries', 'coverage'))
    if document['schema'] != SCHEMA:
        raise ValueError('Unsupported evidence schema')
    _strings(document, ('build', 'scan_started_utc', 'exported_utc'))
    for field in ('scan_started_utc', 'exported_utc'):
        try:
            stamp = datetime.fromisoformat(document[field])
            if stamp.tzinfo is None or stamp.utcoffset().total_seconds() != 0:
                raise ValueError('Expected UTC timestamp')
        except (ValueError, OverflowError) as exc:
            raise ValueError('Invalid UTC evidence timestamp') from exc
    _keys(document['source'], ('host_label', 'account_label', 'verification'))
    _strings(document['source'], ('host_label', 'account_label', 'verification'))
    if document['source']['verification'] != 'operator-confirmation-required':
        raise ValueError('Unsupported source verification')
    scope = document['scope']
    _keys(scope, ('collectors', 'views', 'signals'))
    if scope['collectors'] != SCOPE:
        raise ValueError('Unsupported collector scope')
    if not isinstance(scope['views'], list) or not scope['views'] or any(
            view not in ('32-bit', '64-bit') for view in scope['views']) or len(set(scope['views'])) != len(scope['views']):
        raise ValueError('Invalid view scope')
    _keys(scope['signals'], ('powershell', 'encoded'))
    if any(type(item) is not bool for item in scope['signals'].values()):
        raise ValueError('Invalid signal options')
    for collection in ('entries', 'coverage'):
        if not isinstance(document[collection], list):
            raise ValueError('Expected evidence list')
    seen = set()
    for value in document['entries']:
        _keys(value, ('hive', 'path', 'view', 'name', 'value_type', 'category', 'data', 'reasons'))
        _strings(value, ('hive', 'path', 'view', 'name', 'category'))
        if value['view'] not in scope['views'] or value['hive'] not in ('HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE'):
            raise ValueError('Entry outside declared registry view/hive')
        if type(value['value_type']) is not int or not 0 <= value['value_type'] <= 0xffffffff:
            raise ValueError('Invalid registry value type')
        if not isinstance(value['reasons'], list) or any(not isinstance(x, str) for x in value['reasons']):
            raise ValueError('Invalid reasons')
        data = value['data']
        _keys(data, ('kind', 'value'))
        kind, raw = data['kind'], data['value']
        valid = ((kind == 'null' and raw is None) or
                 (kind == 'string' and isinstance(raw, str)) or
                 (kind == 'integer' and type(raw) is int) or
                 (kind == 'strings' and isinstance(raw, list) and all(isinstance(x, str) for x in raw)))
        if kind == 'bytes' and isinstance(raw, str):
            try:
                valid = bytes.fromhex(raw).hex() == raw
            except ValueError:
                valid = False
        if not valid:
            raise ValueError('Invalid typed registry data')
        value_type = value['value_type']
        expected = {1: 'string', 2: 'string', 4: 'integer',
                    7: 'strings', 11: 'integer'}.get(value_type, 'bytes')
        # CPython Reg2Py returns bytes for REG_LINK, DWORD_BIG_ENDIAN and
        # other non-special types; zero-length binary/default data is None.
        if kind != expected and not (expected == 'bytes' and kind == 'null'):
            raise ValueError('Registry type and data kind disagree')
        if kind == 'integer' and not 0 <= raw < (1 << (64 if value_type == 11 else 32)):
            raise ValueError('Registry integer outside unsigned type range')
        key = identity(value)
        if key in seen:
            raise ValueError('Duplicate registry identity')
        seen.add(key)
    seen = set()
    coverage_status = {}
    for item in document['coverage']:
        _keys(item, ('hive', 'path', 'view', 'status', 'detail'))
        _strings(item, ('hive', 'path', 'view', 'status', 'detail'))
        if item['view'] not in scope['views'] or item['hive'] not in ('HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE'):
            raise ValueError('Coverage outside declared registry view/hive')
        if item['status'] not in ('scanned', 'missing', 'error'):
            raise ValueError('Invalid coverage status')
        key = tuple(item[k].casefold() for k in ('hive', 'path', 'view'))
        if key in seen:
            raise ValueError('Duplicate coverage identity')
        seen.add(key)
        coverage_status[key] = item['status']
    for value in document['entries']:
        status = coverage_status.get(identity(value)[:3])
        if status not in ('scanned', 'error'):
            raise ValueError('Entry contradicts missing or absent key coverage')
    return document


def dumps(document):
    validate(document)
    result = json.dumps(document, ensure_ascii=True, indent=2, allow_nan=False) + '\n'
    if len(result.encode('utf-8')) > MAX_BYTES:
        raise ValueError('Evidence exceeds 10 MiB limit')
    return result


def loads(text):
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('Evidence exceeds 10 MiB limit or is not text')

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON field')
            result[key] = value
        return result

    try:
        document = json.loads(text, object_pairs_hook=unique_pairs)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('Malformed evidence JSON') from exc
    return validate(document)


def compare(baseline, current, same_source_confirmed=False):
    """Compare inventory, not malware status; absence requires current key coverage.

    Never infer removal from a failed/unscanned view or a missing coverage record.
    Additions also require successful baseline coverage, otherwise 'newly observed'.
    Finding/reason changes are not registry changes. Case-insensitive identities
    reflect Windows registry naming; original spelling stays in the evidence.
    """
    validate(baseline)
    validate(current)
    if same_source_confirmed is not True:
        raise ValueError('Comparison unverified: explicitly confirm the same machine and account')
    for key in ('host_label', 'account_label'):
        old_label, new_label = baseline['source'][key], current['source'][key]
        if not old_label or not new_label or old_label.casefold() != new_label.casefold():
            raise ValueError('Comparison blocked: missing or mismatched source machine/account labels')
    old = {identity(v): v for v in baseline['entries']}
    new = {identity(v): v for v in current['entries']}

    def covered_keys(doc):
        return {tuple(c[k].casefold() for k in ('hive', 'path', 'view'))
                for c in doc['coverage'] if c['status'] in ('scanned', 'missing')}

    old_coverage, new_coverage = covered_keys(baseline), covered_keys(current)

    result = {key: [] for key in ('added', 'changed', 'removed', 'unassessed', 'newly_observed', 'unchanged')}
    for key, value in new.items():
        if key not in old:
            result['added' if key[:3] in old_coverage else 'newly_observed'].append(value)
        elif (value['value_type'], value['data']) != (old[key]['value_type'], old[key]['data']):
            result['changed'].append({'before': old[key], 'after': value})
        else:
            result['unchanged'].append(value)
    for key, value in old.items():
        if key not in new:
            result['removed' if key[:3] in new_coverage else 'unassessed'].append(value)
    return result
