"""Compose read-only collectors; injected providers keep fixture tests offline."""
from persistence_core import scan_registry
import copy


def scan_audit(registry, view='64-bit', powershell=True, encoded=True, external_provider=None):
    report = scan_registry(registry, view, powershell, encoded)
    if external_provider is None:
        from external_collectors import collect_external
        external_provider = collect_external
    external = external_provider()
    report.observations.extend(copy.deepcopy(external['observations']))
    report.collector_coverage.extend(copy.deepcopy(external['collector_coverage']))
    return report
