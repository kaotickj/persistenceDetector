"""Compose read-only collectors; cancellation is cooperative at stage boundaries."""
from persistence_core import scan_registry
import copy


class ScanCancelled(Exception):
    """The new snapshot is discarded; callers may retain their previous result."""


def scan_audit(registry, view='64-bit', powershell=True, encoded=True,
               external_provider=None, progress=None, cancelled=None):
    progress = progress or (lambda message: None)
    cancelled = cancelled or (lambda: False)

    def checkpoint():
        if cancelled():
            raise ScanCancelled('Scan cancelled; unfinished snapshot discarded')

    checkpoint()
    progress('1/4 · Registry inventory')
    report = scan_registry(registry, view, powershell, encoded)
    checkpoint()
    if external_provider is not None:
        stages = [('External inventory', external_provider)]
    else:
        from external_collectors import collect_tasks, collect_startup, collect_wmi
        stages = [('2/4 · Scheduled tasks', collect_tasks),
                  ('3/4 · Startup folders', collect_startup),
                  ('4/4 · WMI subscriptions', collect_wmi)]
    for label, provider in stages:
        checkpoint()
        progress(label)
        external = provider()
        checkpoint()
        report.observations.extend(copy.deepcopy(external['observations']))
        report.collector_coverage.extend(copy.deepcopy(external['collector_coverage']))
    checkpoint()
    return report
