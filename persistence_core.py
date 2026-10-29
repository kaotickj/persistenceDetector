"""Read-only registry inventory and explainable triage; no Windows import required.

The injected registry API is winreg (or a test double). Collected command strings
are data only: never executed, expanded, imported, or used as filesystem paths.
"""
import base64
import binascii
import re
import getpass
import platform
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, List, Tuple

BUILD = "0.2.0+build.3"
RUN_PATHS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)
SERVICES_PATH = r"System\CurrentControlSet\Services"
# This is triage, not a full Windows command-line parser. Match executable tokens,
# not e.g. powershell-notes.txt, or an arbitrary occurrence of '-enc'.
POWERSHELL = re.compile(r'(?:^|[\s"\\/])(?:powershell|pwsh)(?:\.exe)?(?=$|[\s"])', re.I)
ENCODED = re.compile(r'(?:^|\s)-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)(?=\s|$)', re.I)


@dataclass(frozen=True)
class RegistryValue:
    hive: str
    path: str
    view: str
    name: str
    data: Any
    value_type: int
    category: str


@dataclass(frozen=True)
class Finding:
    value: RegistryValue
    reasons: Tuple[str, ...]


@dataclass(frozen=True)
class Coverage:
    hive: str
    path: str
    view: str
    status: str  # scanned, missing, error
    detail: str = ""


def source_labels():
    # Informational labels, not authenticated machine/account identifiers.
    try:
        account = getpass.getuser()
    except (OSError, KeyError):
        account = ""
    return (platform.node(), account)


@dataclass(frozen=True)
class ScanReport:
    scan_started_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_labels: Tuple[str, str] = field(default_factory=source_labels)
    view: str = "64-bit"
    powershell: bool = True
    encoded: bool = True
    entries: List[RegistryValue] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    coverage: List[Coverage] = field(default_factory=list)
    observations: List[dict] = field(default_factory=list)
    collector_coverage: List[dict] = field(default_factory=list)

    @property
    def errors(self):
        return [item for item in self.coverage if item.status == "error"]


def indicators(data, powershell=True, encoded=True):
    """Explain review signals, never return a malware verdict.

    Generic Base64 and scary words are not signals. EncodedCommand is inspected
    only in a PowerShell-associated string, with bounded, strict decoding.
    """
    if not isinstance(data, str) or not POWERSHELL.search(data):
        return ()
    reasons = []
    if powershell:
        reasons.append("PowerShell-associated command; legitimate administration is common")
    if encoded:
        match = ENCODED.search(data)
        if match:
            argument = data[match.end():].lstrip()
            if argument.startswith(('"', "'")):
                quote = argument[0]
                end = argument.find(quote, 1)
                token = argument[1:end] if end != -1 else argument[1:]
                malformed_quote = end == -1
            else:
                token = argument.split(None, 1)[0] if argument else ""
                malformed_quote = False
            if not token or malformed_quote:
                reasons.append("PowerShell encoded-command argument is missing or malformed; review manually")
            elif len(token) > 16384:
                reasons.append("PowerShell encoded-command argument exceeds inspection limit")
            else:
                try:
                    payload = base64.b64decode(token, validate=True)
                    decoded = payload.decode("utf-16le")
                    if decoded.strip():
                        reasons.append("PowerShell encoded-command argument (UTF-16LE Base64); review intent")
                except (ValueError, UnicodeError, binascii.Error):
                    reasons.append("PowerShell encoded-command argument is malformed; review manually")
    return tuple(reasons)


def scan_registry(registry, view="64-bit", powershell=True, encoded=True):
    """Inventory Run/RunOnce plus service/driver ImagePath and ServiceDll values.

    A missing optional location is recorded separately from permission/API errors.
    Partial reads are retained and errors are visible. Registry snapshots can race
    with changes by other processes; this function never attempts remediation.
    """
    if view not in ("32-bit", "64-bit"):
        raise ValueError("view must be '32-bit' or '64-bit'")
    access = registry.KEY_READ | (registry.KEY_WOW64_32KEY if view == "32-bit" else registry.KEY_WOW64_64KEY)
    report = ScanReport(view=view, powershell=powershell, encoded=encoded)

    def collect(hive, path, category, names=None, optional=True):
        opened = False
        try:
            with registry.OpenKey(getattr(registry, hive), path, 0, access) as key:
                opened = True
                count = registry.QueryInfoKey(key)[1]
                for index in range(count):
                    name, data, kind = registry.EnumValue(key, index)
                    if names is not None and name.lower() not in names:
                        continue
                    # Freeze mutable multi-string/binary test inputs into snapshots.
                    if isinstance(data, list):
                        data = tuple(data)
                    elif isinstance(data, bytearray):
                        data = bytes(data)
                    value = RegistryValue(hive, path, view, name, data, kind, category)
                    report.entries.append(value)
                    reasons = indicators(data, powershell, encoded)
                    if reasons:
                        report.findings.append(Finding(value, reasons))
            report.coverage.append(Coverage(hive, path, view, "scanned"))
        except OSError as exc:
            status = "missing" if optional and isinstance(exc, FileNotFoundError) and not opened else "error"
            report.coverage.append(Coverage(hive, path, view, status, str(exc)))

    for hive in ("HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"):
        for path in RUN_PATHS:
            collect(hive, path, "Run/RunOnce")
    hive = "HKEY_LOCAL_MACHINE"
    opened = False
    try:
        with registry.OpenKey(getattr(registry, hive), SERVICES_PATH, 0, access) as key:
            opened = True
            count = registry.QueryInfoKey(key)[0]
            for index in range(count):
                service = registry.EnumKey(key, index)
                path = SERVICES_PATH + "\\" + service
                collect(hive, path, "Service/driver", {"imagepath"}, optional=False)
                collect(hive, path + r"\Parameters", "Service DLL", {"servicedll"})
        report.coverage.append(Coverage(hive, SERVICES_PATH, view, "scanned"))
    except OSError as exc:
        report.coverage.append(Coverage(hive, SERVICES_PATH, view, "error", str(exc)))
    return report
