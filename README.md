# Persistence Detector

A Windows persistence **auditor**, not a malware verdict or a clean-machine certificate.

## Build 0.2.0+build.2 — evidence and baseline comparison

This source build separates a cross-platform, testable collection/triage core from
the existing Tk interface. The PyQt6 interface and wider collectors are future
work, not features delivered by this build. Existing executables in `dist/` are
**older builds** and do not contain these safety changes. Run the source instead.

### What is collected

For the selected 32-bit or 64-bit registry view:

- HKCU and HKLM `Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` values.
- HKLM `System\CurrentControlSet\Services\<service>` `ImagePath` values,
  including driver registrations.
- `Services\<service>\Parameters` `ServiceDll` values.

All these values are inventoried in the core report. The GUI lists review
indicators, inventory counts, and coverage errors. **Full inventory** displays all
collected values plus coverage in a structured JSON view.
A collected service/driver registration does **not** establish that it runs at boot,
is enabled, or is malicious. Startup state, signatures and file reputation are
not evaluated. Registry views may share keys, particularly `SYSTEM`; do not treat
results from two views as two distinct installations.

### What a finding means

PowerShell-associated commands and encoded-command arguments are **review
signals**. Legitimate software and administrators use them. Generic printable
Base64, words such as “virus,” and unrelated `-enc` substrings are no longer
classified as malware. Strict, bounded UTF-16LE Base64 inspection never executes
the decoded content. This lightweight string heuristic is not a full Windows
command-line parser and can miss obfuscation or flag benign references.

No indicators found means only that no enabled indicators matched in locations
successfully read. It does not prove a machine clean. Turning both options off
still collects inventory, but produces no heuristic findings. Permission and
mid-enumeration errors are shown as coverage errors; absent optional keys are
counted separately. HKCU means the account running the process, not all users.
Elevating with another account changes that scope.

### Not yet covered

Scheduled tasks, startup folders, WMI subscriptions, other users' hives, Winlogon,
IFEO, AppInit, COM/shell-extension resolution, browser extensions, boot mechanisms,
and other persistence families are **not scanned**. The previous shallow IE and
shell-extension probes did not resolve their subkeys/COM registrations; they have
been removed rather than presented as meaningful coverage.

### Safety changes

Deletion and `.reg` export are disabled/removed until a separately tested,
type-correct backup and identity-bound remediation workflow exists. There is no
registry write path, recursive retry, or command execution in the collector.
Findings preserve the original hive, path, registry view, value name, type and data
snapshot; changing the view selector cannot retarget an existing finding.
No reputation/network lookup is performed by scans. Existing help/donation links
open a browser only when clicked.

## Run from source (Windows)

Use a fresh Python 3.7+ environment with Tkinter; no third-party packages needed.
Do not use the historical checked-in virtual environment directories.

```sh
git clone https://github.com/kaotickj/persistenceDetector.git
cd persistenceDetector
python detectpersist.py
```

Choose the view and enabled signals, then click **Check Registry**. On 64-bit
Windows inspect both views separately. On 32-bit Windows select 32-bit. Results
replace the prior scan; collection is synchronous in this transitional Tk GUI.
Use least privilege first; unreadable keys remain explicitly unassessed.

## JSON evidence and baselines

After scanning, **Export JSON** saves the current snapshot (not a fresh scan).
Reports may contain sensitive usernames, paths and command arguments. Choose the
save location deliberately and review/redact before sharing. This is evidence,
**not** a `.reg` backup or a remediation/import mechanism.

Schema `persistence-detector/evidence-v1` records the build, immutable UTC scan-start
timestamp, separate UTC export timestamp, informational host/account labels,
collector/view scope, signal options, typed values, review reasons, and per-key
coverage. Scan-start time is captured once before collection and retained across exports.
Neither timestamp implies an atomic registry snapshot.
Binary values are lowercase hex; CPython zero-length binary/default `None`
values use a distinct `null` kind (preserving the difference from empty bytes).
`REG_LINK` and `REG_DWORD_BIG_ENDIAN` retain the bytes returned by `winreg`, not
coerced strings/integers. Multi-strings remain ordered string arrays;
registry type changes are preserved. Report reads/writes are capped at 10 MiB.
Malformed or unsupported schemas, ambiguous duplicate identities/JSON fields,
and invalid typed data are rejected. Imported content is only parsed as JSON;
no command, script, registry import, or path from that content is executed.

**Compare baseline** selects an earlier exported JSON report and compares it with
the last scan snapshot. Comparison requires explicit confirmation that both scans
came from the **same machine and Windows account**. Host/account labels are only
informational (not authenticated machine IDs or SIDs); mismatched or missing labels
block comparison, and matching labels alone do not authorize it. Cancel if source
continuity is uncertain. The core API also requires `same_source_confirmed=True`.
Results mean inventory differences, not malware verdicts:

- **Added**: new identity, with successful prior coverage of its exact key.
- **Newly observed**: present now, but prior coverage cannot establish absence.
- **Changed**: same case-insensitive hive/path/view/value-name identity, different
  registry type or typed data. Changed review reasons alone do not count.
- **Removed**: no longer observed, with successful current coverage of its exact
  key (including an absent optional key).
- **Unassessed**: not observed now, but relevant coverage failed, is absent, or is
  for a different registry view. Never reported as removed.
- **Unchanged**: same observed value and type, not proof of trustworthiness.

If a service disappears entirely and no current per-service coverage record
exists, its old values conservatively remain unassessed even if the parent
service list was read. Baselines are user-supplied observations, not authenticated
proof. The current GUI summarizes changes and identities; original complete
values remain in each exported report. Selecting a baseline never changes scan
settings or registry data. Canceling a dialog leaves the displayed result intact.

## Offline tests (Linux, macOS or Windows)

```sh
python -m unittest discover -s tests -v
python -m py_compile persistence_core.py evidence.py detectpersist.py
```

Tests use an injected fake registry, including access denial, concurrent changes,
subkey traversal, registry-view identity, strict encoding checks, and read-only
regressions. They never inspect or modify the host registry or execute collected
commands. Windows `winreg`, live GUI behavior and executable packaging still need
integration testing on an isolated Windows VM. No Actions workflow or paid runner
is introduced.

## Next milestones

1. Inventory adapters for scheduled tasks, startup folders and WMI, each with
   explicit coverage/error reporting and fixture-driven tests.
2. Additional registry persistence families and evidence enrichment, without
   claiming that absence of findings proves cleanliness.
3. PyQt6 black/blue/white interface, background collection, background progress and richer evidence presentation.
4. Windows VM integration and packaging. Remediation remains separately gated.

Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Licensed under [GPL-3.0](LICENSE).
