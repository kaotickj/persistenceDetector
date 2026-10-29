# Persistence Detector

A Windows persistence **auditor**, not a malware verdict or a clean-machine certificate.

## Build 0.2.0+build.3 — scheduled-task and startup inventory

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

### Scheduled tasks and startup folders

Build 3 adds observations (not malware verdicts) beyond the registry:

- **Scheduled tasks visible to the current account**: a fixed, module-qualified
  `ScheduledTasks\Get-ScheduledTask` query records task identity, state, enabled
  flag, principal and action metadata. Commands/arguments remain text. The system
  PowerShell executable is resolved using `GetSystemDirectoryW`; profiles are
  disabled, no shell is used, and module loading is restricted to system modules.
  This is not an all-users/all-permissions guarantee. Task triggers, signatures,
  full XML, COM-handler resolution and action execution are not included.
- **Current-account Startup and shared Common Startup folders**: paths come from
  `SHGetKnownFolderPath`, not guessed profile paths. Only immediate entry metadata
  is read: name, size, modification time and kind. No recursion, file content,
  hashing, shortcut-target resolution, scripts or executables are opened/run.
  Reparse entries are listed as such without following them; root/ancestor
  reparse points and network/device paths are skipped with a coverage error.
  Shared Common Startup does not mean every user's private Startup folder.

Task queries have a 20-second process timeout, 2 MiB output limit and 5,000-task
limit. Each startup folder has a 5,000-entry limit and cooperative 20-second
budget. Filesystem calls can block beyond that budget; metadata-only checks are
not an atomic snapshot and cannot eliminate path-change races. Errors and partial
reads are retained visibly, never reported as an empty successful scan. The
transitional Tk interface still collects synchronously and may be unresponsive
during these calls. Use **Full inventory** or JSON export for task/startup details;
registry heuristic checkboxes do not filter these metadata collectors.

Native integration is still unverified on Windows. Unsupported/blocked native
queries produce coverage errors rather than inventing results. Fixture tests do
not invoke live task or startup scans on the development host.

Primary API references: [Get-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask),
[SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath),
and [known folder identifiers](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid).

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

WMI subscriptions, other users' hives/startup folders, Winlogon,
IFEO, AppInit, COM/shell-extension resolution, browser extensions, boot mechanisms,
and other persistence families are **not scanned**. The previous shallow IE and
shell-extension probes did not resolve their subkeys/COM registrations; they have
been removed rather than presented as meaningful coverage.

### Safety changes

Deletion and `.reg` export are disabled/removed until a separately tested,
type-correct backup and identity-bound remediation workflow exists. There is no
registry write path, recursive retry, or execution of collected commands. The task
collector runs a fixed read-only Windows PowerShell query, never task actions.
Findings preserve the original hive, path, registry view, value name, type and data
snapshot; changing the view selector cannot retarget an existing finding.
No reputation lookup is performed by scans. Startup paths on network/device
locations are skipped with a coverage error. The native task query runs locally. Existing help/donation links
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

Schema `persistence-detector/evidence-v2` records the build, immutable UTC scan-start
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

Version 1 evidence is strictly migrated on import: its original registry values
are preserved, `origin_schema` remains v1, and task/startup coverage is marked
unassessed. An old report's lack of those collectors never implies absence. New
exports include `observations` and `collector_coverage` alongside the original
registry `entries` and `coverage` arrays.

**Compare baseline** selects an earlier exported JSON report and compares it with
the last scan snapshot. Comparison requires explicit confirmation that both scans
came from the **same machine, Windows account and privilege context**. Host/account labels are only
informational (not authenticated machine IDs or SIDs); mismatched or missing labels
block comparison, and matching labels alone do not authorize it. Cancel if source
continuity is uncertain. The core API also requires `same_source_confirmed=True`.
Results mean inventory differences, not malware verdicts:

- **Added**: new identity, with successful prior coverage of its exact key.
- **Newly observed**: present now, but prior coverage cannot establish absence.
- **Changed**: same case-insensitive hive/path/view/value-name identity, different
  registry type or typed data (or task/startup metadata). Changed review reasons alone do not count.
- **Removed**: no longer observed, with successful current coverage of its exact
  registry key or external collector target (including an absent optional folder).
  Startup comparison is bound to the normalized resolved folder path, not merely
  its current-user/shared role; redirection makes old observations unassessed.
  Tasks are never marked removed based on absence: permissions/elevation changes
  can hide them. A newly seen task is likewise newly observed, not proven added.
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
python -m py_compile persistence_core.py evidence.py external_collectors.py audit.py detectpersist.py
```

Tests use an injected fake registry, including access denial, concurrent changes,
subkey traversal, registry-view identity, strict encoding checks, and read-only
regressions. They never inspect or modify the host registry or execute collected
commands. Windows `winreg`, live GUI behavior and executable packaging still need
integration testing on an isolated Windows VM. No Actions workflow or paid runner
is introduced.

## Next milestones

1. WMI subscription inventory, richer task evidence and optional safe shortcut
   analysis, each with explicit coverage/error reporting and fixture-driven tests.
2. Additional registry persistence families and evidence enrichment, without
   claiming that absence of findings proves cleanliness.
3. PyQt6 black/blue/white interface, background collection, background progress and richer evidence presentation.
4. Windows VM integration and packaging. Remediation remains separately gated.

Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Licensed under [GPL-3.0](LICENSE).
