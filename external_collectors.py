"""Bounded read-only metadata collectors; collected strings never become commands.

Windows integration is pending. Filesystem deadlines are cooperative: a blocked
OS metadata call cannot be interrupted. No shortcut resolution/content reads.
"""
import ctypes
import json
import ntpath
import os
import stat
import subprocess
import threading
import time
import uuid

MAX_ITEMS = 5000
MAX_OUTPUT = 2 * 1024 * 1024
TIMEOUT = 20
TASK_TARGET = 'local-visible-tasks'
FOLDERS = {
    'current-user-startup': 'B97D20BB-F46A-4C97-BA10-5E3608430854',
    'common-startup': '82A5EA35-D9CD-47C5-9629-E15D2F714E6E',
}
# Only the fixed TASK_QUERY and WMI_QUERY constants may be passed to PowerShell. No values obtained
# from a task, baseline, filename or GUI control are interpolated into it.
TASK_QUERY = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$rows = New-Object System.Collections.Generic.List[object]
ScheduledTasks\Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
    if ($rows.Count -ge 5000) { throw 'Task enumeration exceeds 5000 item limit' }
    $t = $_
    $actions = @($t.Actions | ForEach-Object {
        [ordered]@{Type=[string]$_.CimClass.CimClassName; Execute=[string]$_.Execute;
        Arguments=[string]$_.Arguments; WorkingDirectory=[string]$_.WorkingDirectory;
        ClassId=[string]$_.ClassId; Data=[string]$_.Data}
    })
    $rows.Add([ordered]@{TaskPath=[string]$t.TaskPath; TaskName=[string]$t.TaskName;
        State=[string]$t.State; Enabled=[bool]$t.Settings.Enabled;
        Principal=[string]$t.Principal.UserId;
        Actions=ConvertTo-Json -InputObject $actions -Depth 4 -Compress})
}
ConvertTo-Json -InputObject @($rows.ToArray()) -Depth 4 -Compress
'''


WMI_TARGET = 'root/subscription'
WMI_QUERY = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
function Get-RelativePath($instance, [int]$depth = 0) {
    if ($depth -gt 4) { throw 'WMI reference nesting limit exceeded' }
    $class = [string]$instance.CimSystemProperties.ClassName
    $keys = @($instance.CimInstanceProperties | Where-Object {
        ($_.Flags -band [Microsoft.Management.Infrastructure.CimFlags]::Key) -ne 0
    } | Sort-Object Name)
    if (-not $class -or $keys.Count -eq 0) { throw 'WMI instance has no stable key identity' }
    $parts = @($keys | ForEach-Object {
        $p = $_
        if ($null -eq $p.Value) { throw 'WMI key value is missing' }
        if ([string]$p.CimType -eq 'Reference') {
            $v = Get-ReferencePath $p.Value ($depth + 1)
            $v = '"' + $v.Replace('\', '\\').Replace('"', '\"') + '"'
        } elseif ([string]$p.CimType -eq 'String') {
            $v = '"' + ([string]$p.Value).Replace('\', '\\').Replace('"', '\"') + '"'
        } elseif ([string]$p.CimType -eq 'Boolean') {
            $v = ([string]$p.Value).ToUpperInvariant()
        } elseif ([string]$p.CimType -match '^(SInt|UInt)(8|16|32|64)$') {
            $v = [Convert]::ToString($p.Value, [Globalization.CultureInfo]::InvariantCulture)
        } else { throw 'Unsupported WMI key type' }
        ([string]$p.Name) + '=' + $v
    })
    return $class + '.' + ($parts -join ',')
}
function Get-ReferencePath($instance, [int]$depth = 0) {
    # Preserve reference provenance without following the reference or querying
    # its namespace/server. Missing fields remain explicit, not silently local.
    $relative = Get-RelativePath $instance $depth
    $server = [string]$instance.CimSystemProperties.ServerName
    $namespace = [string]$instance.CimSystemProperties.Namespace
    if (-not $server) { $server = '<unspecified>' }
    if (-not $namespace) { $namespace = '<unspecified>' }
    return '\\' + $server + '\' + $namespace.Replace('/', '\') + ':' + $relative
}
$rows = New-Object System.Collections.Generic.List[object]
foreach ($class in @('__EventFilter', '__EventConsumer', '__FilterToConsumerBinding')) {
    # No -Shallow: include subclasses, especially concrete event consumers.
    CimCmdlets\Get-CimInstance -Namespace 'root/subscription' -ClassName $class -OperationTimeoutSec 15 -ErrorAction Stop | ForEach-Object {
        if ($rows.Count -ge 5000) { throw 'WMI enumeration exceeds 5000 item limit' }
        $o = $_
        $properties = [ordered]@{}
        foreach ($p in @($o.CimInstanceProperties | Sort-Object Name)) {
            if ([string]$p.CimType -eq 'Reference' -and $null -ne $p.Value) {
                $properties[$p.Name] = Get-ReferencePath $p.Value
            } elseif ($p.Value -is [Array]) {
                $properties[$p.Name] = ConvertTo-Json -InputObject $p.Value -Depth 3 -Compress
            } elseif ($null -eq $p.Value) {
                $properties[$p.Name] = $null
            } else {
                $properties[$p.Name] = [string]$p.Value
            }
        }
        $rows.Add([ordered]@{
            ClassName=[string]$o.CimSystemProperties.ClassName;
            RelativePath=Get-RelativePath $o;
            Query=[string]$o.Query; EventNamespace=[string]$o.EventNamespace;
            CommandLineTemplate=[string]$o.CommandLineTemplate; ExecutablePath=[string]$o.ExecutablePath;
            ScriptText=[string]$o.ScriptText; ScriptFileName=[string]$o.ScriptFileName;
            ScriptingEngine=[string]$o.ScriptingEngine;
            Filter=[string]$properties['Filter']; Consumer=[string]$properties['Consumer'];
            Properties=ConvertTo-Json -InputObject $properties -Depth 4 -Compress
        })
    }
}
ConvertTo-Json -InputObject @($rows.ToArray()) -Depth 4 -Compress
'''


def _system_directory():
    if os.name != 'nt':
        raise OSError('Windows native collector unavailable on this platform')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    count = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not count or count >= len(buffer):
        raise OSError('GetSystemDirectoryW failed')
    return buffer.value


def run_fixed_query(query, timeout=TIMEOUT, max_output=MAX_OUTPUT):
    """Allow only built-in read-only queries, with process/output bounds."""
    if query not in (TASK_QUERY, WMI_QUERY):
        raise ValueError("Only built-in inventory query constants are allowed")
    home = os.path.join(_system_directory(), 'WindowsPowerShell', 'v1.0')
    executable = os.path.join(home, 'powershell.exe')
    environment = dict(os.environ)
    # Do not auto-load a user-supplied ScheduledTasks module.
    environment['PSModulePath'] = os.path.join(home, 'Modules')
    process = subprocess.Popen(
        [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', query],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        shell=False, env=environment, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    chunks = []
    errors = []

    def read_output():
        size = 0
        try:
            while True:
                block = process.stdout.read(8192)
                if not block:
                    break
                size += len(block)
                if size > max_output:
                    errors.append('Inventory query exceeds output limit')
                    process.kill()
                    break
                chunks.append(block)
        except OSError as exc:
            errors.append(str(exc))

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise OSError('Inventory query timed out') from exc
    finally:
        reader.join(timeout=2)
        if not reader.is_alive():
            process.stdout.close()
    if reader.is_alive():
        raise OSError('Inventory query output reader did not finish')
    if errors:
        raise OSError(errors[0])
    if process.returncode:
        raise OSError('Inventory query failed (exit {}); coverage unknown'.format(process.returncode))
    return b''.join(chunks).decode('utf-8-sig')


def run_task_query(timeout=TIMEOUT, max_output=MAX_OUTPUT):
    return run_fixed_query(TASK_QUERY, timeout, max_output)


def run_wmi_query(timeout=TIMEOUT, max_output=MAX_OUTPUT):
    return run_fixed_query(WMI_QUERY, timeout, max_output)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate inventory JSON field')
        result[key] = value
    return result


def collect_tasks(runner=run_task_query):
    observations = []
    status, detail = 'scanned', 'Only tasks visible to the querying account; not proof of complete system visibility'
    try:
        raw = runner()
        if not isinstance(raw, str) or len(raw.encode('utf-8')) > MAX_OUTPUT:
            raise ValueError('Task query output exceeds limit or is not text')
        rows = json.loads(raw, object_pairs_hook=_unique_pairs)
        if not isinstance(rows, list) or len(rows) > MAX_ITEMS:
            raise ValueError('Invalid task list or task count limit exceeded')
        seen = set()
        expected = {'TaskPath', 'TaskName', 'State', 'Enabled', 'Principal', 'Actions'}
        for row in rows:
            if not isinstance(row, dict) or set(row) != expected:
                raise ValueError('Invalid task fields')
            if type(row['Enabled']) is not bool or any(not isinstance(row[key], str) for key in expected - {'Enabled'}):
                raise ValueError('Invalid task field type')
            if not row['TaskPath'].startswith('\\') or not row['TaskPath'].endswith('\\') or not row['TaskName'] or '\\' in row['TaskName']:
                raise ValueError('Invalid task identity')
            identity = row['TaskPath'] + row['TaskName']
            if identity.casefold() in seen:
                raise ValueError('Duplicate task identity')
            seen.add(identity.casefold())
            observations.append({'collector': 'scheduled-tasks', 'target': TASK_TARGET,
                                 'identity': identity, 'data': dict(row)})
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        status, detail = 'error', str(exc)
    return {'observations': observations, 'collector_coverage': [
        {'collector': 'scheduled-tasks', 'target': TASK_TARGET, 'location': '', 'status': status, 'detail': detail}]}


def collect_wmi(runner=run_wmi_query):
    """Inventory permanent-subscription objects; never invoke a consumer."""
    observations = []
    status = 'scanned'
    detail = 'Only visible root/subscription filters, consumers and bindings; other namespaces unassessed'
    try:
        raw = runner()
        if not isinstance(raw, str) or len(raw.encode('utf-8')) > MAX_OUTPUT:
            raise ValueError('WMI query output exceeds limit or is not text')
        rows = json.loads(raw, object_pairs_hook=_unique_pairs)
        if not isinstance(rows, list) or len(rows) > MAX_ITEMS:
            raise ValueError('Invalid WMI list or item count limit exceeded')
        expected = {'ClassName', 'RelativePath', 'Query', 'EventNamespace',
                    'CommandLineTemplate', 'ExecutablePath', 'ScriptText', 'ScriptFileName',
                    'ScriptingEngine', 'Filter', 'Consumer', 'Properties'}
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != expected or any(not isinstance(v, str) for v in row.values()):
                raise ValueError('Invalid WMI fields')
            if not row['ClassName'] or not row['RelativePath'].startswith(row['ClassName'] + '.'):
                raise ValueError('Invalid WMI stable identity')
            identity = row['ClassName'] + ':' + row['RelativePath']
            if identity.casefold() in seen:
                raise ValueError('Duplicate WMI identity')
            seen.add(identity.casefold())
            observations.append({'collector': 'wmi-subscriptions', 'target': WMI_TARGET,
                                 'identity': identity, 'data': dict(row)})
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        status, detail = 'error', str(exc)
    return {'observations': observations, 'collector_coverage': [
        {'collector': 'wmi-subscriptions', 'target': WMI_TARGET, 'location': '',
         'status': status, 'detail': detail}]}


def known_startup_folder(target):
    """Resolve current-account/shared Startup using SHGetKnownFolderPath."""
    if os.name != 'nt':
        raise OSError('Windows known folders unavailable on this platform')
    folder_id = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(FOLDERS[target]).bytes_le)
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    ole = ctypes.WinDLL('ole32', use_last_error=True)
    shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                         ctypes.POINTER(ctypes.c_void_p)]
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    pointer = ctypes.c_void_p()
    # KF_FLAG_DONT_VERIFY: resolve without probing filesystem here; no CREATE flag.
    result = shell.SHGetKnownFolderPath(ctypes.byref(folder_id), 0x4000, None, ctypes.byref(pointer))
    try:
        if result != 0:
            raise OSError('SHGetKnownFolderPath failed: 0x{:08x}'.format(result & 0xffffffff))
        return ctypes.wstring_at(pointer)
    finally:
        if pointer.value:
            ole.CoTaskMemFree(pointer)


def _reparse(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def collect_startup(resolver=known_startup_folder, scandir=os.scandir, lstat=os.lstat,
                    clock=time.monotonic, max_items=MAX_ITEMS, timeout=TIMEOUT):
    observations, coverage = [], []
    for target in FOLDERS:
        started = clock()
        status, detail = 'scanned', 'Top-level metadata only; shortcuts unresolved; no file content read'
        opened = False
        location = ''
        seen = set()
        try:
            folder = resolver(target)
            if not isinstance(folder, str) or not folder or not os.path.isabs(folder):
                raise ValueError('Startup folder is not an absolute path')
            path_module = ntpath if os.name == 'nt' else os.path
            location = path_module.normcase(path_module.normpath(folder))
            if ntpath.splitdrive(folder)[0].startswith('\\\\') or folder.startswith('\\\\'):
                raise OSError('Network/device startup paths are not inspected')
            # Reject root/ancestor reparse paths before enumeration. This is a
            # best-effort preflight, not a race-free filesystem snapshot.
            check = folder
            chain = []
            while True:
                chain.append(check)
                parent = os.path.dirname(check)
                if parent == check:
                    break
                check = parent
            # Check from filesystem root toward leaf: inspecting a descendant
            # first could already traverse an intermediate junction/symlink.
            for check in reversed(chain):
                if clock() - started > timeout:
                    raise OSError('Startup preflight time limit reached')
                if _reparse(lstat(check)):
                    raise OSError('Startup root or ancestor is a reparse point; skipped')
            if not stat.S_ISDIR(lstat(folder).st_mode):
                raise OSError('Startup location is not a directory')
            if clock() - started > timeout:
                raise OSError('Startup preflight time limit reached')
            with scandir(folder) as entries:
                opened = True
                for index, entry in enumerate(entries):
                    if index >= max_items or clock() - started > timeout:
                        raise OSError('Startup enumeration item/time limit reached')
                    if entry.name.casefold() in seen:
                        raise OSError('Duplicate startup identity during enumeration')
                    seen.add(entry.name.casefold())
                    info = entry.stat(follow_symlinks=False)
                    reparse = _reparse(info)
                    observations.append({
                        'collector': 'startup-folders', 'target': target, 'identity': entry.name,
                        'data': {'folder': folder, 'name': entry.name, 'size': info.st_size,
                                 'modified_ns': info.st_mtime_ns,
                                 'kind': 'reparse-point' if reparse else ('directory' if stat.S_ISDIR(info.st_mode) else ('file' if stat.S_ISREG(info.st_mode) else 'other')),
                                 'content_inspected': False}})
            if clock() - started > timeout:
                raise OSError('Startup enumeration time limit reached')
        except FileNotFoundError as exc:
            status, detail = ('error' if opened else 'missing'), str(exc)
        except (OSError, ValueError) as exc:
            status, detail = 'error', str(exc)
        coverage.append({'collector': 'startup-folders', 'target': target, 'location': location,
                         'status': status, 'detail': detail})
    return {'observations': observations, 'collector_coverage': coverage}


def collect_external(task_runner=run_task_query, folder_resolver=known_startup_folder,
                     wmi_runner=run_wmi_query):
    tasks = collect_tasks(task_runner)
    startup = collect_startup(folder_resolver)
    wmi = collect_wmi(wmi_runner)
    return {key: tasks[key] + startup[key] + wmi[key] for key in ('observations', 'collector_coverage')}
