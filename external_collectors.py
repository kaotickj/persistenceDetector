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
# This constant is the only query code passed to PowerShell. No values obtained
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


def run_task_query(timeout=TIMEOUT, max_output=MAX_OUTPUT):
    """Run only the fixed native inventory query, with process/output bounds."""
    home = os.path.join(_system_directory(), 'WindowsPowerShell', 'v1.0')
    executable = os.path.join(home, 'powershell.exe')
    environment = dict(os.environ)
    # Do not auto-load a user-supplied ScheduledTasks module.
    environment['PSModulePath'] = os.path.join(home, 'Modules')
    process = subprocess.Popen(
        [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', TASK_QUERY],
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
                    errors.append('Task query exceeds output limit')
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
        raise OSError('Task query timed out') from exc
    finally:
        reader.join(timeout=2)
        if not reader.is_alive():
            process.stdout.close()
    if reader.is_alive():
        raise OSError('Task query output reader did not finish')
    if errors:
        raise OSError(errors[0])
    if process.returncode:
        raise OSError('Task query failed (exit {}); coverage unknown'.format(process.returncode))
    return b''.join(chunks).decode('utf-8-sig')


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate task JSON field')
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


def collect_external(task_runner=run_task_query, folder_resolver=known_startup_folder):
    tasks = collect_tasks(task_runner)
    startup = collect_startup(folder_resolver)
    return {key: tasks[key] + startup[key] for key in ('observations', 'collector_coverage')}
