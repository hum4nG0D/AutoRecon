"""Host-side lifecycle control for the local AutoRecon portal.

The portal writes its pid to <results>/.autorecon-portal/portal.pid so that
later runs (and `autorecon stop`) can find exactly one portal per results
directory. Processes are only signalled after their command line is verified
to be the AutoRecon portal, never a reused or foreign pid.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import psutil


DEFAULT_PORT = 8787
STATE_DIR = '.autorecon-portal'
PIDFILE = 'portal.pid'
LOGFILE = 'portal.log'
MARKERS = ('autorecon.portal.server', 'autorecon-portal')


def state_dir(results_dir):
    path = Path(results_dir).expanduser() / STATE_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def pidfile_path(results_dir):
    return state_dir(results_dir) / PIDFILE


def _is_portal(pid):
    if pid <= 0:
        return False
    try:
        process = psutil.Process(pid)
    except psutil.Error:
        return False
    if process.status() == psutil.STATUS_ZOMBIE:
        return False
    command = ' '.join(process.cmdline())
    return any(marker in command for marker in MARKERS)


def portal_pid(results_dir):
    """Return the pid of a verified live portal for results_dir, or None."""
    try:
        pid = int(pidfile_path(results_dir).read_text().strip())
    except (OSError, ValueError):
        return None
    return pid if _is_portal(pid) else None


def write_pidfile(results_dir):
    path = pidfile_path(results_dir)
    path.write_text(str(os.getpid()) + '\n', encoding='utf8')
    return path


def remove_pidfile(path):
    try:
        if path and Path(path).exists():
            Path(path).unlink()
    except OSError:
        pass


def start_portal(results_dir, port=DEFAULT_PORT, host='127.0.0.1'):
    """Start the portal for results_dir unless one is already running.

    Returns the portal pid, or None if no verified portal is available.
    """
    existing = portal_pid(results_dir)
    if existing:
        return existing
    directory = state_dir(results_dir)
    log = open(str(directory / LOGFILE), 'ab', buffering=0)
    process = subprocess.Popen(
        [sys.executable, '-m', 'autorecon.portal.server',
         '--results-dir', str(Path(results_dir).expanduser()),
         '--host', host, '--port', str(port)],
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True, close_fds=True)
    # The server writes the pidfile itself once it is listening.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        pid = portal_pid(results_dir)
        if pid:
            return pid
        if process.poll() is not None:
            return None
        time.sleep(0.2)
    return None


def stop_portal(results_dir, timeout=10):
    """Stop the portal for results_dir. Returns True if one was stopped."""
    pidfile = pidfile_path(results_dir)
    try:
        pid = int(pidfile.read_text().strip())
    except (OSError, ValueError):
        return False
    if not _is_portal(pid):
        # Stale or forged pidfile; never signal a process we cannot identify.
        try:
            pidfile.unlink()
        except OSError:
            pass
        return False
    process = psutil.Process(pid)
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except psutil.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=5)
        except psutil.TimeoutExpired:
            pass
    remove_pidfile(pidfile)
    return True
