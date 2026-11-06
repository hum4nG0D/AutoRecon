"""Launch CLI scans and index their JSONL events without storing credentials."""

import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import psutil

from autorecon.portal.store import now


def _pid_alive(pid):
	if not pid:
		return False
	try:
		process = psutil.Process(pid)
		return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
	except (psutil.Error, OverflowError):
		return False


class JobManager:
	def __init__(self, results_dir, store):
		self.results_dir = Path(results_dir)
		self.store = store
		self.lock = threading.Lock()
		self.processes = {}
		self.threads = {}
		self.stop_event = threading.Event()
		for job in store.list_jobs():
			if job['status'] in ('queued', 'running', 'cancelling'):
				self._start_watcher(job['id'], None)

	def _paths(self, job):
		root = self.results_dir / job['output_root']
		return root, root / 'events.jsonl', root / 'portal.log'

	def create(self, target, ai, plugins, linpeas, ssh_user, ssh_identity):
		with self.lock:
			if self.store.active_target(target):
				raise ValueError('A scan for this target is already active.')
			job_id = str(uuid.uuid4())
			output_root = 'portal-runs/' + job_id
			job = self.store.create_job({
				'id': job_id, 'target': target, 'output_root': output_root,
				'ai': ai, 'include_plugins': plugins, 'linpeas': linpeas,
				'authenticated': bool(ssh_user and ssh_identity),
			})
			self._start_watcher(job_id, (ssh_user, ssh_identity))
			return job

	def _start_watcher(self, job_id, credentials):
		thread = threading.Thread(target=self._watch, args=(job_id, credentials), daemon=True,
		                          name='autorecon-job-' + job_id[:8])
		self.threads[job_id] = thread
		thread.start()

	def _scan_args(self, job, events_path, credentials):
		args = [sys.executable, '-m', 'autorecon.main', job['target'],
		        '-o', str(self.results_dir / job['output_root']),
		        '--events-file', str(events_path), '--disable-keyboard-control',
		        '--include-plugins', ','.join(job['include_plugins']), '--no-portal']
		if job['ai']:
			args.append('--ai')
		if job['linpeas']:
			args.append('--linpeas')
		if credentials:
			username, identity = credentials
			if username and identity:
				args.extend(['--ssh-authenticated-host-checks.username', username,
				             '--ssh-authenticated-host-checks.identity-file', identity])
		return args

	def _watch(self, job_id, credentials):
		job = self.store.get_job(job_id)
		root, events_path, log_path = self._paths(job)
		process = None
		if credentials is not None:
			try:
				root.mkdir(parents=True, exist_ok=False)
				with self.lock:
					if self.store.get_job(job_id)['status'] != 'queued':
						return
					with log_path.open('ab', buffering=0) as output:
						process = subprocess.Popen(
							self._scan_args(job, events_path, credentials),
							stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
							start_new_session=True, close_fds=True,
						)
					self.processes[job_id] = process
					self.store.update_job(job_id, status='running', started_at=now(), pid=process.pid)
			except Exception as exc:
				self.store.update_job(job_id, status='failed', finished_at=now(), error=str(exc))
				return
		elif job['status'] == 'queued':
			# The portal stopped before this job was launched; no credentials were retained.
			self.store.update_job(job_id, status='failed', finished_at=now(),
			                      error='Portal stopped before this scan started. Start a new job.')
			return

		offset = 0
		pending = b''
		last_event = None
		while not self.stop_event.is_set():
			try:
				with events_path.open('rb') as source:
					source.seek(offset)
					data = source.read()
					offset = source.tell()
			except FileNotFoundError:
				data = b''
			if data:
				pending += data
				lines = pending.split(b'\n')
				pending = lines.pop()
				for line in lines:
					try:
						event = json.loads(line)
					except ValueError:
						continue
					if isinstance(event, dict):
						self.store.add_event(job_id, event)
						last_event = event
			alive = process.poll() is None if process is not None else _pid_alive(job['pid'])
			if not alive:
				# Give the event writer one final flush before deciding the state.
				if data:
					time.sleep(0.1)
					continue
				current = self.store.get_job(job_id)
				if current['status'] == 'cancelling' or (last_event and last_event.get('event') == 'run_cancelled'):
					status = 'cancelled'
				elif last_event and last_event.get('event') in ('run_timed_out', 'run_failed'):
					status = 'failed'
				elif process is not None:
					status = 'completed' if process.returncode == 0 else 'failed'
				else:
					status = 'completed' if last_event and last_event.get('event') == 'run_completed' else 'failed'
				message = ('Scan timed out.' if last_event and last_event.get('event') == 'run_timed_out'
				           else 'Scan reported a failure.' if last_event and last_event.get('event') == 'run_failed'
				           else 'Scan stopped without completion.')
				self.store.update_job(job_id, status=status, finished_at=now(),
				                      exit_code=process.returncode if process is not None else None,
				                      error=None if status != 'failed' else message)
				break
			time.sleep(0.3)
		with self.lock:
			self.processes.pop(job_id, None)

	def cancel(self, job_id):
		with self.lock:
			job = self.store.get_job(job_id)
			if not job:
				raise KeyError(job_id)
			if job['status'] not in ('queued', 'running', 'cancelling'):
				return job
			if job['status'] == 'queued':
				return self.store.update_job(job_id, status='cancelled', finished_at=now())
			self.store.update_job(job_id, status='cancelling')
			process = self.processes.get(job_id)
		pid = process.pid if process else job['pid']
		if pid and _pid_alive(pid):
			# For recovered jobs, verify the process still belongs to this job.
			if process is None:
				try:
					command = Path('/proc/{}/cmdline'.format(pid)).read_bytes().replace(b'\0', b' ').decode('utf8', 'replace')
				except OSError:
					command = ''
				if 'autorecon.main' not in command or job_id not in command:
					return self.store.update_job(job_id, status='running', error='Cannot safely identify the recovered scan process.')
			try:
				os.killpg(pid, signal.SIGTERM)
			except ProcessLookupError:
				pass
		return self.store.get_job(job_id)

	def close(self):
		self.stop_event.set()
