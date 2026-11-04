"""Constrained discovery and reading of AutoRecon result artifacts."""

import base64
import json
from datetime import datetime
from pathlib import Path

import psutil

from autorecon.portal.render import render_markdown, render_text


TEXT_SUFFIXES = {'.md', '.txt', '.log', '.nmap', '.json', '.xml', '.html', '.ctd'}
HIDDEN_FILES = {'ai-report-input.txt', '_events.jsonl'}
PREVIEW_BYTES = 1_000_000


def target_id(relative_path):
	return base64.urlsafe_b64encode(relative_path.encode('utf8')).decode('ascii').rstrip('=')


def _under(path, root):
	try:
		path.relative_to(root)
		return True
	except ValueError:
		return False


def _target_status(events_path):
	events = read_events(events_path)
	if not events:
		return 'legacy', None
	last = events[-1]
	if last.get('event') in ('run_completed', 'target_completed'):
		return 'completed', last.get('run_id')
	if last.get('event') in ('run_timed_out', 'target_timed_out', 'run_failed', 'target_failed'):
		return 'failed', last.get('run_id')
	if last.get('event') == 'run_cancelled':
		return 'cancelled', last.get('run_id')
	start = next((event for event in reversed(events)
	              if event.get('run_id') == last.get('run_id') and event.get('event') == 'run_started'), None)
	return ('running' if start and cli_pid_matches(start) else 'unknown'), last.get('run_id')


def cli_pid_matches(start):
	try:
		pid = int(start['pid'])
		process = psutil.Process(pid)
		stamp = datetime.fromisoformat(start['timestamp'].replace('Z', '+00:00')).timestamp()
		return abs(process.create_time() - stamp) <= 30 and any('autorecon' in part.lower() for part in process.cmdline())
	except (KeyError, TypeError, ValueError, psutil.Error, OSError):
		return False


def read_events(path):
	try:
		with path.open('r', encoding='utf8', errors='replace') as source:
			events = []
			for line in source:
				try:
					item = json.loads(line)
				except ValueError:
					continue
				if isinstance(item, dict) and isinstance(item.get('sequence'), int):
					events.append(item)
			return events
	except (FileNotFoundError, PermissionError, IsADirectoryError):
		return []


class Results:
	def __init__(self, root, store):
		self.root = Path(root).expanduser().resolve()
		self.root.mkdir(parents=True, exist_ok=True)
		self.store = store

	def _candidate_dirs(self):
		if (self.root / 'scans').is_dir() or (self.root / 'report').is_dir():
			yield self.root
		for child in sorted(self.root.iterdir()):
			if child.is_symlink() or not child.is_dir() or child.name.startswith('.'):
				continue
			if child.name == 'portal-runs':
				for run_root in sorted(child.iterdir()):
					if run_root.is_symlink() or not run_root.is_dir():
						continue
					for target in sorted(run_root.iterdir()):
						if target.is_dir() and not target.is_symlink():
							yield target
			else:
				yield child

	def targets(self):
		found = []
		jobs = {job['output_root']: job for job in self.store.list_jobs()}
		for directory in self._candidate_dirs():
			resolved = directory.resolve()
			if not _under(resolved, self.root):
				continue
			report = directory / 'report'
			scans = directory / 'scans'
			if not ((report.is_dir() and not report.is_symlink()) or (scans.is_dir() and not scans.is_symlink())):
				continue
			relative = str(directory.relative_to(self.root))
			if relative == '.':
				relative = '.'
			job = None
			if relative.startswith('portal-runs/'):
				job = jobs.get('/'.join(relative.split('/')[:2]))
			status, run_id = _target_status(scans / '_events.jsonl')
			if job:
				status = job['status']
				last_events = self.store.events_after(job['id'], 0, 1)
				if last_events:
					run_id = last_events[0].get('run_id')
			try:
				updated_at = datetime.fromtimestamp(max(report.stat().st_mtime if report.exists() else 0,
				                                     scans.stat().st_mtime if scans.exists() else 0)).isoformat()
			except OSError:
				updated_at = None
			found.append({'id': target_id(relative), 'name': directory.name,
			              'relative_path': relative, 'has_report': report.is_dir(),
			              'has_scans': scans.is_dir(), 'updated_at': updated_at,
			              'run_id': run_id, 'job_id': job['id'] if job else None,
			              'status': status})
		return sorted(found, key=lambda item: item['updated_at'] or '', reverse=True)

	def target_path(self, identifier):
		for target in self.targets():
			if target['id'] == identifier:
				path = (self.root / target['relative_path']).resolve()
				if _under(path, self.root):
					return path
		raise FileNotFoundError('Target results not found.')

	def files(self, identifier):
		root = self.target_path(identifier)
		sections = {'reports': [], 'scans': []}
		for folder, key in (('report', 'reports'), ('scans', 'scans')):
			base = root / folder
			if not base.is_dir() or base.is_symlink():
				continue
			for path in base.rglob('*'):
				if not path.is_file() or path.is_symlink() or path.name in HIDDEN_FILES or path.suffix.lower() not in TEXT_SUFFIXES:
					continue
				resolved = path.resolve()
				if not _under(resolved, base.resolve()):
					continue
				relative = str(path.relative_to(root))
				try:
					size = path.stat().st_size
				except OSError:
					continue
				if key == 'reports' and size == 0:
					continue
				sections[key].append({'path': relative, 'label': path.name,
				                      'size': size, 'kind': 'markdown' if path.suffix.lower() == '.md' else 'text'})
		sections['reports'].sort(key=lambda item: (0 if item['path'] == 'report/ai-report.md' else
		                                            1 if item['path'] == 'report/ai-report-reviews.md' else 2, item['path']))
		sections['scans'].sort(key=lambda item: item['path'])
		return {'target_id': identifier, **sections}

	def cli_jobs(self):
		"""Treat instrumented CLI scans as jobs even without portal DB rows."""
		jobs = []
		for target in self.targets():
			if target['job_id'] or not target['has_scans']:
				continue
			path = self.target_path(target['id']) / 'scans' / '_events.jsonl'
			by_run = {}
			for event in read_events(path):
				run_id = event.get('run_id')
				if isinstance(run_id, str) and run_id:
					by_run.setdefault(run_id, []).append(event)
			for run_id, events in by_run.items():
				start = next((item for item in events if item.get('event') == 'run_started'), events[0])
				last = events[-1]
				terminal = last.get('event')
				if terminal in ('run_completed', 'target_completed'):
					status = 'completed'
				elif terminal in ('run_cancelled',):
					status = 'cancelled'
				elif terminal in ('run_timed_out', 'target_timed_out', 'run_failed', 'target_failed'):
					status = 'failed'
				else:
					status = 'running' if cli_pid_matches(start) else 'unknown'
				jobs.append({
					'id': 'cli:' + target['id'] + ':' + run_id,
					'source': 'cli', 'target': target['name'], 'target_id': target['id'],
					'output_root': target['relative_path'], 'log_path': None,
					'status': status, 'created_at': start.get('timestamp'),
					'started_at': start.get('timestamp'),
					'finished_at': last.get('timestamp') if status in ('completed', 'failed', 'cancelled') else None,
					'exit_code': None, 'ai': any(item.get('category') == 'ai' for item in events),
					'include_plugins': [], 'linpeas': False, 'authenticated': False,
					'error': None,
				})
		return sorted(jobs, key=lambda item: item['created_at'] or '', reverse=True)

	def cli_events(self, job_id, after=0):
		for job in self.cli_jobs():
			if job['id'] == job_id:
				run_id = job_id.rsplit(':', 1)[-1]
				path = self.target_path(job['target_id']) / 'scans' / '_events.jsonl'
				return [item for item in read_events(path)
				        if item.get('run_id') == run_id and item.get('sequence', 0) > after]
		raise FileNotFoundError('CLI job not found.')

	def file(self, identifier, relative_path):
		listed = {item['path']: item for group in ('reports', 'scans')
		          for item in self.files(identifier)[group]}
		if relative_path not in listed:
			raise FileNotFoundError('File is not available in this target.')
		root = self.target_path(identifier)
		path = (root / relative_path).resolve()
		if not _under(path, root) or not path.is_file():
			raise FileNotFoundError('File is not available in this target.')
		with path.open('rb') as source:
			data = source.read(PREVIEW_BYTES + 1)
		truncated = len(data) > PREVIEW_BYTES
		content = data[:PREVIEW_BYTES].decode('utf8', 'replace')
		kind = listed[relative_path]['kind']
		return {'path': relative_path, 'kind': kind, 'content': content,
		        'html': render_markdown(content) if kind == 'markdown' else render_text(content),
		        'truncated': truncated}
