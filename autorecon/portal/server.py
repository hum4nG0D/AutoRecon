"""Loopback-only AutoRecon portal and JSON/SSE API."""

import argparse
import hmac
import ipaddress
import json
import mimetypes
import re
import secrets
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from autorecon.portal.catalog import plugin_catalog
from autorecon.portal.files import Results, target_id
from autorecon.portal.jobs import JobManager
from autorecon.portal.store import Store


HOSTNAME = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$')
STATIC_DIR = Path(__file__).resolve().parent / 'static'
MAX_EVENT_SEQUENCE = (1 << 63) - 1


def valid_target(value):
	if not isinstance(value, str) or not value or len(value) > 253 or value != value.strip():
		return False
	try:
		ipaddress.ip_address(value)
		return True
	except ValueError:
		return bool(HOSTNAME.fullmatch(value) and all(0 < len(label) <= 63 and
		           not label.startswith('-') and not label.endswith('-') for label in value.split('.')))


def tasks_from_events(events):
	tasks = {}
	terminal = None
	for item in events:
		if item.get('event') in ('run_timed_out', 'run_cancelled', 'run_failed',
		                         'target_timed_out', 'target_failed'):
			terminal = item
		key = item.get('task_id')
		if not key:
			continue
		task = tasks.setdefault(key, {
			'task_id': key, 'target': item.get('target'), 'category': item.get('category'),
			'plugin': item.get('plugin'), 'service': item.get('service'),
			'status': 'queued', 'started_at': None, 'finished_at': None,
			'detail': None, 'outputs': [],
		})
		event = item.get('event')
		if event == 'task_started':
			task['status'] = 'running'
			task['started_at'] = item.get('timestamp')
		elif event in ('task_completed', 'task_failed', 'task_skipped', 'task_cancelled'):
			task['status'] = event.split('_', 1)[1]
			task['finished_at'] = item.get('timestamp')
		if item.get('detail'):
			task['detail'] = item['detail']
		if isinstance(item.get('outputs'), list):
			task['outputs'] = item['outputs']
	if terminal:
		for task in tasks.values():
			if task['status'] in ('queued', 'running'):
				task['status'] = 'cancelled' if terminal['event'] == 'run_cancelled' else 'failed'
				task['finished_at'] = terminal.get('timestamp')
				task['detail'] = task['detail'] or 'Scan stopped before this task completed.'
	return list(tasks.values())


class Portal:
	def __init__(self, results_dir):
		self.results = Results(results_dir, Store(Path(results_dir).expanduser().resolve() /
		                                           '.autorecon-portal' / 'portal.db'))
		self.store = self.results.store
		self.jobs = JobManager(self.results.root, self.store)
		self.catalog = plugin_catalog()
		self.csrf_token = secrets.token_urlsafe(32)
		self.stopping = False

	def job(self, job_id):
		if job_id.startswith('cli:'):
			return next((job for job in self.results.cli_jobs() if job['id'] == job_id), None)
		job = self.store.get_job(job_id)
		if job:
			job['source'] = 'portal'
			job['target_id'] = target_id(job['output_root'] + '/' + job['target'])
		return job

	def list_jobs(self):
		jobs = [self.job(job['id']) for job in self.store.list_jobs()] + self.results.cli_jobs()
		return sorted((job for job in jobs if job), key=lambda item: item['created_at'] or '', reverse=True)

	def events(self, job_id, after=0):
		if job_id.startswith('cli:'):
			return self.results.cli_events(job_id, after)
		if not self.store.get_job(job_id):
			raise FileNotFoundError('Job not found.')
		return self.store.events_after(job_id, after)

	def all_events(self, job_id):
		collected = []
		after = 0
		while True:
			batch = self.events(job_id, after)
			if not batch:
				break
			collected.extend(batch)
			if len(batch) < 200 or job_id.startswith('cli:'):
				break
			after = batch[-1]['sequence']
		return collected

	def start_job(self, data):
		if not isinstance(data, dict):
			raise ValueError('Expected a JSON object.')
		target = data.get('target')
		if not valid_target(target):
			raise ValueError('Enter one valid IP address or hostname.')
		if any(job['target'].casefold() == target.casefold() and job['status'] == 'running'
		       for job in self.results.cli_jobs()):
			raise ValueError('A CLI scan for this target is already active.')
		plugins = data.get('include_plugins')
		if not isinstance(plugins, list) or not plugins or not all(isinstance(value, str) for value in plugins):
			raise ValueError('Select at least one port scan plugin.')
		available = {item['slug']: item for item in self.catalog['plugins']}
		if len(set(plugins)) != len(plugins) or any(value not in available for value in plugins):
			raise ValueError('Selected plugin list contains an unknown or duplicate plugin.')
		if not any(available[value]['kind'] == 'port' for value in plugins):
			raise ValueError('Select at least one port scan plugin.')
		ai = data.get('ai', False)
		linpeas = data.get('linpeas', False)
		if not isinstance(ai, bool) or not isinstance(linpeas, bool):
			raise ValueError('AI and LinPEAS settings must be checkboxes.')
		ssh_user = data.get('ssh_user') or ''
		ssh_identity = data.get('ssh_identity') or ''
		if not isinstance(ssh_user, str) or not isinstance(ssh_identity, str):
			raise ValueError('SSH credentials must be text values.')
		if bool(ssh_user) != bool(ssh_identity):
			raise ValueError('SSH username and identity file are both required.')
		if linpeas and not ssh_user:
			raise ValueError('LinPEAS requires an SSH username and identity file.')
		if ssh_user and 'ssh-authenticated-host-checks' not in plugins:
			raise ValueError('Select the SSH authenticated host checks plugin to use SSH credentials.')
		if ssh_identity and not Path(ssh_identity).expanduser().is_file():
			raise ValueError('SSH identity file does not exist.')
		if ai:
			from autorecon.ai_auth import session
			if not session():
				raise ValueError('Connect ChatGPT from a local terminal with autorecon-ai login before starting an AI scan.')
		job = self.jobs.create(target, ai, plugins, linpeas, ssh_user,
		                       str(Path(ssh_identity).expanduser()) if ssh_identity else '')
		return self.job(job['id'])

	def close(self):
		self.stopping = True
		self.jobs.close()


class Handler(BaseHTTPRequestHandler):
	protocol_version = 'HTTP/1.1'

	@property
	def app(self):
		return self.server.app

	def log_message(self, format_string, *args):
		# Keep access logs terse and avoid logging file contents or POST bodies.
		sys.stderr.write('portal: ' + format_string % args + '\n')

	def _headers(self, status, kind, length=None):
		self.send_response(status)
		self.send_header('Content-Type', kind)
		self.send_header('Cache-Control', 'no-store')
		self.send_header('X-Content-Type-Options', 'nosniff')
		self.send_header('X-Frame-Options', 'DENY')
		self.send_header('Referrer-Policy', 'no-referrer')
		if self.close_connection:
			self.send_header('Connection', 'close')
		self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		if length is not None:
			self.send_header('Content-Length', str(length))
		self.end_headers()

	def _json(self, status, payload):
		body = json.dumps(payload, ensure_ascii=False).encode('utf8')
		self._headers(status, 'application/json; charset=utf-8', len(body))
		self.wfile.write(body)

	def _error(self, status, message):
		self.close_connection = True
		self._json(status, {'error': message})

	def _valid_host(self):
		value = self.headers.get('Host', '')
		port = self.server.server_address[1]
		return value in ('127.0.0.1:' + str(port), 'localhost:' + str(port))

	def _static(self, name):
		if name.startswith('/') or '..' in Path(name).parts:
			raise FileNotFoundError('Static asset not found.')
		path = (STATIC_DIR / name).resolve()
		if path.parent != STATIC_DIR.resolve() or not path.is_file():
			raise FileNotFoundError('Static asset not found.')
		body = path.read_bytes()
		kind = mimetypes.guess_type(str(path))[0] or 'application/octet-stream'
		self._headers(200, kind + ('; charset=utf-8' if kind.startswith(('text/', 'application/javascript')) else ''), len(body))
		self.wfile.write(body)

	def do_GET(self):
		if not self._valid_host():
			return self._error(400, 'Invalid host.')
		parsed = urlsplit(self.path)
		path = parsed.path
		query = parse_qs(parsed.query)
		try:
			if path == '/':
				return self._static('index.html')
			if path.startswith('/static/'):
				return self._static(unquote(path[len('/static/'):]))
			if path == '/api/config':
				return self._json(200, {'csrf_token': self.app.csrf_token, 'results_dir': str(self.app.results.root)})
			if path == '/api/catalog':
				return self._json(200, self.app.catalog)
			if path == '/api/targets':
				return self._json(200, {'targets': self.app.results.targets()})
			if path.startswith('/api/targets/') and path.endswith('/files'):
				identifier = unquote(path[len('/api/targets/'):-len('/files')].strip('/'))
				return self._json(200, self.app.results.files(identifier))
			if path == '/api/file':
				identifier = query.get('target', [''])[0]
				filename = query.get('path', [''])[0]
				return self._json(200, self.app.results.file(identifier, filename))
			if path == '/api/jobs':
				return self._json(200, {'jobs': self.app.list_jobs()})
			if path.startswith('/api/jobs/'):
				job_id = unquote(path[len('/api/jobs/'):].strip('/'))
				job = self.app.job(job_id)
				if not job:
					raise FileNotFoundError('Job not found.')
				return self._json(200, {'job': job, 'tasks': tasks_from_events(self.app.all_events(job_id))})
			if path == '/api/events':
				job_id = query.get('job_id', [''])[0]
				if not self.app.job(job_id):
					raise FileNotFoundError('Job not found.')
				try:
					query_cursor = query.get('after', ['0'])[0]
					if len(query_cursor) > 20:
						raise ValueError()
					after = max(0, int(query_cursor))
					if after > MAX_EVENT_SEQUENCE:
						raise ValueError()
				except ValueError:
					raise ValueError('after must be an event sequence number.')
				last_event_id = self.headers.get('Last-Event-ID', '')
				if last_event_id and len(last_event_id) <= 20:
					try:
						last_sequence = int(last_event_id)
					except ValueError:
						pass
					else:
						if 0 <= last_sequence <= MAX_EVENT_SEQUENCE:
							after = max(after, last_sequence)
				return self._events(job_id, after)
			raise FileNotFoundError('Page not found.')
		except FileNotFoundError as exc:
			self._error(404, str(exc))
		except ValueError as exc:
			self._error(400, str(exc))
		except Exception:
			traceback.print_exc()
			self._error(500, 'Portal error.')

	def _events(self, job_id, after):
		self._headers(200, 'text/event-stream; charset=utf-8')
		last_heartbeat = time.monotonic()
		try:
			while not self.app.stopping:
				batch = self.app.events(job_id, after)
				for item in batch:
					sequence = item['sequence']
					message = 'id: {}\nevent: scan\ndata: {}\n\n'.format(sequence,
					                                            json.dumps(item, separators=(',', ':')))
					self.wfile.write(message.encode('utf8'))
					after = sequence
				if batch:
					self.wfile.flush()
				elif time.monotonic() - last_heartbeat >= 10:
					self.wfile.write(b': keepalive\n\n')
					self.wfile.flush()
					last_heartbeat = time.monotonic()
				time.sleep(0.4)
		except (BrokenPipeError, ConnectionResetError):
			return

	def do_POST(self):
		if not self._valid_host():
			return self._error(400, 'Invalid host.')
		port = self.server.server_address[1]
		origin = self.headers.get('Origin', '')
		if origin not in ('http://127.0.0.1:' + str(port), 'http://localhost:' + str(port)):
			return self._error(403, 'Invalid origin.')
		if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), self.app.csrf_token):
			return self._error(403, 'Invalid CSRF token.')
		if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
			return self._error(415, 'Expected application/json.')
		try:
			length = int(self.headers.get('Content-Length', '0'))
			if not 0 < length <= 65536:
				raise ValueError('Request body must be between 1 byte and 64 KB.')
			data = json.loads(self.rfile.read(length))
			path = urlsplit(self.path).path
			if path == '/api/jobs':
				return self._json(201, {'job': self.app.start_job(data)})
			if path.startswith('/api/jobs/') and path.endswith('/cancel'):
				job_id = unquote(path[len('/api/jobs/'):-len('/cancel')].strip('/'))
				if job_id.startswith('cli:'):
					return self._error(405, 'CLI jobs cannot be cancelled from the portal.')
				return self._json(200, {'job': self.app.jobs.cancel(job_id)})
			raise FileNotFoundError('Page not found.')
		except FileNotFoundError as exc:
			self._error(404, str(exc))
		except KeyError:
			self._error(404, 'Job not found.')
		except (ValueError, json.JSONDecodeError) as exc:
			self._error(400, str(exc))
		except Exception:
			traceback.print_exc()
			self._error(500, 'Portal error.')


class Server(ThreadingHTTPServer):
	daemon_threads = True
	allow_reuse_address = True

	def __init__(self, address, app):
		super().__init__(address, Handler)
		self.app = app


def main(argv=None):
	parser = argparse.ArgumentParser(prog='autorecon-portal', description='View AutoRecon results and run scans in a local browser.')
	parser.add_argument('--results-dir', default='~/results', help='Results root (default: ~/results).')
	parser.add_argument('--port', type=int, default=8787, help='Loopback port (default: 8787).')
	args = parser.parse_args(argv)
	if not 0 <= args.port <= 65535:
		parser.error('Port must be between 0 and 65535.')
	app = Portal(args.results_dir)
	with Server(('127.0.0.1', args.port), app) as server:
		print('AutoRecon portal: http://127.0.0.1:{}/'.format(server.server_port), flush=True)
		try:
			server.serve_forever(poll_interval=0.25)
		except KeyboardInterrupt:
			pass
		finally:
			app.close()
	return 0


if __name__ == '__main__':
	sys.exit(main())
