import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from autorecon.portal.files import Results, target_id
from autorecon.portal.render import render_markdown
from autorecon.portal.server import Portal, Server, tasks_from_events
from autorecon.portal.store import Store, now


class PortalFilesTests(unittest.TestCase):
	def setUp(self):
		self.temp = tempfile.TemporaryDirectory()
		self.root = Path(self.temp.name)
		self.target = self.root / '192.0.2.10'
		(self.target / 'report').mkdir(parents=True)
		(self.target / 'scans').mkdir()
		(self.target / 'report' / 'ai-report.md').write_text('# Finding\n<script>alert(1)</script>\n', encoding='utf8')
		(self.target / 'report' / 'ai-report-input.txt').write_text('private preview', encoding='utf8')
		(self.target / 'scans' / 'raw.txt').write_text('<img src=x onerror=alert(1)>', encoding='utf8')
		(self.target / 'scans' / '_events.jsonl').write_text('', encoding='utf8')
		self.results = Results(self.root, Store(self.root / '.autorecon-portal' / 'portal.db'))
		self.id = target_id('192.0.2.10')

	def tearDown(self):
		self.temp.cleanup()

	def test_index_reports_and_escapes_untrusted_content(self):
		self.assertEqual(len(self.results.targets()), 1)
		files = self.results.files(self.id)
		self.assertEqual([item['path'] for item in files['reports']], ['report/ai-report.md'])
		self.assertEqual([item['path'] for item in files['scans']], ['scans/raw.txt'])
		markdown = self.results.file(self.id, 'report/ai-report.md')
		self.assertIn('<h1>Finding</h1>', markdown['html'])
		self.assertIn('&lt;script&gt;', markdown['html'])
		self.assertNotIn('<script>', markdown['html'])
		self.assertIn('&lt;img', self.results.file(self.id, 'scans/raw.txt')['html'])
		self.assertNotIn('<img', render_markdown('![remote](https://example.test/pixel)'))

	def test_rejects_traversal_and_symlinks(self):
		outside = self.root / 'outside.txt'
		outside.write_text('secret', encoding='utf8')
		(self.target / 'scans' / 'link.txt').symlink_to(outside)
		self.assertNotIn('scans/link.txt', [item['path'] for item in self.results.files(self.id)['scans']])
		for path in ('../outside.txt', 'scans/link.txt', 'report/ai-report-input.txt'):
			with self.assertRaises(FileNotFoundError):
				self.results.file(self.id, path)

	def test_cli_event_file_becomes_job(self):
		run_id = 'test-run-id'
		events = [
			{'schema': 1, 'run_id': run_id, 'sequence': 1, 'event': 'run_started', 'timestamp': now(), 'pid': os.getpid()},
			{'schema': 1, 'run_id': run_id, 'sequence': 2, 'event': 'task_completed', 'timestamp': now(),
			 'target': '192.0.2.10', 'task_id': 'port/top', 'category': 'port', 'plugin': 'top'},
			{'schema': 1, 'run_id': run_id, 'sequence': 3, 'event': 'run_completed', 'timestamp': now()},
		]
		(self.target / 'scans' / '_events.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in events), encoding='utf8')
		jobs = self.results.cli_jobs()
		self.assertEqual(len(jobs), 1)
		self.assertEqual(jobs[0]['source'], 'cli')
		self.assertEqual(jobs[0]['status'], 'completed')
		self.assertEqual(len(self.results.cli_events(jobs[0]['id'], after=1)), 2)

	def test_failed_cli_run_and_cancelled_task_projection(self):
		events = [
			{'schema': 1, 'run_id': 'failed-run', 'sequence': 1, 'event': 'run_started',
			 'timestamp': now(), 'pid': os.getpid()},
			{'schema': 1, 'run_id': 'failed-run', 'sequence': 2, 'event': 'task_queued',
			 'timestamp': now(), 'task_id': 'port/one', 'category': 'port', 'plugin': 'one'},
			{'schema': 1, 'run_id': 'failed-run', 'sequence': 3, 'event': 'task_started',
			 'timestamp': now(), 'task_id': 'port/two', 'category': 'port', 'plugin': 'two'},
			{'schema': 1, 'run_id': 'failed-run', 'sequence': 4, 'event': 'task_cancelled',
			 'timestamp': now(), 'task_id': 'port/two', 'category': 'port', 'plugin': 'two'},
			{'schema': 1, 'run_id': 'failed-run', 'sequence': 5, 'event': 'run_failed',
			 'timestamp': now()},
		]
		(self.target / 'scans' / '_events.jsonl').write_text(
			''.join(json.dumps(item) + '\n' for item in events), encoding='utf8')
		self.assertEqual(self.results.targets()[0]['status'], 'failed')
		self.assertEqual(self.results.cli_jobs()[0]['status'], 'failed')
		self.assertEqual({item['task_id']: item['status'] for item in tasks_from_events(events)},
		                 {'port/one': 'failed', 'port/two': 'cancelled'})


class PortalHttpTests(unittest.TestCase):
	def setUp(self):
		self.temp = tempfile.TemporaryDirectory()
		self.app = Portal(self.temp.name)
		self.server = Server(('127.0.0.1', 0), self.app)
		self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
		self.thread.start()
		self.url = 'http://127.0.0.1:{}'.format(self.server.server_port)
		self.session = requests.Session()
		self.token = self.session.get(self.url + '/api/config', timeout=5).json()['csrf_token']

	def tearDown(self):
		self.app.close()
		self.server.shutdown()
		self.server.server_close()
		self.session.close()
		self.temp.cleanup()

	def test_authentic_post_and_job_event_replay(self):
		catalog = self.session.get(self.url + '/api/catalog', timeout=5).json()['plugins']
		port_plugin = next(item['slug'] for item in catalog if item['kind'] == 'port')
		payload = {'target': '192.0.2.10', 'ai': False, 'include_plugins': [port_plugin], 'linpeas': False}
		self.assertEqual(self.session.post(self.url + '/api/jobs', json=payload, timeout=5).status_code, 403)
		self.assertEqual(self.session.post(self.url + '/api/jobs', json=payload,
		                 headers={'Origin': self.url, 'X-CSRF-Token': 'wrong'}, timeout=5).status_code, 403)

		def fake_args(manager, job, events_path, credentials):
			program = ('import json,sys; p=sys.argv[1]; '
			           'events=[dict(schema=1,run_id="mock-run",sequence=1,event="run_started",target="192.0.2.10"),'
			           'dict(schema=1,run_id="mock-run",sequence=2,event="task_completed",target="192.0.2.10",'
			           'task_id="port/mock",category="port",plugin="mock"),'
			           'dict(schema=1,run_id="mock-run",sequence=3,event="run_completed",target="192.0.2.10")]; '
			           'open(p,"w").write("".join(json.dumps(e)+"\\n" for e in events))')
			return [sys.executable, '-c', program, str(events_path)]

		with patch('autorecon.portal.jobs.JobManager._scan_args', fake_args):
			response = self.session.post(self.url + '/api/jobs', json=payload,
			                             headers={'Origin': self.url, 'X-CSRF-Token': self.token}, timeout=5)
			self.assertEqual(response.status_code, 201, response.text)
			job_id = response.json()['job']['id']
			for _ in range(100):
				job = self.session.get(self.url + '/api/jobs/' + job_id, timeout=5).json()
				if job['job']['status'] in ('completed', 'failed'):
					break
				time.sleep(0.05)
		self.assertEqual(job['job']['status'], 'completed', job)
		self.assertEqual(job['tasks'][0]['task_id'], 'port/mock')
		with self.session.get(self.url + '/api/events?job_id=' + job_id + '&after=1', stream=True, timeout=5) as stream:
			lines = stream.iter_lines(chunk_size=1, decode_unicode=True)
			self.assertEqual(next(lines), 'id: 2')
			self.assertEqual(next(lines), 'event: scan')
		with self.session.get(self.url + '/api/events?job_id=' + job_id + '&after=0',
		                      headers={'Last-Event-ID': '2'}, stream=True, timeout=5) as stream:
			self.assertEqual(next(stream.iter_lines(chunk_size=1, decode_unicode=True)), 'id: 3')
		with self.session.get(self.url + '/api/events?job_id=' + job_id + '&after=2',
		                      headers={'Last-Event-ID': '1'}, stream=True, timeout=5) as stream:
			self.assertEqual(next(stream.iter_lines(chunk_size=1, decode_unicode=True)), 'id: 3')
		with self.session.get(self.url + '/api/events?job_id=' + job_id + '&after=1',
		                      headers={'Last-Event-ID': 'garbage'}, stream=True, timeout=5) as stream:
			self.assertEqual(next(stream.iter_lines(chunk_size=1, decode_unicode=True)), 'id: 2')
		self.assertEqual(self.session.get(self.url + '/api/events?job_id=' + job_id + '&after=' + '9' * 30,
		                                  timeout=5).status_code, 400)
		self.assertEqual(self.session.get(self.url + '/api/jobs', timeout=5).json()['jobs'][0]['id'], job_id)

	def test_ai_scan_requires_existing_local_login(self):
		catalog = self.session.get(self.url + '/api/catalog', timeout=5).json()['plugins']
		port_plugin = next(item['slug'] for item in catalog if item['kind'] == 'port')
		payload = {'target': '192.0.2.10', 'ai': True, 'include_plugins': [port_plugin], 'linpeas': False}
		with patch('autorecon.ai_auth.session', return_value=None):
			response = self.session.post(self.url + '/api/jobs', json=payload,
			                             headers={'Origin': self.url, 'X-CSRF-Token': self.token}, timeout=5)
		self.assertEqual(response.status_code, 400, response.text)
		self.assertIn('autorecon-ai login', response.json()['error'])
		self.assertEqual(self.session.get(self.url + '/api/jobs', timeout=5).json()['jobs'], [])


if __name__ == '__main__':
	unittest.main()
