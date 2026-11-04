"""Small SQLite index for portal-owned jobs and their progress events."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone


def now():
	return datetime.now(timezone.utc).isoformat()


class Store:
	def __init__(self, path):
		self.path = str(path)
		path.parent.mkdir(parents=True, exist_ok=True)
		with self._connect() as db:
			db.executescript('''
			CREATE TABLE IF NOT EXISTS jobs (
			 id TEXT PRIMARY KEY, target TEXT NOT NULL, output_root TEXT NOT NULL,
			 status TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT,
			 finished_at TEXT, pid INTEGER, exit_code INTEGER, ai INTEGER NOT NULL,
			 include_plugins TEXT NOT NULL, linpeas INTEGER NOT NULL,
			 authenticated INTEGER NOT NULL, error TEXT
			);
			CREATE TABLE IF NOT EXISTS events (
			 job_id TEXT NOT NULL REFERENCES jobs(id), sequence INTEGER NOT NULL,
			 payload TEXT NOT NULL, PRIMARY KEY(job_id, sequence)
			);
			CREATE INDEX IF NOT EXISTS events_job_sequence ON events(job_id, sequence);
			''')

	@contextmanager
	def _connect(self):
		db = sqlite3.connect(self.path, timeout=10)
		db.row_factory = sqlite3.Row
		db.execute('PRAGMA foreign_keys=ON')
		db.execute('PRAGMA journal_mode=WAL')
		try:
			with db:
				yield db
		finally:
			db.close()

	@staticmethod
	def _job(row):
		if row is None:
			return None
		item = dict(row)
		item['ai'] = bool(item['ai'])
		item['linpeas'] = bool(item['linpeas'])
		item['authenticated'] = bool(item['authenticated'])
		item['include_plugins'] = json.loads(item['include_plugins'])
		item['log_path'] = item['output_root'] + '/portal.log'
		return item

	def create_job(self, job):
		with self._connect() as db:
			db.execute('''INSERT INTO jobs
			 (id, target, output_root, status, created_at, ai, include_plugins, linpeas, authenticated)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
			 (job['id'], job['target'], job['output_root'], 'queued', now(), int(job['ai']),
			  json.dumps(job['include_plugins']), int(job['linpeas']), int(job['authenticated'])))
		return self.get_job(job['id'])

	def update_job(self, job_id, **changes):
		if not changes:
			return self.get_job(job_id)
		allowed = {'status', 'started_at', 'finished_at', 'pid', 'exit_code', 'error'}
		if set(changes) - allowed:
			raise ValueError('Invalid job field')
		sets = ', '.join(key + '=?' for key in changes)
		with self._connect() as db:
			db.execute('UPDATE jobs SET ' + sets + ' WHERE id=?', list(changes.values()) + [job_id])
		return self.get_job(job_id)

	def get_job(self, job_id):
		with self._connect() as db:
			return self._job(db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone())

	def list_jobs(self):
		with self._connect() as db:
			return [self._job(row) for row in db.execute('SELECT * FROM jobs ORDER BY created_at DESC')]

	def active_target(self, target):
		with self._connect() as db:
			return self._job(db.execute("SELECT * FROM jobs WHERE target=? AND status IN ('queued','running','cancelling') ORDER BY created_at DESC LIMIT 1", (target,)).fetchone())

	def add_event(self, job_id, event):
		sequence = event.get('sequence')
		if not isinstance(sequence, int):
			return
		with self._connect() as db:
			db.execute('INSERT OR IGNORE INTO events(job_id,sequence,payload) VALUES (?,?,?)',
			           (job_id, sequence, json.dumps(event, separators=(',', ':'))))

	def events_after(self, job_id, sequence, limit=200):
		with self._connect() as db:
			return [json.loads(row['payload']) for row in db.execute(
				'SELECT payload FROM events WHERE job_id=? AND sequence>? ORDER BY sequence LIMIT ?',
				(job_id, sequence, limit))]
