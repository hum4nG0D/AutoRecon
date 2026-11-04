"""Append-only progress events for local scan viewers.

Each line is one complete JSON object. Sequence numbers are monotonic within an
EventWriter (a run-wide stream when --events-file is used, otherwise a target).
"""

import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path


class EventWriter:
	def __init__(self, path, run_id):
		self.path = Path(path)
		self.run_id = run_id
		self.sequence = 0
		self._lock = threading.Lock()
		self._disabled = False

	def emit(self, event, **fields):
		"""Write an event, or warn once and let the scan continue on I/O failure."""
		with self._lock:
			if self._disabled:
				return
			self.sequence += 1
			record = {
				'schema': 1,
				'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
				'run_id': self.run_id,
				'sequence': self.sequence,
				'event': event,
			}
			record.update(fields)
			try:
				self.path.parent.mkdir(parents=True, exist_ok=True)
				with self.path.open('a', encoding='utf8') as stream:
					stream.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n')
			except (OSError, TypeError, ValueError) as exc:
				self._disabled = True
				print('Warning: progress events could not be written to {}: {}'.format(self.path, exc), file=sys.stderr)


def terminal_event_for_targets(targets):
	"""Choose the final run event from target outcomes, not task completion alone."""
	statuses = {getattr(target, 'scan_status', None) for target in targets}
	if 'failed' in statuses:
		return 'run_failed'
	if 'timed_out' in statuses:
		return 'run_timed_out'
	return 'run_completed'


def target_terminal_event(target, interrupted_event):
	"""Preserve a finished target's outcome when the wider CLI run stops."""
	status = getattr(target, 'scan_status', None)
	if status in ('completed', 'failed', 'timed_out'):
		return 'run_' + status
	return interrupted_event


def watch_task(task, on_cancelled, on_failed):
	"""Report terminal task states even when cancellation precedes its first await."""
	def finished(done):
		if done.cancelled():
			on_cancelled()
		else:
			exception = done.exception()
			if exception is not None:
				on_failed(exception)

	task.add_done_callback(finished)
	return task
