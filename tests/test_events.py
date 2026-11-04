import asyncio
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from autorecon.ai_report import IncrementalReport
from autorecon.events import EventWriter, target_terminal_event, terminal_event_for_targets, watch_task
from autorecon.selection import failed_plugin_checks, parse_include_plugins, plugin_selected, service_plugin_candidates


class EventWriterTests(unittest.TestCase):
	def test_jsonl_events_append_with_run_id_and_sequence(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / 'scans' / '_events.jsonl'
			writer = EventWriter(path, 'run-123')
			writer.emit('target_started', target='192.0.2.10')
			writer.emit('task_started', target='192.0.2.10', task_id='192.0.2.10/port/tcp', category='port')
			events = [json.loads(line) for line in path.read_text(encoding='utf8').splitlines()]
			self.assertEqual([event['event'] for event in events], ['target_started', 'task_started'])
			self.assertEqual([event['sequence'] for event in events], [1, 2])
			self.assertTrue(all(event['run_id'] == 'run-123' and event['schema'] == 1 for event in events))
			self.assertTrue(all(event['timestamp'].endswith('Z') for event in events))

	def test_unwritable_event_file_warns_once_without_stopping_scan(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / 'file'
			path.write_text('parent is a file', encoding='utf8')
			writer = EventWriter(path / '_events.jsonl', 'run-123')
			warnings = io.StringIO()
			with contextlib.redirect_stderr(warnings):
				writer.emit('target_started')
				writer.emit('target_completed')
			self.assertEqual(warnings.getvalue().count('progress events could not be written'), 1)

	def test_terminal_event_reflects_target_timeout_or_failure(self):
		completed = SimpleNamespace(scan_status='completed')
		timed_out = SimpleNamespace(scan_status='timed_out')
		failed = SimpleNamespace(scan_status='failed')
		self.assertEqual(terminal_event_for_targets([completed]), 'run_completed')
		self.assertEqual(terminal_event_for_targets([completed, timed_out]), 'run_timed_out')
		self.assertEqual(terminal_event_for_targets([completed, timed_out, failed]), 'run_failed')
		self.assertEqual(target_terminal_event(completed, 'run_timed_out'), 'run_completed')
		self.assertEqual(target_terminal_event(failed, 'run_cancelled'), 'run_failed')
		self.assertEqual(target_terminal_event(SimpleNamespace(scan_status='running'), 'run_timed_out'), 'run_timed_out')


class SelectionTests(unittest.TestCase):
	def test_exact_allowlist_overrides_tags_and_legacy_force_flags(self):
		plugin = SimpleNamespace(slug='special', tags=['unsafe'])
		self.assertEqual(parse_include_plugins('special, default', ['special', 'default']), {'special', 'default'})
		self.assertTrue(plugin_selected(plugin, {'special'}, None, [['default']], [['unsafe']]))
		self.assertFalse(plugin_selected(plugin, {'default'}, ['special'], [['unsafe']], []))
		self.assertTrue(plugin_selected(plugin, None, ['special'], [['default']], [['unsafe']]))
		self.assertFalse(plugin_selected(plugin, None, None, [['default']], []))

	def test_invalid_allowlist_is_rejected(self):
		self.assertIsNone(parse_include_plugins(None, ['one']))
		for value in ('', 'one,', 'missing'):
			with self.subTest(value=value), self.assertRaises(ValueError):
				parse_include_plugins(value, ['one'])

	def test_preflight_skips_unselected_plugins_with_missing_tools(self):
		class Plugin:
			def __init__(self, available):
				self.available = available
				self.checks = 0

			def check(self):
				self.checks += 1
				return self.available

		selected = Plugin(True)
		unselected = Plugin(False)
		plugins = {'selected': selected, 'unselected': unselected}
		self.assertEqual(failed_plugin_checks(plugins, {'selected'}), [])
		self.assertEqual((selected.checks, unselected.checks), (1, 0))
		self.assertEqual(failed_plugin_checks(plugins, None), ['unselected'])
		self.assertEqual((selected.checks, unselected.checks), (2, 1))

	def test_service_manual_candidates_follow_exact_allowlist(self):
		called = []
		plugins = [SimpleNamespace(slug=slug, manual=lambda name=slug: called.append(name))
			for slug in ('selected', 'unselected')]
		for plugin in service_plugin_candidates(plugins, {'selected'}):
			plugin.manual()
		self.assertEqual(called, ['selected'])
		self.assertEqual(list(service_plugin_candidates(plugins, None)), plugins)


class TaskLifecycleTests(unittest.IsolatedAsyncioTestCase):
	async def test_cancelled_task_is_reported_even_if_it_never_starts(self):
		states = []

		async def scan():
			await asyncio.Event().wait()

		task = watch_task(asyncio.create_task(scan()),
			lambda: states.append('cancelled'), lambda exception: states.append('failed'))
		task.cancel()
		await asyncio.gather(task, return_exceptions=True)
		await asyncio.sleep(0)
		self.assertEqual(states, ['cancelled'])

	async def test_failed_task_is_reported(self):
		states = []

		async def scan():
			raise RuntimeError('scan failed')

		task = watch_task(asyncio.create_task(scan()),
			lambda: states.append('cancelled'), lambda exception: states.append(type(exception).__name__))
		await asyncio.gather(task, return_exceptions=True)
		await asyncio.sleep(0)
		self.assertEqual(states, ['RuntimeError'])


class AIEventTests(unittest.TestCase):
	def test_incremental_review_emits_task_transitions(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			scans = root / 'scans'
			scans.mkdir()
			events = []
			report = IncrementalReport(root, 'test-model', target_address='192.0.2.10',
				on_event=lambda event, **fields: events.append((event, fields)))
			path = scans / 'check.txt'
			path.write_text('Finding\n', encoding='utf8')
			with patch('autorecon.ai_report.access_token', return_value='mock-token'), patch(
				'autorecon.ai_report._response', return_value='Review'
			):
				report.review_paths([path])
			self.assertEqual([event for event, _ in events], ['task_started', 'task_completed'])
			self.assertEqual(events[0][1]['task_id'], '192.0.2.10/ai/scans/check.txt#1')
			self.assertEqual(events[0][1]['category'], 'ai')


if __name__ == '__main__':
	unittest.main()
