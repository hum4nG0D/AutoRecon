import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from autorecon.ai_report import IncrementalReport, _response, create_report, prepare_input, review_completed_scan, section_chunks, split_input


class AIReportTests(unittest.TestCase):
	def setUp(self):
		self.temp = tempfile.TemporaryDirectory()
		self.root = Path(self.temp.name)
		(self.root / 'scans' / 'tcp22').mkdir(parents=True)
		(self.root / 'scans' / 'tcp22' / 'tcp_22_ssh_linpeas.txt').write_text(
			'Potential issue\npassword: hunter2\n-----BEGIN RSA PRIVATE KEY-----\nsecret bytes\n-----END RSA PRIVATE KEY-----\n', encoding='utf8')
		(self.root / 'scans' / 'tcp22' / 'tcp_22_ssh_linpeas_raw.txt').write_text('raw only', encoding='utf8')

	def tearDown(self):
		self.temp.cleanup()

	def test_preview_redacts_secrets_and_skips_raw(self):
		preview, count, report = create_report(self.root, None)
		text = preview.read_text(encoding='utf8')
		self.assertIn('tcp_22_ssh_linpeas.txt:1 Potential issue', text)
		self.assertIn('password: [redacted]', text)
		self.assertIn('[private key redacted]', text)
		self.assertNotIn('hunter2', text)
		self.assertNotIn('secret bytes', text)
		self.assertNotIn('raw only', text)
		self.assertEqual(count, 1)
		self.assertIsNone(report)
		self.assertEqual(preview.stat().st_mode & 0o777, 0o600)

	def test_rejects_files_outside_results(self):
		with self.assertRaises(ValueError):
			prepare_input(self.root, ['../outside.txt'])

	def test_chunk_limit_is_explicit(self):
		with self.assertRaises(ValueError):
			split_input('x' * 40001, 2)
		with self.assertRaises(ValueError):
			section_chunks('a.txt:1 first\nb.txt:1 second\n', 1)

	def test_send_writes_report_only_after_completed_responses(self):
		create_report(self.root, None)
		with patch('autorecon.ai_report.access_token', return_value='mock-token'), patch(
			'autorecon.ai_report._response', side_effect=['Partial finding', 'Final finding']
		) as send:
			preview, count, report = create_report(self.root, 'model-test', send=True)
		self.assertEqual(count, 1)
		self.assertEqual(send.call_count, 2)
		self.assertIn('Final finding', report.read_text(encoding='utf8'))
		self.assertEqual(report.stat().st_mode & 0o777, 0o600)

	def test_send_uses_edited_preview(self):
		preview, _, _ = create_report(self.root, None)
		preview.write_text('scans/tcp22/check.txt:1 Manually reviewed evidence\n', encoding='utf8')
		with patch('autorecon.ai_report.access_token', return_value='mock-token'), patch(
			'autorecon.ai_report._response', side_effect=['Partial', 'Final']
		) as send:
			create_report(self.root, 'model-test', send=True)
		self.assertIn('Manually reviewed evidence', send.call_args_list[0].args[3])
		self.assertNotIn('Potential issue', send.call_args_list[0].args[3])

	def test_streaming_request_requires_completion_and_no_storage(self):
		class FakeResponse:
			encoding = None

			def raise_for_status(self):
				pass

			def iter_lines(self, decode_unicode=False):
				return iter(['data: {"type":"response.output_text.delta","delta":"Finding"}', '',
				             'data: {"type":"response.completed"}', ''])

			def close(self):
				pass

		with patch('autorecon.ai_report.requests.post', return_value=FakeResponse()) as post:
			self.assertEqual(_response('token', 'model', 'rules', 'scan data'), 'Finding')
		payload = post.call_args.kwargs['json']
		self.assertIs(payload['store'], False)
		self.assertIs(payload['stream'], True)
		self.assertEqual(payload['input'][0]['content'], 'scan data')

	def test_completed_scan_reviews_files_separately(self):
		(self.root / 'scans' / 'tcp22' / 'tcp_22_ssh_host.txt').write_text('Hostname example\n', encoding='utf8')
		with patch('autorecon.ai_report.access_token', return_value='mock-token'), patch(
			'autorecon.ai_report._response', side_effect=['Host review', 'LinPEAS review', 'Combined summary']
		) as send:
			report = review_completed_scan(self.root, 'model-test')
		text = report.read_text(encoding='utf8')
		self.assertEqual(send.call_count, 3)
		self.assertIn('## Consolidated findings\n\nCombined summary', text)
		self.assertIn('### `scans/tcp22/tcp_22_ssh_host.txt`', text)
		self.assertIn('### `scans/tcp22/tcp_22_ssh_linpeas.txt`', text)
		self.assertIn('Host review', text)
		self.assertIn('LinPEAS review', text)

	def test_partial_reviews_survive_later_failure(self):
		(self.root / 'scans' / 'tcp22' / 'tcp_22_ssh_host.txt').write_text('Hostname example\n', encoding='utf8')
		with patch('autorecon.ai_report.access_token', return_value='mock-token'), patch(
			'autorecon.ai_report._response', side_effect=['First review', RuntimeError('limit')]
		):
			with self.assertRaises(RuntimeError):
				review_completed_scan(self.root, 'model-test')
		text = (self.root / 'ai-report.md').read_text(encoding='utf8')
		self.assertIn('First review', text)
		self.assertIn('Consolidated summary pending', text)

	def test_incremental_review_writes_each_scan_before_final_summary(self):
		host = self.root / 'scans' / 'tcp22' / 'host.txt'
		linpeas = self.root / 'scans' / 'tcp22' / 'tcp_22_ssh_linpeas.txt'
		report = IncrementalReport(self.root, 'model-test')
		host.write_text('Host finding\n', encoding='utf8')
		linpeas.write_text('Fresh LinPEAS result\n', encoding='utf8')
		with patch('autorecon.ai_report.access_token', return_value='mock-token'), patch(
			'autorecon.ai_report._response', side_effect=['Host review', 'LinPEAS review', 'Final summary']
		) as send:
			report.review_paths([host])
			first = report.report_path.read_text(encoding='utf8')
			self.assertIn('Host review', first)
			self.assertIn('Consolidated summary pending', first)
			report.review_paths([host, linpeas])
			self.assertEqual(send.call_count, 2)
			report.review_remaining()
			self.assertEqual(send.call_count, 2)
			report.finish()
		self.assertEqual(send.call_count, 3)
		self.assertIn('Final summary', report.report_path.read_text(encoding='utf8'))
		self.assertIn('Host finding', (self.root / 'ai-report-input.txt').read_text(encoding='utf8'))

	def test_incremental_review_skips_unchanged_prior_scan_output(self):
		report = IncrementalReport(self.root, 'model-test')
		with patch('autorecon.ai_report._response') as send:
			report.review_remaining()
			report.finish()
		self.assertEqual(send.call_count, 0)
		self.assertIn('No eligible scan text', report.report_path.read_text(encoding='utf8'))


if __name__ == '__main__':
	unittest.main()
