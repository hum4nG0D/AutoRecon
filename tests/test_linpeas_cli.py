import unittest
from unittest.mock import patch

from autorecon.linpeas_cli import main


class LinpeasCLITests(unittest.TestCase):
	def test_short_command_selects_only_linpeas(self):
		with patch('autorecon.linpeas_cli.subprocess.call', return_value=0) as call:
			self.assertEqual(main(['192.168.1.30', '-u', 'websec', '-i', '~/.ssh/cs6035']), 0)
		arguments = call.call_args.args[0]
		self.assertIn('tcp/22/ssh', arguments)
		self.assertIn('--tags', arguments)
		self.assertEqual(arguments[arguments.index('--tags') + 1], 'authenticated')
		self.assertEqual(arguments[arguments.index('--service-scans') + 1], 'ssh-authenticated-host-checks')
		self.assertIn('--ssh-authenticated-host-checks.linpeas-only', arguments)
		self.assertNotIn('--output', arguments)

	def test_port_and_output_are_forwarded(self):
		with patch('autorecon.linpeas_cli.subprocess.call', return_value=0) as call:
			main(['host.example', '-u', 'audit', '-i', '/tmp/key', '-p', '2222', '-o', 'results/rerun', '--ai'])
		arguments = call.call_args.args[0]
		self.assertIn('tcp/2222/ssh', arguments)
		self.assertEqual(arguments[arguments.index('--output') + 1], 'results/rerun')
		self.assertIn('--ai', arguments)


if __name__ == '__main__':
	unittest.main()
