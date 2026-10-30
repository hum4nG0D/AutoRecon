import asyncio
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock


PLUGIN_PATH = Path(__file__).resolve().parents[1] / 'autorecon' / 'default-plugins' / 'ssh-authenticated-host-checks.py'
spec = importlib.util.spec_from_file_location('ssh_authenticated_host_checks', PLUGIN_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LinpeasOnlyTests(unittest.TestCase):
	def test_only_linpeas_command_runs(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			key = root / 'key'
			script = root / 'linpeas.sh'
			raw = root / 'tcp_22_ssh_linpeas_raw.txt'
			key.write_text('test key', encoding='utf8')
			script.write_text('#!/bin/sh\n', encoding='utf8')
			raw.write_text('LinPEAS result\n', encoding='utf8')
			plugin = module.SSHAuthenticatedHostChecks()
			plugin.slug = 'ssh-authenticated-host-checks'
			plugin.autorecon = SimpleNamespace(args=SimpleNamespace(**{
				'ssh_authenticated_host_checks.username': 'websec',
				'ssh_authenticated_host_checks.identity_file': str(key),
				'ssh_authenticated_host_checks.linpeas': True,
				'ssh_authenticated_host_checks.linpeas_only': True,
				'ssh_authenticated_host_checks.linpeas_script': str(script),
			}))
			service = SimpleNamespace(
				target=SimpleNamespace(address='192.0.2.10', running_tasks={
					'tcp/22/ssh/ssh-authenticated-host-checks': {'outputs': []}}), protocol='tcp', port=22,
				tag=lambda: 'tcp/22/ssh',
				warn=lambda message: self.fail(message),
				execute=AsyncMock(return_value=(SimpleNamespace(returncode=0), SimpleNamespace(outfile=str(raw)), None)),
			)
			asyncio.run(plugin.run(service))
			self.assertEqual(service.execute.await_count, 1)
			self.assertIn('linpeas.sh', service.execute.await_args.args[0])
			self.assertEqual((root / 'tcp_22_ssh_linpeas.txt').read_text(encoding='utf8'), 'LinPEAS result\n')
			self.assertIn(str(root / 'tcp_22_ssh_linpeas.txt'), service.target.running_tasks['tcp/22/ssh/ssh-authenticated-host-checks']['outputs'])


if __name__ == '__main__':
	unittest.main()
