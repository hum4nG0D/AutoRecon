import asyncio
import importlib
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from autorecon.targets import command_text_outputs


class ScanOutputTests(unittest.TestCase):
	def test_nmap_normal_output_is_recognized(self):
		self.assertEqual(command_text_outputs('nmap -sV -oN "/tmp/scan results/ssh_nmap.txt" -oX /tmp/ssh.xml 192.0.2.10'),
			['/tmp/scan results/ssh_nmap.txt'])

	def test_missing_http_files_log_one_service_tag(self):
		for module_name, class_name, filename in (
			('curl-known-security', 'CurlKnownSecurity', '.well-known/security.txt'),
			('curl-robots', 'CurlRobots', 'robots.txt'),
		):
			with self.subTest(filename=filename):
				module = importlib.import_module('autorecon.default-plugins.' + module_name)
				plugin = getattr(module, class_name)()
				stdout = SimpleNamespace(readlines=AsyncMock(return_value=[]))
				service = SimpleNamespace(
					protocol='tcp',
					execute=AsyncMock(return_value=(SimpleNamespace(returncode=22), stdout, None)),
					info=Mock(),
				)
				asyncio.run(plugin.run(service))
				service.info.assert_called_once_with(
					'There did not appear to be a {} file in the webroot (/).'.format(filename))


if __name__ == '__main__':
	unittest.main()
