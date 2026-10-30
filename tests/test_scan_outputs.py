import unittest

from autorecon.targets import command_text_outputs


class ScanOutputTests(unittest.TestCase):
	def test_nmap_normal_output_is_recognized(self):
		self.assertEqual(command_text_outputs('nmap -sV -oN "/tmp/scan results/ssh_nmap.txt" -oX /tmp/ssh.xml 192.0.2.10'),
			['/tmp/scan results/ssh_nmap.txt'])


if __name__ == '__main__':
	unittest.main()
