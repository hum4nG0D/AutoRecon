import unittest
from argparse import Namespace

from autorecon.linpeas_options import apply_linpeas_options


class LinpeasOptionsTests(unittest.TestCase):
	def test_short_flags_enable_existing_plugin_option(self):
		args = Namespace(linpeas=True, ssh_user='websec', ssh_identity='~/.ssh/cs6035', **{
			'ssh_authenticated_host_checks.username': None,
			'ssh_authenticated_host_checks.identity_file': None,
			'ssh_authenticated_host_checks.linpeas': False,
		})
		apply_linpeas_options(args)
		self.assertEqual(vars(args)['ssh_authenticated_host_checks.username'], 'websec')
		self.assertEqual(vars(args)['ssh_authenticated_host_checks.identity_file'], '~/.ssh/cs6035')
		self.assertTrue(vars(args)['ssh_authenticated_host_checks.linpeas'])

	def test_linpeas_requires_credentials(self):
		args = Namespace(linpeas=True, ssh_user=None, ssh_identity=None)
		with self.assertRaisesRegex(ValueError, 'requires an SSH username'):
			apply_linpeas_options(args)

	def test_short_credentials_require_linpeas(self):
		args = Namespace(linpeas=False, ssh_user='websec', ssh_identity='key')
		with self.assertRaisesRegex(ValueError, 'require --linpeas'):
			apply_linpeas_options(args)

	def test_long_options_still_work_without_alias(self):
		args = Namespace(linpeas=False, ssh_user=None, ssh_identity=None, **{
			'ssh_authenticated_host_checks.username': 'websec',
			'ssh_authenticated_host_checks.identity_file': 'key',
			'ssh_authenticated_host_checks.linpeas': True,
		})
		apply_linpeas_options(args)
		self.assertTrue(vars(args)['ssh_authenticated_host_checks.linpeas'])


if __name__ == '__main__':
	unittest.main()
