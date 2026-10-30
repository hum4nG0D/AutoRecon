"""Short command for running only the authenticated SSH LinPEAS plugin."""

import argparse
import subprocess
import sys


def main(argv=None):
	parser = argparse.ArgumentParser(prog='autorecon-linpeas', description='Run only LinPEAS over SSH; skip AutoRecon discovery and other scans.')
	parser.add_argument('target', help='Target IP address or hostname.')
	parser.add_argument('-u', '--user', required=True, help='SSH username.')
	parser.add_argument('-i', '--identity', required=True, help='SSH private key path.')
	parser.add_argument('-p', '--port', type=int, default=22, help='SSH port (default: 22).')
	parser.add_argument('-o', '--output', help='Results directory (default: results).')
	parser.add_argument('--ai', action='store_true', help='Automatically review completed LinPEAS output with ChatGPT.')
	args = parser.parse_args(argv)
	if not 1 <= args.port <= 65535:
		parser.error('SSH port must be between 1 and 65535.')
	command = [
		sys.executable, '-m', 'autorecon.main', args.target,
		'--force-services', 'tcp/{}/ssh'.format(args.port),
		'--tags', 'authenticated',
		'--service-scans', 'ssh-authenticated-host-checks',
		'--ssh-authenticated-host-checks.username', args.user,
		'--ssh-authenticated-host-checks.identity-file', args.identity,
		'--ssh-authenticated-host-checks.linpeas',
		'--ssh-authenticated-host-checks.linpeas-only',
	]
	if args.output:
		command.extend(['--output', args.output])
	if args.ai:
		command.append('--ai')
	return subprocess.call(command)


if __name__ == '__main__':
	sys.exit(main())
