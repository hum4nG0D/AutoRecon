import os
import re
import shlex

from autorecon.plugins import ServiceScan


ANSI_ESCAPE = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))')


def write_readable_linpeas(raw_path, readable_path):
	with open(raw_path, 'r', encoding='utf8', errors='replace') as source, open(readable_path, 'w', encoding='utf8') as destination:
		for line in source:
			destination.write(ANSI_ESCAPE.sub('', line).replace('\r', '\n').replace('\x08', ''))


class SSHAuthenticatedHostChecks(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'SSH Authenticated Host Checks'
		self.tags = ['default', 'safe', 'ssh', 'authenticated']

	def configure(self):
		self.match_service_name('^ssh')
		self.add_option('username', help='SSH username for authenticated host checks. Requires --ssh-authenticated-host-checks.identity-file.')
		self.add_option('identity-file', help='Path to a private key for authenticated host checks. Requires --ssh-authenticated-host-checks.username.')
		self.add_option('config-file', help='Optional SSH client config file. Use /dev/null to ignore a broken system SSH config.')
		self.add_option('linpeas-script', help='Optional local path to linpeas.sh. Stream it over SSH and save its output separately.')
		self.add_option('linpeas-timeout', default='300', help='Maximum LinPEAS runtime in seconds. Default: 300.')
		self.add_option('linpeas-section', help='Optional LinPEAS -o section name, such as system_information.')

	async def run(self, service):
		username = self.get_option('username')
		identity_file = self.get_option('identity-file')
		linpeas_script = self.get_option('linpeas-script')
		if not username and not identity_file:
			if linpeas_script:
				service.warn('SSH username and identity file are required to run LinPEAS.')
			return
		if not username or not identity_file:
			service.warn('Both SSH username and identity file are required for authenticated host checks.')
			return

		identity_file = os.path.expanduser(identity_file)
		if not os.path.isfile(identity_file):
			service.warn('SSH identity file does not exist: ' + identity_file)
			return

		# Keep the remote commands read-only and label each section in the output.
		checks = [
			('Identity', 'id'),
			('Hostname', 'hostname'),
			('Kernel', 'uname -a'),
			('Operating system', 'cat /etc/os-release'),
			('Uptime', 'uptime'),
			('Network addresses', 'ip -brief address'),
			('Routes', 'ip route'),
			('Listening sockets', 'ss -tuln'),
			('Disk usage', 'df -h'),
			('Memory', 'free -h'),
		]
		script = '\n'.join('printf "\\n=== ' + title + ' ===\\n"; ' + command + ' 2>&1' for title, command in checks)
		remote_command = 'sh -c ' + shlex.quote(script)
		address = service.target.address
		# -- prevents an address beginning with a dash from being parsed as an option.
		arguments = [
			'ssh', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
			'-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectionAttempts=1',
			'-o', 'ConnectTimeout=10',
		]
		config_file = self.get_option('config-file')
		if config_file:
			arguments.extend(['-F', os.path.expanduser(config_file)])
		arguments.extend(['-i', identity_file, '-p', str(service.port), '-l', username, '--', address])
		command = ' '.join(shlex.quote(argument) for argument in arguments + [remote_command])
		# service.execute formats command strings, so preserve literal braces in paths.
		command = command.replace('{', '{{').replace('}', '}}')
		process, _, _ = await service.execute(
			command,
			outfile='{protocol}_{port}_ssh_authenticated_host_checks.txt',
			errfile='{protocol}_{port}_ssh_authenticated_host_checks_errors.txt',
		)
		if process.returncode:
			service.warn('Authenticated SSH host checks failed; see the SSH error output.')

		if linpeas_script:
			linpeas_script = os.path.abspath(os.path.expanduser(linpeas_script))
			if not os.path.isfile(linpeas_script) or not os.access(linpeas_script, os.R_OK):
				service.warn('LinPEAS script is not a readable file: ' + linpeas_script)
				return
			try:
				linpeas_timeout = int(self.get_option('linpeas-timeout'))
				if linpeas_timeout < 1:
					raise ValueError
			except (TypeError, ValueError):
				service.warn('LinPEAS timeout must be a positive number of seconds.')
				return
			linpeas_section = self.get_option('linpeas-section')
			if linpeas_section and not re.fullmatch(r'[A-Za-z0-9_,]+', linpeas_section):
				service.warn('LinPEAS section must contain only letters, numbers, underscores, and commas.')
				return

			# The local shell redirects the script into SSH; no target-side file is created.
			remote_linpeas_command = 'sh -s -- -q'
			if linpeas_section:
				remote_linpeas_command += ' -o ' + shlex.quote(linpeas_section)
			linpeas_arguments = ['timeout', '-k', '5s', str(linpeas_timeout) + 's'] + arguments + [remote_linpeas_command]
			linpeas_command = ' '.join(shlex.quote(argument) for argument in linpeas_arguments)
			linpeas_command += ' < ' + shlex.quote(linpeas_script)
			linpeas_command = linpeas_command.replace('{', '{{').replace('}', '}}')
			process, stdout, _ = await service.execute(
				linpeas_command,
				outfile='{protocol}_{port}_ssh_linpeas_raw.txt',
				errfile='{protocol}_{port}_ssh_linpeas_errors.txt',
			)
			readable_path = os.path.join(os.path.dirname(stdout.outfile), str(service.protocol) + '_' + str(service.port) + '_ssh_linpeas.txt')
			try:
				write_readable_linpeas(stdout.outfile, readable_path)
			except OSError as ex:
				service.warn('Could not write readable LinPEAS output: ' + str(ex))
			if process.returncode == 124:
				service.warn('LinPEAS over SSH reached its time limit; output may be incomplete.')
			elif process.returncode:
				service.warn('LinPEAS over SSH failed; see the LinPEAS error output.')
