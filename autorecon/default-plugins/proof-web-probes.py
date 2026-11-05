import asyncio
import json
import os

from autorecon.config import config
from autorecon.plugins import ServiceScan
from autorecon.proof import discover_get_inputs, origin, run_entries, session_from_headers, write_summary


class ProofWebProbes(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Proof Web Probes'
		self.tags = ['default', 'http', 'proof']

	def configure(self):
		self.match_service_name('^http')
		self.add_option('manifest', help='Optional JSON file selecting exact GET URLs and parameter names instead of automatic discovery.')
		self.add_option('timeout', default='8', help='Seconds allowed per HTTP request, at most 30.')
		self.add_option('headers-file', help='Optional JSON request headers for authenticated web checks.')
		self.add_list_option('modules', help='Proof modules to run (ssti, command-injection). Default: all modules.')

	async def run(self, service):
		manifest = self.get_option('manifest')
		if service.protocol != 'tcp':
			return
		try:
			timeout = float(self.get_option('timeout'))
			if not 0 < timeout <= 30:
				raise ValueError
		except (TypeError, ValueError):
			service.warn('Proof timeout must be between 0 and 30 seconds.')
			return
		scheme = 'https' if 'https' in service.name or service.secure else 'http'
		address = service.target.address
		if ':' in address and not address.startswith('['):
			address = '[' + address + ']'
		allowed_origin = scheme + '://' + address + ':' + str(service.port)
		scandir = service.target.scandir
		if not config['no_port_dirs']:
			scandir = os.path.join(scandir, service.protocol + str(service.port))
		output = os.path.join(scandir, service.protocol + '_' + str(service.port) + '_proof_web.json')
		try:
			headers_file = self.get_option('headers-file')
			session = session_from_headers(os.path.expanduser(headers_file)) if headers_file else None
			if manifest:
				with open(os.path.expanduser(manifest), encoding='utf-8') as source:
					entries = json.load(source)
				if not isinstance(entries, list):
					raise ValueError('Manifest must be a JSON list.')
				selected = [item for item in entries if isinstance(item, dict)
					and isinstance(item.get('url'), str) and origin(item['url']) == origin(allowed_origin)]
				if not selected:
					return
			else:
				selected = await asyncio.get_running_loop().run_in_executor(
					None, lambda: discover_get_inputs(allowed_origin, timeout, session))
			modules = self.get_option('modules')
			result = await asyncio.get_running_loop().run_in_executor(
				None, lambda: run_entries(selected, allowed_origin, output, timeout, session, modules))
		except (OSError, ValueError, json.JSONDecodeError) as exc:
			service.warn('Proof checks skipped: ' + str(exc))
			return
		summary = os.path.splitext(output)[0] + '.txt'
		write_summary(result, summary)
		service.target.running_tasks[service.tag() + '/' + self.slug]['outputs'].extend([output, summary])
		confirmed = sum(item['status'] == 'confirmed' for item in result['findings'])
		service.info('Proof checks: ' + str(len(result['findings'])) + ' inputs, ' + str(confirmed) + ' confirmed; evidence saved to ' + output)
