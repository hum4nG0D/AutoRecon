import os
import shlex
from shutil import which

from autorecon.config import config
from autorecon.plugins import ServiceScan
from autorecon.signature import bridge_findings, parse_nuclei_jsonl, write_signatures_json


def build_command(target, jsonl, templates='', severity=(), tags=(),
                  rate_limit='150', timeout='10', disable_oob=False, extras=''):
    """Assemble the nuclei command line. Kept module-level for testing."""
    cmd = 'nuclei -u ' + shlex.quote(target) + ' -jsonl -silent -no-color -o ' + shlex.quote(jsonl)
    if severity:
        cmd += ' -severity ' + shlex.quote(','.join(severity))
    if tags:
        cmd += ' -tags ' + shlex.quote(','.join(tags))
    if templates:
        cmd += ' -t ' + shlex.quote(templates)
    cmd += ' -rate-limit ' + shlex.quote(str(rate_limit or '150'))
    cmd += ' -timeout ' + shlex.quote(str(timeout or '10'))
    if disable_oob:
        cmd += ' -no-interactsh'
    if extras:
        cmd += ' ' + extras
    return cmd


class SignatureScan(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = 'Signature Scan'
        self.tags = ['signatures']

    def configure(self):
        self.match_service_name('^http')
        self.add_option('templates', default='',
                        help='Comma-separated nuclei template paths or URLs to run. Default: the nuclei built-in template set.')
        self.add_list_option('severity', default=['critical', 'high', 'medium'],
                             help='Template severities to run. Default: critical high medium.')
        self.add_list_option('tags', help='Only run templates carrying these tags.')
        self.add_option('rate-limit', default='150', help='Maximum requests per second. Default: 150.')
        self.add_option('timeout', default='10', help='Nuclei run timeout in minutes. Default: 10.')
        self.add_true_option('disable-oob', help='Disable nuclei interactsh callbacks (-no-interactsh).')
        self.add_false_option('skip-update', help='Skip the per-run nuclei binary and template self-update check. Default: update before scanning.')
        self.add_false_option('no-bridge', help='Do not re-run matched signatures through the proof modules for confirmation. Default: bridge on.')
        self.add_choice_option('oob', ['interactsh'], help='Out-of-band provider for blind bridge checks (ssrf, xxe). Default: none.')
        self.add_option('oob-timeout', default='10', help='Seconds to wait per blind bridge callback, at most 60. Default: 10.')
        self.add_option('extras', default='', help='Additional raw nuclei flags.')

    def check(self):
        if which('nuclei') is None:
            self.error('The nuclei program could not be found. Install it from https://github.com/projectdiscovery/nuclei '
                       '(included in the Docker image), or disable the plugin with --exclude-tags signatures.')
            return False
        if not self.get_option('skip-update'):
            from subprocess import PIPE, run
            try:
                result = run(['nuclei', '-update', '-ut', '-silent'],
                             stdout=PIPE, stderr=PIPE, timeout=300)
                if result.returncode != 0:
                    detail = result.stderr.decode('utf8', 'replace').strip()[:200]
                    self.warn('nuclei self-update failed; continuing with the installed version. ' + detail)
            except Exception as ex:
                self.warn('nuclei self-update skipped: ' + str(ex))

    async def run(self, service):
        if service.protocol != 'tcp':
            return
        scheme = 'https' if 'https' in service.name or service.secure else 'http'
        address = service.target.address
        if ':' in address and not address.startswith('['):
            address = '[' + address + ']'
        target = scheme + '://' + address + ':' + str(service.port)
        scandir = service.target.scandir
        if not config['no_port_dirs']:
            scandir = os.path.join(scandir, service.protocol + str(service.port))
        jsonl = os.path.join(scandir, service.protocol + '_' + str(service.port) + '_signatures.jsonl')
        output = os.path.join(scandir, service.protocol + '_' + str(service.port) + '_signatures.json')
        cmd = build_command(target, jsonl,
                            templates=self.get_option('templates'),
                            severity=self.get_option('severity') or (),
                            tags=self.get_option('tags') or (),
                            rate_limit=self.get_option('rate-limit'),
                            timeout=self.get_option('timeout'),
                            disable_oob=bool(self.get_option('disable-oob')),
                            extras=self.get_option('extras'))
        await service.execute(cmd)
        findings = parse_nuclei_jsonl(jsonl) if os.path.isfile(jsonl) else []
        if not self.get_option('no-bridge') and findings:
            bridge_output = os.path.join(scandir, service.protocol + '_' + str(service.port) + '_bridge.json')
            try:
                oob_timeout = float(self.get_option('oob-timeout') or 10)
                if not 0 < oob_timeout <= 60:
                    raise ValueError('OOB timeout must be between 0 and 60 seconds.')
                findings = bridge_findings(findings, bridge_output,
                                           oob=self.get_option('oob'), oob_timeout=oob_timeout)
            except (ValueError, TypeError) as ex:
                service.warn('Signature confirmation bridge skipped: ' + str(ex))
        write_signatures_json(output, findings)
        service.target.running_tasks[service.tag() + '/' + self.slug]['outputs'].extend([jsonl, output])
        confirmed = sum(1 for item in findings if item.get('status') == 'confirmed')
        service.info('Signature scan: ' + str(len(findings)) + ' matched template(s), ' + str(confirmed)
                     + ' confirmed by proof bridge; evidence saved to ' + output)
