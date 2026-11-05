"""Bounded HTTP discovery and proof checks for GET parameters."""

import argparse
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

from autorecon.proofmodules import all_modules, select_modules
from autorecon.proofmodules.commandinjection import CommandInjection
from autorecon.proofmodules.http import (ProofContext, checked_origin, display_url,
                                         origin, with_parameter, write_private_text)
from autorecon.proofmodules.ssti import TemplateExpression


REQUEST_BUDGET = 150

# Re-exported for the plugin and tests; the implementations moved to proofmodules.http.
__all__ = ['origin', 'checked_origin', 'display_url', 'with_parameter', 'write_private_text',
           'discover_get_inputs', 'verify_ssti', 'run_entries', 'run_manifest',
           'write_summary', 'session_from_headers', 'main']


class _InputsParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.form = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'a' and values.get('href'):
            self.links.append(values['href'])
        elif tag == 'form':
            self.form = {'action': values.get('action', ''),
                         'method': values.get('method', 'get').lower(), 'fields': []}
        elif tag == 'input' and self.form is not None and values.get('name'):
            self.form['fields'].append((values['name'], values.get('value', ''),
                                        values.get('type', 'text').lower()))

    def handle_endtag(self, tag):
        if tag == 'form' and self.form is not None:
            self.forms.append(self.form)
            self.form = None


def discover_get_inputs(allowed_origin, timeout=8, session=None, max_pages=20, max_inputs=20):
    """Follow same-origin HTML links without queries and collect bounded GET inputs."""
    checked_origin(allowed_origin)
    if timeout <= 0 or timeout > 30 or not 1 <= max_pages <= 100 or not 1 <= max_inputs <= 50:
        raise ValueError('Discovery limits are outside their allowed range.')
    client = session or requests.Session()
    root = allowed_origin.rstrip('/') + '/'
    queue = [(root, 0)]
    visited = set()
    entries = []
    seen_inputs = set()
    unsafe_words = ('logout', 'signout', 'delete', 'remove', 'destroy', 'reset',
                    'shutdown', 'restart', 'install', 'upload', 'update')

    def in_scope(candidate):
        try:
            parts = urlsplit(candidate)
            if origin(candidate) != origin(allowed_origin) or parts.fragment:
                return False
            return not any(word in parts.path.lower() for word in unsafe_words)
        except ValueError:
            return False

    def collect(candidate, only_parameter=None):
        if not in_scope(candidate):
            return
        for key, _ in parse_qsl(urlsplit(candidate).query, keep_blank_values=True):
            if only_parameter is not None and key != only_parameter:
                continue
            if key.lower() in ('action', 'cmd', 'command', 'delete', 'remove', 'do', 'submit'):
                continue
            identity = (candidate, key)
            if identity not in seen_inputs and len(entries) < max_inputs:
                seen_inputs.add(identity)
                entries.append({'url': candidate, 'parameter': key})

    while queue and len(visited) < max_pages and len(entries) < max_inputs:
        page, depth = queue.pop(0)
        if page in visited or not in_scope(page):
            continue
        visited.add(page)
        try:
            response = client.get(page, timeout=timeout, allow_redirects=False,
                                  headers={'Accept': 'text/html'})
        except requests.RequestException:
            continue
        if response.status_code != 200 or 'text/html' not in response.headers.get('Content-Type', '').lower():
            continue
        parser = _InputsParser()
        parser.feed(response.text[:262144])
        for link in parser.links:
            candidate = urljoin(page, link)
            if not in_scope(candidate):
                continue
            if urlsplit(candidate).query:
                collect(candidate)
            elif depth < 2 and candidate not in visited:
                parts = urlsplit(candidate)
                path = parts.path.lower()
                if path.endswith(('/', '.html', '.htm', '.jsp', '.php', '.asp', '.aspx')) or '.' not in path.rsplit('/', 1)[-1]:
                    queue.append((candidate, depth + 1))
        for form in parser.forms:
            if form['method'] != 'get':
                continue
            action = urljoin(page, form['action'])
            if not in_scope(action):
                continue
            existing = parse_qsl(urlsplit(action).query, keep_blank_values=True)
            fields = existing + [(name, value) for name, value, kind in form['fields']
                                 if kind in ('text', 'search', 'hidden')]
            if not fields:
                continue
            parts = urlsplit(action)
            candidate = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urlencode(fields), ''))
            for name, _, kind in form['fields']:
                if kind in ('text', 'search'):
                    collect(candidate, name)
    return entries


def verify_ssti(url, parameter, allowed_origin, timeout=8, session=None):
    """Confirm two distinct arithmetic evaluations; never follow redirects."""
    context = ProofContext(allowed_origin, timeout=timeout, session=session)
    return TemplateExpression().verify(url, parameter, context)


def run_entries(entries, allowed_origin, output_path, timeout=8, session=None, modules=None):
    scope = checked_origin(allowed_origin)
    if not isinstance(entries, list):
        raise ValueError('The manifest must be a JSON list of URL and parameter objects.')
    if len(entries) > 50:
        raise ValueError('The manifest may contain at most 50 entries.')
    # Validate all scope entries before sending any request.
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get('url'), str) or not isinstance(item.get('parameter'), str):
            raise ValueError('Each entry needs string url and parameter fields.')
        if origin(item['url']) != scope:
            raise ValueError('Manifest contains an out-of-scope URL.')
        with_parameter(item['url'], item['parameter'], 'scope-check')
    selected = select_modules(modules)
    needed = len(entries) * sum(module.max_requests for module in selected)
    if needed > REQUEST_BUDGET:
        raise ValueError('Selected checks need {} requests; the limit is {}. Use fewer entries or select fewer modules.'.format(needed, REQUEST_BUDGET))
    context = ProofContext(allowed_origin, timeout=timeout, session=session)
    findings = []
    for item in entries:
        for module in selected:
            try:
                findings.append(module.verify(item['url'], item['parameter'], context))
            except requests.RequestException as exc:
                findings.append(module.error_finding(item['url'], item['parameter'], type(exc).__name__))
            except ValueError as exc:
                findings.append(module.error_finding(item['url'], item['parameter'], str(exc)))
    result = {'schema_version': 2, 'allowed_origin': allowed_origin, 'findings': findings}
    write_private_text(output_path, json.dumps(result, indent=2) + '\n')
    return result


def run_manifest(manifest_path, allowed_origin, output_path, timeout=8, session=None, modules=None):
    entries = json.loads(Path(manifest_path).read_text(encoding='utf8'))
    return run_entries(entries, allowed_origin, output_path, timeout, session, modules)


def write_summary(result, output_path):
    """Write a compact text report that AutoRecon can include in AI review."""
    lines = ['HTTP proof check summary', 'Allowed origin: ' + result['allowed_origin'], '']
    for finding in result['findings']:
        lines.extend(['Status: ' + finding['status'],
                      'Module: ' + str(finding.get('module', '')),
                      'Severity: ' + str(finding.get('severity', '')),
                      'Check: ' + finding['check'],
                      'URL: ' + finding['url'], 'Parameter: ' + finding['parameter']])
        for probe in finding.get('probes', []):
            lines.append(probe['kind'] + ': HTTP ' + str(probe['status']) +
                         ', evaluated=' + str(probe['evaluated']) +
                         ', payload=' + probe['payload'] +
                         (', expected=' + probe['expected'] if probe['expected'] else ''))
        lines.append('')
    write_private_text(output_path, '\n'.join(lines))


def session_from_headers(path):
    headers = json.loads(Path(path).read_text(encoding='utf8'))
    if not isinstance(headers, dict) or not all(isinstance(key, str) and isinstance(value, str)
                                                 for key, value in headers.items()):
        raise ValueError('Headers file must be a JSON object of string names and values.')
    forbidden = {'host', 'content-length', 'transfer-encoding', 'connection'}
    for key, value in headers.items():
        if key.lower() in forbidden or '\n' in key + value or '\r' in key + value:
            raise ValueError('Headers file contains a disallowed header or newline.')
    session = requests.Session()
    session.headers.update(headers)
    return session


def main():
    parser = argparse.ArgumentParser(description='Discover GET inputs and run bounded HTTP proof checks.')
    parser.add_argument('--manifest', help='Optional JSON list of {"url": ..., "parameter": ...} objects')
    parser.add_argument('--allow-origin', required=True, help='Exact HTTP(S) origin permitted for requests')
    parser.add_argument('--output', required=True, help='Evidence JSON path')
    parser.add_argument('--timeout', type=float, default=8)
    parser.add_argument('--module', action='append', choices=[module.name for module in all_modules()],
                        metavar='NAME', help='Proof module to run; repeat to combine. Default: all modules.')
    parser.add_argument('--headers-file', help='Optional JSON request headers, such as Cookie or Authorization')
    args = parser.parse_args()
    try:
        session = session_from_headers(args.headers_file) if args.headers_file else None
        if args.manifest:
            result = run_manifest(args.manifest, args.allow_origin, args.output, args.timeout, session, args.module)
        else:
            entries = discover_get_inputs(args.allow_origin, args.timeout, session)
            result = run_entries(entries, args.allow_origin, args.output, args.timeout, session, args.module)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    write_summary(result, str(Path(args.output).with_suffix('.txt')))
    confirmed = sum(item['status'] == 'confirmed' for item in result['findings'])
    print(f"Checked {len(result['findings'])} input(s); {confirmed} confirmed. Evidence: {args.output}")


if __name__ == '__main__':
    main()
