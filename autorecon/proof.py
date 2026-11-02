"""Bounded HTTP discovery and proof checks for GET parameters."""

import argparse
import json
import os
import secrets
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests


def origin(url):
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
        raise ValueError('A URL must have an HTTP(S) scheme and host, without embedded credentials.')
    if parts.fragment:
        raise ValueError('URL fragments are not accepted.')
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    return parts.scheme.lower(), parts.hostname.lower().rstrip('.'), port


def checked_origin(url):
    parsed = urlsplit(url)
    value = origin(url)
    if parsed.path not in ('', '/') or parsed.query:
        raise ValueError('Allowed origin must contain only scheme, host, and optional port.')
    return value


def display_url(url):
    """Keep the path and parameter names without retaining unrelated query secrets."""
    parts = urlsplit(url)
    query = urlencode([(key, '<redacted>') for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ''))


def with_parameter(url, parameter, value):
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if parameter not in [key for key, _ in pairs]:
        raise ValueError('The selected parameter must already occur in the URL query.')
    updated = [(key, value if key == parameter else old) for key, old in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path or '/', urlencode(updated), ''))


def write_private_text(path, value):
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as destination:
        os.fchmod(destination.fileno(), 0o600)
        destination.write(value)


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


def _probe(session, url, parameter, value, timeout):
    response = session.get(with_parameter(url, parameter, value), timeout=timeout,
                           allow_redirects=False, headers={'Accept': 'text/html, text/plain;q=0.9'})
    return response.status_code, response.text[:262144]


def verify_ssti(url, parameter, allowed_origin, timeout=8, session=None):
    """Confirm two distinct arithmetic evaluations; never follow redirects."""
    if origin(url) != checked_origin(allowed_origin):
        raise ValueError('Target URL is outside the exact allowed origin.')
    if not parameter or not isinstance(parameter, str):
        raise ValueError('A parameter name is required.')
    if timeout <= 0 or timeout > 30:
        raise ValueError('Timeout must be between 0 and 30 seconds.')
    nonce = secrets.token_hex(8)
    probes = []
    client = session or requests.Session()
    cases = [('control', 'ar' + nonce + 'control', None)]
    for index in (1, 2):
        left = 10000 + secrets.randbelow(80000)
        right = 101 + secrets.randbelow(800)
        prefix = 'ar' + nonce + str(index) + 'a'
        suffix = 'z' + nonce + str(index)
        payload = prefix + '{{' + str(left) + '*' + str(right) + '}}' + suffix
        expected = prefix + str(left * right) + suffix
        cases.append(('probe' + str(index), payload, expected))
    confirmed = True
    for label, payload, expected in cases:
        status, body = _probe(client, url, parameter, payload, timeout)
        evaluated = bool(expected and expected in body and payload not in body)
        if label != 'control' and (not evaluated or status >= 300):
            confirmed = False
        if label == 'control' and (status >= 300 or payload not in body):
            confirmed = False
        match = expected if evaluated else payload
        offset = body.find(match)
        excerpt = body[max(0, offset - 60):offset + len(match) + 60] if offset >= 0 else ''
        probes.append({'kind': label, 'status': status, 'payload': payload,
                       'expected': expected, 'evaluated': evaluated, 'excerpt': excerpt})
    return {'schema_version': 1, 'check': 'ssti_arithmetic',
            'status': 'confirmed' if confirmed else 'inconclusive',
            'url': display_url(url), 'parameter': parameter,
            'allowed_origin': allowed_origin, 'tested_at': datetime.now(timezone.utc).isoformat(),
            'probes': probes}


def run_entries(entries, allowed_origin, output_path, timeout=8, session=None):
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
    findings = []
    for item in entries:
        try:
            findings.append(verify_ssti(item['url'], item['parameter'], allowed_origin, timeout, session))
        except requests.RequestException as exc:
            findings.append({'check': 'ssti_arithmetic', 'status': 'error',
                             'url': display_url(item['url']), 'parameter': item['parameter'],
                             'error': type(exc).__name__})
    result = {'schema_version': 1, 'allowed_origin': allowed_origin, 'findings': findings}
    write_private_text(output_path, json.dumps(result, indent=2) + '\n')
    return result


def run_manifest(manifest_path, allowed_origin, output_path, timeout=8, session=None):
    entries = json.loads(Path(manifest_path).read_text(encoding='utf-8'))
    return run_entries(entries, allowed_origin, output_path, timeout, session)


def write_summary(result, output_path):
    """Write a compact text report that AutoRecon can include in AI review."""
    lines = ['HTTP proof check summary', 'Allowed origin: ' + result['allowed_origin'], '']
    for finding in result['findings']:
        lines.extend(['Status: ' + finding['status'], 'Check: ' + finding['check'],
                      'URL: ' + finding['url'], 'Parameter: ' + finding['parameter']])
        for probe in finding.get('probes', []):
            lines.append(probe['kind'] + ': HTTP ' + str(probe['status']) +
                         ', evaluated=' + str(probe['evaluated']) +
                         ', payload=' + probe['payload'] +
                         (', expected=' + probe['expected'] if probe['expected'] else ''))
        lines.append('')
    write_private_text(output_path, '\n'.join(lines))


def session_from_headers(path):
    headers = json.loads(Path(path).read_text(encoding='utf-8'))
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
    parser.add_argument('--headers-file', help='Optional JSON request headers, such as Cookie or Authorization')
    args = parser.parse_args()
    try:
        session = session_from_headers(args.headers_file) if args.headers_file else None
        if args.manifest:
            result = run_manifest(args.manifest, args.allow_origin, args.output, args.timeout, session)
        else:
            entries = discover_get_inputs(args.allow_origin, args.timeout, session)
            result = run_entries(entries, args.allow_origin, args.output, args.timeout, session)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    write_summary(result, str(Path(args.output).with_suffix('.txt')))
    confirmed = sum(item['status'] == 'confirmed' for item in result['findings'])
    print(f"Checked {len(result['findings'])} input(s); {confirmed} confirmed. Evidence: {args.output}")


if __name__ == '__main__':
    main()
