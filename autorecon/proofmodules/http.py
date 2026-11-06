"""Shared HTTP guardrails for proof modules.

These helpers predate the module registry and live in autorecon.proof as
well, which re-exports them for the plugin and tests.
"""

import os
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
    output = Path(str(path))
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf8') as destination:
        os.fchmod(destination.fileno(), 0o600)
        destination.write(value)


class ProofContext(object):
    """Per-run guardrails shared by every proof module.

    Enforces the exact allowed origin, the timeout cap, and a single request
    budget across all modules and parameters in one run.
    """

    def __init__(self, allowed_origin, timeout=8, session=None, max_requests=300,
                 callback=None, oob_timeout=10.0, oob_budget=45.0):
        checked_origin(allowed_origin)
        if timeout <= 0 or timeout > 30:
            raise ValueError('Timeout must be between 0 and 30 seconds.')
        self.allowed_origin = allowed_origin
        self.scope = checked_origin(allowed_origin)
        self.timeout = timeout
        self.session = session or requests.Session()
        self.max_requests = max_requests
        self.requests_used = 0
        self.callback = callback
        self.oob_timeout = oob_timeout
        self.oob_budget = oob_budget
        self.oob_deadline = time.monotonic() + oob_budget if callback is not None else None
        # Per-entry transport: GET (query parameter) by default; manifest
        # entries may switch to POST with a body template containing {value}.
        self.entry_method = 'GET'
        self.body_template = None
        self.body_content_type = 'text/plain'

    def set_entry(self, entry):
        """Select the transport for the entry about to be verified."""
        if not isinstance(entry, dict):
            self.entry_method, self.body_template, self.body_content_type = 'GET', None, 'text/plain'
            return
        self.entry_method = str(entry.get('method', 'GET')).upper()
        self.body_template = entry.get('body_template')
        self.body_content_type = entry.get('content_type', 'text/plain')

    def check_target(self, url, parameter):
        """Validate a module target the same way for every module."""
        if origin(url) != self.scope:
            raise ValueError('Target URL is outside the exact allowed origin.')
        if not parameter or not isinstance(parameter, str):
            raise ValueError('A parameter name is required.')
        if self.entry_method == 'POST':
            if not self.body_template or '{value}' not in self.body_template:
                raise ValueError('POST entries need a body_template containing {value}.')
        else:
            with_parameter(url, parameter, 'scope-check')

    def oob_url(self, nonce):
        """Return a unique callback URL for the nonce, or None if unavailable."""
        if self.callback is None:
            return None
        return self.callback.url(nonce)

    def oob_wait(self, nonce, timeout=None):
        """Wait for a callback interaction, bounded by the run-level budget.

        Returns the interaction dict, or None.
        """
        if self.callback is None:
            return None
        limit = self.oob_timeout if timeout is None else timeout
        remaining = self.oob_deadline - time.monotonic()
        if remaining <= 0:
            return None
        return self.callback.poll(nonce, timeout=min(limit, remaining))

    def _request(self, url, parameter, value):
        if origin(url) != self.scope:
            raise ValueError('Target URL is outside the exact allowed origin.')
        if self.requests_used >= self.max_requests:
            raise ValueError('Proof check request budget exceeded.')
        self.requests_used += 1
        headers = {'Accept': 'text/html, text/plain;q=0.9'}
        if self.entry_method == 'POST':
            if not self.body_template or '{value}' not in self.body_template:
                raise ValueError('POST entries need a body_template containing {value}.')
            headers['Content-Type'] = self.body_content_type
            return self.session.post(url, data=self.body_template.replace('{value}', value).encode('utf8'),
                                     timeout=self.timeout, allow_redirects=False, headers=headers)
        return self.session.get(with_parameter(url, parameter, value), timeout=self.timeout,
                                allow_redirects=False, headers=headers)

    def probe_timed(self, url, parameter, value):
        """Send one bounded probe and return (status_code, body, elapsed_seconds)."""
        started = time.monotonic()
        response = self._request(url, parameter, value)
        elapsed = time.monotonic() - started
        return response.status_code, response.text[:262144], elapsed

    def probe(self, url, parameter, value):
        """Send one bounded probe and return (status_code, body)."""
        status, body, _ = self.probe_timed(url, parameter, value)
        return status, body
