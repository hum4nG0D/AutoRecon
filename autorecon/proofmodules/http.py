"""Shared HTTP guardrails for proof modules.

These helpers predate the module registry and live in autorecon.proof as
well, which re-exports them for the plugin and tests.
"""

import os
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

    def __init__(self, allowed_origin, timeout=8, session=None, max_requests=300):
        checked_origin(allowed_origin)
        if timeout <= 0 or timeout > 30:
            raise ValueError('Timeout must be between 0 and 30 seconds.')
        self.allowed_origin = allowed_origin
        self.scope = checked_origin(allowed_origin)
        self.timeout = timeout
        self.session = session or requests.Session()
        self.max_requests = max_requests
        self.requests_used = 0

    def check_target(self, url, parameter):
        """Validate a module target the same way for every module."""
        if origin(url) != self.scope:
            raise ValueError('Target URL is outside the exact allowed origin.')
        if not parameter or not isinstance(parameter, str):
            raise ValueError('A parameter name is required.')
        with_parameter(url, parameter, 'scope-check')

    def probe(self, url, parameter, value):
        """Send one bounded GET probe and return (status_code, body)."""
        if origin(url) != self.scope:
            raise ValueError('Target URL is outside the exact allowed origin.')
        if self.requests_used >= self.max_requests:
            raise ValueError('Proof check request budget exceeded.')
        self.requests_used += 1
        response = self.session.get(with_parameter(url, parameter, value), timeout=self.timeout,
                                    allow_redirects=False, headers={'Accept': 'text/html, text/plain;q=0.9'})
        return response.status_code, response.text[:262144]
