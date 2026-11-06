"""Base class for proof-of-exploit modules.

Every module must be read-only: probes may only cause the target to reflect
or evaluate attacker-chosen text, never to modify state. The nonce-and-control
contract is the same across modules: a finding is confirmed only when a
nonce-tagged probe produces a deterministic signal that plain reflection
cannot produce.
"""

from datetime import datetime, timezone

from autorecon.proofmodules.http import display_url


class ProofModule(object):
    """One vulnerability class with a safe, self-proving confirmation check."""

    name = None          # short slug, e.g. 'command-injection'
    check_name = None    # evidence 'check' value, e.g. 'command_injection'
    description = None
    severity = None      # 'critical' | 'high' | 'medium' | 'low'
    cwe = None           # e.g. 'CWE-78'
    read_only = True     # probes must never modify target state
    rationale = ''       # why the probes are read-only; reviewed with payloads
    max_requests = 3     # per parameter; enforced by the shared request budget

    def finding(self, status, url, parameter, probes, **extra):
        result = {
            'schema_version': 2,
            'module': self.name,
            'check': self.check_name,
            'severity': self.severity,
            'cwe': self.cwe,
            'status': status,
            'url': display_url(url),
            'parameter': parameter,
            'tested_at': datetime.now(timezone.utc).isoformat(),
            'probes': probes,
        }
        result.update(extra)
        return result

    def error_finding(self, url, parameter, message):
        return {'schema_version': 2, 'module': self.name, 'check': self.check_name,
                'severity': self.severity, 'cwe': self.cwe, 'status': 'error',
                'url': display_url(url), 'parameter': parameter, 'error': message}

    def probe_entry(self, kind, status, payload, expected, evaluated, body, delay=None):
        match = expected if evaluated else payload
        offset = body.find(match) if match else -1
        excerpt = body[max(0, offset - 60):offset + len(match) + 60] if offset >= 0 else ''
        entry = {'kind': kind, 'status': status, 'payload': payload,
                 'expected': expected, 'evaluated': evaluated, 'excerpt': excerpt}
        if delay is not None:
            entry['delay'] = delay
        return entry

    def verify(self, url, parameter, context):
        raise NotImplementedError
