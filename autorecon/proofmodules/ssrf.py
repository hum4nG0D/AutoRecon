"""SSRF confirmation via out-of-band callback correlation.

The parameter value is replaced with a nonce-tagged callback URL (HTTP fetch
attempt) and a nonce-tagged bare hostname (DNS resolution attempt). A
confirmed finding requires an interaction carrying our nonce to arrive at
the callback provider, which the target can only cause by fetching or
resolving the value we supplied. Without a configured callback provider the
check fails closed as 'skipped'.
"""

import secrets

from autorecon.proofmodules.base import ProofModule


class SSRF(ProofModule):
    name = 'ssrf'
    check_name = 'ssrf_oob'
    description = 'Server-side request forgery (out-of-band callback correlation)'
    severity = 'critical'
    cwe = 'CWE-918'
    rationale = 'Probes only point the server at a callback URL under our control; the callback server receives one request and no target data is requested or returned.'
    max_requests = 2

    def verify(self, url, parameter, context):
        context.check_target(url, parameter)
        if context.callback is None:
            return self.finding('skipped', url, parameter, [],
                                allowed_origin=context.allowed_origin,
                                reason='no out-of-band callback configured')
        nonce_http = secrets.token_hex(8)
        nonce_dns = secrets.token_hex(8)
        callback_http = context.oob_url(nonce_http)
        callback_dns = context.oob_url(nonce_dns).split('://', 1)[1]
        cases = [
            ('probe-http-url', callback_http + '/', nonce_http),
            ('probe-hostname', callback_dns, nonce_dns),
        ]
        probes = []
        nonces = []
        for label, payload, nonce in cases:
            status, body = context.probe(url, parameter, payload)
            probes.append(self.probe_entry(label, status, payload, None, False, body))
            nonces.append((label, nonce))
        confirmed = False
        hits = {}
        for label, nonce in nonces:
            interaction = context.oob_wait(nonce)
            if interaction is not None:
                hits[label] = interaction
                for probe in probes:
                    if probe['kind'] == label:
                        probe['evaluated'] = True
        if hits:
            confirmed = True
        return self.finding('confirmed' if confirmed else 'inconclusive',
                            url, parameter, probes, allowed_origin=context.allowed_origin,
                            interactions={label: {'protocol': item.get('protocol'),
                                                  'remote-address': item.get('remote-address')}
                                          for label, item in hits.items()} if hits else None)
