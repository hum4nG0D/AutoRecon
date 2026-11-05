"""OS command injection confirmation with read-only arithmetic markers.

The deterministic signal is shell arithmetic inside echo: a sanitizing proxy
could strip the punctuation and leave the digits, but it cannot produce the
sum, so a confirmed finding requires the computed value to appear while the
full payload does not. Two distinct shell syntaxes must both evaluate.
"""

import secrets

from autorecon.proofmodules.base import ProofModule


class CommandInjection(ProofModule):
    name = 'command-injection'
    check_name = 'command_injection'
    description = 'OS command injection (echo-marker evaluation via two distinct shell syntaxes)'
    severity = 'critical'
    cwe = 'CWE-78'
    rationale = 'Every probe only runs echo with a random arithmetic expression; the computed sum proves execution without reading files, changing state, or launching other programs.'
    max_requests = 3

    SYNTAXES = (
        ('substitution', '$(echo $(({:d}+{:d})))'),
        ('backticks', '`echo $(({:d}+{:d}))`'),
    )

    def verify(self, url, parameter, context):
        context.check_target(url, parameter)
        nonce = secrets.token_hex(8)
        probes = []
        cases = [('control', 'ar' + nonce + 'control', None)]
        for index, (label, template) in enumerate(self.SYNTAXES, 1):
            left = 10000 + secrets.randbelow(80000)
            right = 101 + secrets.randbelow(800)
            marker = str(left + right)
            prefix = 'ar' + nonce + str(index)
            cases.append(('probe-' + label, prefix + template.format(left, right), prefix + marker))
        confirmed = True
        for label, payload, expected in cases:
            status, body = context.probe(url, parameter, payload)
            evaluated = bool(expected and expected in body and payload not in body)
            if label != 'control' and (not evaluated or status >= 300):
                confirmed = False
            if label == 'control' and (status >= 300 or payload not in body):
                confirmed = False
            probes.append(self.probe_entry(label, status, payload, expected, evaluated, body))
        return self.finding('confirmed' if confirmed else 'inconclusive',
                            url, parameter, probes, allowed_origin=context.allowed_origin)
