"""Server-side template expression (SSTI) confirmation via arithmetic probes."""

import secrets

from autorecon.proofmodules.base import ProofModule


class TemplateExpression(ProofModule):
    """Confirm two distinct arithmetic evaluations; never follow redirects."""

    name = 'ssti'
    check_name = 'ssti_arithmetic'
    description = 'Server-side template expression evaluation (arithmetic probes)'
    severity = 'high'
    cwe = 'CWE-94'
    rationale = 'Probes only ask the template engine to multiply two numbers and print the result; no code execution, file access, or state change is requested.'
    max_requests = 3

    def verify(self, url, parameter, context):
        context.check_target(url, parameter)
        nonce = secrets.token_hex(8)
        probes = []
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
            status, body = context.probe(url, parameter, payload)
            evaluated = bool(expected and expected in body and payload not in body)
            if label != 'control' and (not evaluated or status >= 300):
                confirmed = False
            if label == 'control' and (status >= 300 or payload not in body):
                confirmed = False
            probes.append(self.probe_entry(label, status, payload, expected, evaluated, body))
        return self.finding('confirmed' if confirmed else 'inconclusive',
                            url, parameter, probes, allowed_origin=context.allowed_origin)
