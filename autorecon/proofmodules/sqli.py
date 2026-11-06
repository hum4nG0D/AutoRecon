"""SQL injection confirmation via dual-duration time-based probes.

Two requests carry SLEEP() with different durations. A randomly slow server
cannot satisfy both the absolute thresholds and the ordering
slow > fast > control, so a confirmed finding requires the delays to track
the requested durations. MySQL/MariaDB syntax; no stacked queries, no data
access — SLEEP only delays the response.
"""

import secrets

from autorecon.proofmodules.base import ProofModule


class SQLInjection(ProofModule):
    name = 'sqli'
    check_name = 'sql_injection'
    description = 'SQL injection (dual-duration time-based confirmation, MySQL/MariaDB syntax)'
    severity = 'critical'
    cwe = 'CWE-89'
    rationale = 'Probes only append AND SLEEP(n), which delays the query without reading or modifying any data; no stacked queries are used.'
    max_requests = 3

    SLOW_SLEEP = 5
    FAST_SLEEP = 2

    def verify(self, url, parameter, context):
        context.check_target(url, parameter)
        nonce = secrets.token_hex(8)
        probes = []
        delays = {}
        cases = [
            ('control', 'ar' + nonce + 'control', None),
            ('probe-slow', "' AND SLEEP({:g})-- -".format(self.SLOW_SLEEP),
             'delay>={:.2f}s'.format(self.SLOW_SLEEP * 0.8)),
            ('probe-fast', "' AND SLEEP({:g})-- -".format(self.FAST_SLEEP),
             'delay>={:.2f}s'.format(self.FAST_SLEEP * 0.75)),
        ]
        confirmed = True
        for label, payload, expected in cases:
            status, body, elapsed = context.probe_timed(url, parameter, payload)
            delays[label] = elapsed
            if label == 'control':
                evaluated = status < 300
                if not evaluated:
                    confirmed = False
            else:
                needed = self.SLOW_SLEEP * 0.8 if label == 'probe-slow' else self.FAST_SLEEP * 0.75
                evaluated = elapsed >= needed
                if not evaluated or status >= 300:
                    confirmed = False
            probes.append(self.probe_entry(label, status, payload, expected, evaluated, body,
                                           delay=round(elapsed, 3)))
        # The delays must track the requested durations and beat the baseline.
        if not (delays['probe-slow'] > delays['probe-fast'] > 0
                and delays['control'] < self.FAST_SLEEP):
            confirmed = False
        return self.finding('confirmed' if confirmed else 'inconclusive',
                            url, parameter, probes, allowed_origin=context.allowed_origin,
                            db_family='mysql')
