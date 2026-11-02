import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from autorecon.proof import discover_get_inputs, run_entries, session_from_headers, verify_ssti, write_summary


class Response:
    status_code = 200
    headers = {'Content-Type': 'text/html'}

    def __init__(self, text):
        self.text = text


class FakeSession:
    def __init__(self, evaluate=False):
        self.evaluate = evaluate
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        value = parse_qs(urlsplit(url).query)['q'][0]
        if self.evaluate:
            value = re.sub(r'\{\{(\d+)\*(\d+)\}\}',
                           lambda match: str(int(match[1]) * int(match[2])), value)
        return Response('<p>' + value + '</p>')


class CrawlSession:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        if url == 'http://example.test:80/':
            return Response('<a href="/examples/">Examples</a>'
                            '<a href="https://elsewhere.test/?q=x">External</a>'
                            '<a href="/logout?q=x">Logout</a>')
        if url == 'http://example.test:80/examples/':
            return Response('<a href="/search?q=hello">Search</a>'
                            '<form action="/lookup" method="GET">'
                            '<input name="q" type="search"><input name="token" type="hidden" value="keep">'
                            '</form><form action="/change" method="POST">'
                            '<input name="q" type="text"></form>')
        raise AssertionError('Unexpected crawler request: ' + url)


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.url = 'http://example.test/search?q=old&token=private'
        self.scope = 'http://example.test:80'

    def test_two_arithmetic_probes_confirm_evaluation(self):
        client = FakeSession(evaluate=True)
        result = verify_ssti(self.url, 'q', self.scope, session=client)
        self.assertEqual(result['status'], 'confirmed')
        self.assertEqual(len(client.calls), 3)
        self.assertTrue(all(not call[1]['allow_redirects'] for call in client.calls))
        self.assertNotIn('private', json.dumps(result))

    def test_plain_reflection_is_inconclusive(self):
        result = verify_ssti(self.url, 'q', self.scope, session=FakeSession())
        self.assertEqual(result['status'], 'inconclusive')

    def test_scope_validation_precedes_requests_and_output(self):
        client = FakeSession(evaluate=True)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'proof.json'
            entries = [{'url': self.url, 'parameter': 'q'},
                       {'url': 'https://elsewhere.test/?q=x', 'parameter': 'q'}]
            with self.assertRaisesRegex(ValueError, 'out-of-scope'):
                run_entries(entries, self.scope, output, session=client)
            self.assertEqual(client.calls, [])
            self.assertFalse(output.exists())

    def test_evidence_file_contains_retest_material(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'proof.json'
            result = run_entries([{'url': self.url, 'parameter': 'q'}],
                                 self.scope, output, session=FakeSession(evaluate=True))
            saved = json.loads(output.read_text())
            self.assertEqual(saved, result)
            self.assertEqual(saved['findings'][0]['status'], 'confirmed')
            summary = output.with_suffix('.txt')
            write_summary(result, summary)
            self.assertIn('Status: confirmed', summary.read_text())

    def test_authentication_header_file_accepts_cookie_and_rejects_host(self):
        with tempfile.TemporaryDirectory() as directory:
            headers = Path(directory) / 'headers.json'
            headers.write_text('{"Cookie": "session=secret"}')
            session = session_from_headers(headers)
            self.assertEqual(session.headers['Cookie'], 'session=secret')
            with self.assertRaisesRegex(ValueError, 'disallowed'):
                headers.write_text('{"Host": "elsewhere.test"}')
                session_from_headers(headers)

    def test_discovery_is_bounded_to_safe_same_origin_get_inputs(self):
        session = CrawlSession()
        entries = discover_get_inputs(self.scope, session=session)
        self.assertEqual(len(entries), 2)
        self.assertEqual({item['parameter'] for item in entries}, {'q'})
        self.assertTrue(any('/search?q=hello' in item['url'] for item in entries))
        self.assertTrue(any('/lookup?' in item['url'] for item in entries))
        self.assertEqual(session.calls, ['http://example.test:80/',
                                         'http://example.test:80/examples/'])
        self.assertEqual(discover_get_inputs(self.scope, session=CrawlSession(), max_inputs=1)[0]['parameter'], 'q')


if __name__ == '__main__':
    unittest.main()
