"""Out-of-band (blind) callback providers for proof modules.

A provider generates unique callback URLs and reports which of them received
an interaction. The interactsh provider implements the documented wire
protocol of ProjectDiscovery's interactsh (register/poll/deregister with
RSA-2048 + AES-256-CTR) directly, so no external client binary is needed.

Privacy note: public interactsh servers (oast.*) see only random nonce
subdomains — no target data ever leaves your machine beyond the nonce.
"""

import base64
import json
import secrets
import time
import uuid

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DEFAULT_SERVERS = ('oast.pro', 'oast.live', 'oast.site', 'oast.online', 'oast.fun', 'oast.me')
XID_ALPHABET = '0123456789abcdefghijklmnopqrstuv'


class CallbackError(RuntimeError):
    pass


class CallbackProvider(object):
    """Interface: start(), url(nonce), poll(nonce, timeout), close()."""

    name = 'base'
    supports_dns = True

    def start(self):
        raise NotImplementedError

    def url(self, nonce):
        """Return a unique callback URL embedding the nonce."""
        raise NotImplementedError

    def poll(self, nonce=None, timeout=10.0):
        """Wait up to timeout seconds for an interaction matching nonce.

        Returns an interaction dict (protocol, remote-address, ...) or None.
        """
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class InteractshProvider(CallbackProvider):
    """Client for ProjectDiscovery's interactsh OOB interaction servers."""

    name = 'interactsh'

    def __init__(self, server=None, token=None, request_timeout=10):
        self.server = server or secrets.choice(DEFAULT_SERVERS)
        self.token = token
        self.request_timeout = request_timeout
        self.session = requests.Session()
        self.private_key = None
        self.correlation_id = None
        self.secret_key = None
        self.host = None
        self.scheme = None

    def start(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.correlation_id = ''.join(secrets.choice(XID_ALPHABET) for _ in range(20))
        self.secret_key = str(uuid.uuid4())
        public_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        payload = json.dumps({
            'public-key': base64.b64encode(public_pem).decode('ascii'),
            'secret-key': self.secret_key,
            'correlation-id': self.correlation_id,
        }).encode('utf8')
        errors = []
        for scheme in ('https', 'http'):
            base = '{}://{}'.format(scheme, self.server.lstrip('/').replace('https://', '').replace('http://', ''))
            try:
                response = self._post(base + '/register', payload)
                message = response.get('message', '')
                if message != 'registration successful':
                    raise CallbackError('unexpected register response: ' + str(response))
                self.scheme = scheme
                self.host = base.split('://', 1)[1]
                return self
            except (requests.RequestException, CallbackError, ValueError) as exc:
                errors.append(str(exc))
        raise CallbackError('could not register with interactsh server {}: {}'.format(
            self.server, '; '.join(errors)))

    def _post(self, url, payload):
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = self.token
        # Never follow redirects: ISPs block OOB domains by intercepting with
        # a redirect to a warning page, which must surface as a clear error.
        response = self.session.post(url, data=payload, headers=headers,
                                     timeout=self.request_timeout, allow_redirects=False)
        if response.is_redirect or response.is_permanent_redirect:
            raise CallbackError(
                '{} redirected to {} — the network is likely blocking the interactsh '
                'server (ISP security filter). Use a self-hosted interactsh server instead.'.format(
                    url, response.headers.get('Location', '?')))
        if response.status_code != 200:
            raise CallbackError('{} returned HTTP {}'.format(url, response.status_code))
        try:
            return response.json()
        except ValueError:
            raise CallbackError('{} returned a non-JSON response'.format(url))

    def url(self, nonce):
        if not self.host:
            raise CallbackError('provider is not started')
        # Servers correlate interactions by sliding a (correlation+nonce)
        # window over the hostname; too-short payloads never match.
        if len(self.correlation_id) + len(nonce) < 33:
            raise CallbackError('nonce too short: interactsh requires correlation + nonce >= 33 characters')
        return 'http://{}{}.{}'.format(self.correlation_id, nonce, self.host)

    def poll(self, nonce=None, timeout=10.0):
        if not self.host:
            raise CallbackError('provider is not started')
        deadline = time.monotonic() + timeout
        seen = set()
        while True:
            interaction = self._poll_once(nonce, seen)
            if interaction is not None:
                return interaction
            if time.monotonic() >= deadline:
                return None
            time.sleep(1.0)

    def _poll_once(self, nonce, seen):
        url = '{}://{}/poll?id={}&secret={}'.format(self.scheme, self.host,
                                                    self.correlation_id, self.secret_key)
        headers = {}
        if self.token:
            headers['Authorization'] = self.token
        try:
            response = self.session.get(url, headers=headers, timeout=self.request_timeout,
                                        allow_redirects=False)
        except requests.RequestException:
            return None
        if response.status_code != 200:
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        interactions = []
        wrapped = body.get('aes_key') or body.get('aes-key') or ''
        for item in body.get('data') or []:
            interaction = self._decrypt(wrapped, item)
            if interaction is not None:
                interactions.append(interaction)
        # Some servers return plaintext interactions in 'extra' / 'tld-data'.
        for group in ('extra', 'tld-data'):
            for item in body.get(group) or []:
                try:
                    interactions.append(json.loads(item))
                except (ValueError, TypeError):
                    continue
        for interaction in interactions:
            key = (interaction.get('protocol'), interaction.get('full-id'),
                   interaction.get('remote-address'), interaction.get('timestamp'))
            if key in seen:
                continue
            seen.add(key)
            full_id = interaction.get('full-id') or ''
            if nonce is None or (nonce and nonce in full_id):
                return interaction
        return None

    def _decrypt(self, wrapped_key, encrypted):
        try:
            key_plaintext = self.private_key.decrypt(
                base64.b64decode(wrapped_key),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None))
            ciphertext = base64.b64decode(encrypted)
            iv, data = ciphertext[:16], ciphertext[16:]
            decryptor = Cipher(algorithms.AES(key_plaintext), modes.CTR(iv)).decryptor()
            plaintext = decryptor.update(data) + decryptor.finalize()
            return json.loads(plaintext.decode('utf8', 'replace').rstrip(' \t\r\n'))
        except (ValueError, KeyError, TypeError):
            return None

    def close(self):
        if not self.host:
            return
        try:
            self._post('{}://{}/deregister'.format(self.scheme, self.host), json.dumps({
                'correlation-id': self.correlation_id,
                'secret-key': self.secret_key,
            }).encode('utf8'))
        except (requests.RequestException, CallbackError, ValueError):
            pass


def create_provider(spec):
    """Resolve an OOB spec ('interactsh' or a CallbackProvider)."""
    if spec is None or spec == 'none':
        return None
    if isinstance(spec, CallbackProvider):
        return spec
    if spec == 'interactsh':
        return InteractshProvider()
    raise ValueError('Unknown out-of-band provider: ' + str(spec) + '. Choose from: interactsh')
