"""ChatGPT plan authorization for the optional, local AI report command.

This uses OpenAI's documented open-source Sign in with ChatGPT flow. Tokens
belong to this application; no browser cookies or Codex credentials are read.
"""

import base64
import fcntl
import hashlib
import json
import os
import secrets
import tempfile
import time
import uuid
import webbrowser
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import platformdirs
import requests


AUTH_BASE = 'https://auth.openai.com'
RESOURCE = 'https://api.openai.com/v1'
SCOPES = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct'
CALLBACK_PATH = '/auth/callback'
CONFIG_DIR = Path(platformdirs.user_config_dir('AutoRecon')) / 'ai'
SESSION_FILE = CONFIG_DIR / 'chatgpt-session.json'
HOST_FILE = CONFIG_DIR / 'chatgpt-host.json'
LOCK_FILE = CONFIG_DIR / '.session.lock'


class ChatGPTAuthError(RuntimeError):
	pass


def _save_private(path, data):
	path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
	os.chmod(path.parent, 0o700)
	fd, name = tempfile.mkstemp(prefix='.chatgpt-', dir=str(path.parent))
	try:
		with os.fdopen(fd, 'w', encoding='utf8') as handle:
			json.dump(data, handle)
			handle.flush()
			os.fsync(handle.fileno())
		os.chmod(name, 0o600)
		os.replace(name, path)
	finally:
		if os.path.exists(name):
			os.unlink(name)


def _load(path):
	try:
		with path.open(encoding='utf8') as handle:
			return json.load(handle)
	except FileNotFoundError:
		return None
	except (OSError, ValueError) as exc:
		raise ChatGPTAuthError('Could not read saved ChatGPT connection: ' + str(exc)) from exc


@contextmanager
def _session_lock():
	CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
	os.chmod(CONFIG_DIR, 0o700)
	fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
	try:
		fcntl.flock(fd, fcntl.LOCK_EX)
		yield
	finally:
		fcntl.flock(fd, fcntl.LOCK_UN)
		os.close(fd)


def session():
	return _load(SESSION_FILE)


def _host_id():
	host = _load(HOST_FILE)
	if host and host.get('host_id'):
		return host['host_id']
	host_id = 'urn:uuid:' + str(uuid.uuid4())
	_save_private(HOST_FILE, {'host_id': host_id})
	return host_id


def _oidc_metadata():
	response = requests.get(AUTH_BASE + '/.well-known/openid-configuration', timeout=15)
	response.raise_for_status()
	metadata = response.json()
	if metadata.get('issuer') != AUTH_BASE or not metadata.get('jwks_uri', '').startswith(AUTH_BASE + '/'):
		raise ChatGPTAuthError('Unexpected OpenAI identity-provider metadata.')
	return metadata


def _verify_id_token(token, client_id, nonce):
	metadata = _oidc_metadata()
	key = jwt.PyJWKClient(metadata['jwks_uri']).get_signing_key_from_jwt(token)
	claims = jwt.decode(token, key.key, algorithms=['RS256', 'ES256'], audience=client_id, issuer=AUTH_BASE)
	if claims.get('nonce') != nonce or not claims.get('sub'):
		raise ChatGPTAuthError('ChatGPT identity validation failed.')
	return claims


def login(timeout=180):
	previous = session()
	if previous and previous.get('client_id'):
		client_id = previous['client_id']
	else:
		client_id = 'dynamic_agent_client'
		previous = None
	state = secrets.token_urlsafe(32)
	nonce = secrets.token_urlsafe(32)
	verifier = secrets.token_urlsafe(48)
	challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
	callback = {}

	class Callback(BaseHTTPRequestHandler):
		def do_GET(self):
			parsed = urlparse(self.path)
			if parsed.path != CALLBACK_PATH:
				self.send_error(404)
				return
			if callback:
				self.send_error(409)
				return
			callback.update({key: values[0] for key, values in parse_qs(parsed.query).items()})
			body = b'ChatGPT sign-in received. Return to the AutoRecon terminal.'
			self.send_response(200)
			self.send_header('Content-Type', 'text/plain; charset=utf-8')
			self.send_header('Content-Length', str(len(body)))
			self.end_headers()
			self.wfile.write(body)

		def log_message(self, *args):
			# Callback URLs contain authorization codes and must not enter logs.
			pass

	with HTTPServer(('127.0.0.1', 0), Callback) as server:
		server.timeout = 1
		redirect_uri = 'http://127.0.0.1:' + str(server.server_port) + CALLBACK_PATH
		params = {
			'client_id': client_id,
			'ext_agent_host_id': _host_id(),
			'response_type': 'code',
			'redirect_uri': redirect_uri,
			'scope': SCOPES,
			'resource': RESOURCE,
			'state': state,
			'nonce': nonce,
			'code_challenge_method': 'S256',
			'code_challenge': challenge,
		}
		if not previous:
			params['agent_name_hint'] = 'AutoRecon'
		url = AUTH_BASE + '/api/accounts/authorize?' + urlencode(params)
		print('Opening OpenAI sign-in in your browser. Complete authorization there.')
		if not webbrowser.open(url):
			print('Open this URL in your browser: ' + url)
		deadline = time.monotonic() + timeout
		while not callback and time.monotonic() < deadline:
			server.handle_request()
	if not callback:
		raise ChatGPTAuthError('Sign-in timed out. Run login again.')
	if not secrets.compare_digest(callback.get('state', ''), state):
		raise ChatGPTAuthError('ChatGPT sign-in state did not match.')
	if callback.get('error'):
		raise ChatGPTAuthError('ChatGPT sign-in was declined or failed: ' + callback['error'])
	issued_client = callback.get('client_id', client_id)
	if client_id == 'dynamic_agent_client' and not callback.get('client_id'):
		raise ChatGPTAuthError('OpenAI did not return a registered client ID.')
	if client_id != 'dynamic_agent_client' and issued_client != client_id:
		raise ChatGPTAuthError('OpenAI returned a different client ID for this account.')
	if not callback.get('code'):
		raise ChatGPTAuthError('OpenAI did not return an authorization code.')
	response = requests.post(AUTH_BASE + '/api/accounts/oauth/token', data={
		'grant_type': 'authorization_code', 'client_id': issued_client,
		'code': callback['code'], 'code_verifier': verifier,
		'redirect_uri': redirect_uri, 'resource': RESOURCE,
	}, timeout=20)
	response.raise_for_status()
	tokens = response.json()
	claims = _verify_id_token(tokens['id_token'], issued_client, nonce)
	if previous and claims['sub'] != previous['subject']:
		raise ChatGPTAuthError('The selected ChatGPT account changed during sign-in.')
	scopes = tokens.get('scope', '').split()
	if 'chatgpt.tokens.use.direct' not in scopes:
		raise ChatGPTAuthError('ChatGPT plan usage was not authorized. No connection was saved.')
	if not tokens.get('refresh_token') or not tokens.get('access_token'):
		raise ChatGPTAuthError('OpenAI did not return renewable credentials.')
	record = {
		'client_id': issued_client, 'subject': claims['sub'],
		'email': claims.get('email', ''), 'id_token': tokens['id_token'],
		'access_token': tokens['access_token'], 'refresh_token': tokens['refresh_token'],
		'scopes': scopes, 'expires_at': time.time() + int(tokens.get('expires_in', 3600)),
	}
	with _session_lock():
		_save_private(SESSION_FILE, record)
	return record


def access_token():
	with _session_lock():
		record = session()
		if not record:
			raise ChatGPTAuthError('Not signed in. Run autorecon-ai login first.')
		if 'chatgpt.tokens.use.direct' not in record.get('scopes', []):
			raise ChatGPTAuthError('This connection cannot use your ChatGPT plan. Sign in again.')
		if time.time() < record.get('expires_at', 0) - 120:
			return record['access_token']
		response = requests.post(AUTH_BASE + '/api/accounts/oauth/token', data={
			'grant_type': 'refresh_token', 'client_id': record['client_id'],
			'refresh_token': record['refresh_token'], 'resource': RESOURCE,
		}, timeout=20)
		response.raise_for_status()
		tokens = response.json()
		if not tokens.get('access_token') or not tokens.get('refresh_token'):
			raise ChatGPTAuthError('OpenAI did not return renewed credentials. Sign in again.')
		record.update({
			'access_token': tokens['access_token'], 'refresh_token': tokens['refresh_token'],
			'expires_at': time.time() + int(tokens.get('expires_in', 3600)),
			'scopes': tokens.get('scope', ' '.join(record['scopes'])).split(),
		})
		if 'chatgpt.tokens.use.direct' not in record['scopes']:
			raise ChatGPTAuthError('ChatGPT plan permission was removed. Sign in again.')
		_save_private(SESSION_FILE, record)
		return record['access_token']


def logout():
	with _session_lock():
		record = session()
		if not record:
			return False
		try:
			metadata = _oidc_metadata()
			endpoint = metadata.get('revocation_endpoint', '')
			if not endpoint.startswith(AUTH_BASE + '/'):
				raise ChatGPTAuthError('Unexpected OpenAI revocation endpoint.')
			response = requests.post(endpoint, data={
				'token': record['refresh_token'], 'token_type_hint': 'refresh_token',
				'client_id': record['client_id'],
			}, timeout=20)
			response.raise_for_status()
		except (requests.RequestException, ChatGPTAuthError) as exc:
			print('Remote sign-out could not be confirmed; disconnect AutoRecon in ChatGPT Settings if needed: ' + str(exc))
		SESSION_FILE.unlink(missing_ok=True)
		return True
