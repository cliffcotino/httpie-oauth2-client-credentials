import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Union

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from httpie.plugins.registry import plugin_manager
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Request, Response

from fixtures import http
from httpie_oauth2_client_credentials import OAuth2ClientCredentialsPlugin

HTTP_OK = '200 OK'
BEARER_TOKEN = 'XYZ'
CLIENT_CREDENTIALS = 'client_credentials'
CLIENT_ID = 'client-id'
CLIENT_SECRET = 'client-secret'
BASIC_AUTH_CREDENTIALS = 'Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ='
APPLICATION_JSON = 'application/json'
APPLICATION_WWW_FORM_URLENCODED = 'application/x-www-form-urlencoded'
SCOPE_ROLES = 'roles'
JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
FIXED_TOKEN_RESPONSE = Response(status=200, response=json.dumps({
    'access_token': BEARER_TOKEN,
    'scope': 'roles',
    'token_type': 'Bearer',
    'expires_in': 3599
}))


def do_test(httpserver: HTTPServer,
            token_request_type: Union[str, None],
            token_assertions: Union[Callable[[Request], None], None] = None,
            token_response: Response = FIXED_TOKEN_RESPONSE,
            client_id: str = CLIENT_ID,
            client_secret: str = CLIENT_SECRET,
            print_token_response: bool = False):
    httpserver.clear()

    auth_ok = {'authenticated': True, 'user': CLIENT_ID}
    auth_headers = {'Authorization': f'Bearer {BEARER_TOKEN}'}

    def token_handler(request: Request):
        if token_assertions:
            token_assertions(request)
        return token_response or FIXED_TOKEN_RESPONSE

    httpserver.expect_request(uri='/token', method='POST').respond_with_handler(token_handler)
    httpserver.expect_request(uri='/api', method='GET', headers=auth_headers).respond_with_json(auth_ok)

    args = [httpserver.url_for('/api'),
            '--auth-type', OAuth2ClientCredentialsPlugin.auth_type,
            '--auth', f'{client_id}:{client_secret}',
            '--token-endpoint', httpserver.url_for('/token'),
            '--scope', 'roles']

    if token_request_type:
        args.append('--token-request-type')
        args.append(token_request_type)

    if print_token_response:
        args.append('--print-token-response')

    plugin_manager.register(OAuth2ClientCredentialsPlugin)
    try:
        return http(*args)
    finally:
        httpserver.check()
        plugin_manager.unregister(OAuth2ClientCredentialsPlugin)


def test_token_request_type_basic_is_default(httpserver: HTTPServer):
    def assertions(request: Request):
        assert request.headers['Content-Type'] == APPLICATION_WWW_FORM_URLENCODED
        assert request.headers['Authorization'] == BASIC_AUTH_CREDENTIALS
        assert request.form['scope'] == SCOPE_ROLES

    r = do_test(httpserver, token_request_type=None, token_assertions=assertions)
    assert HTTP_OK in r.stdout
    assert len(r.stderr) == 0


def test_token_request_type_basic(httpserver: HTTPServer):
    def assertions(request: Request):
        assert request.headers['Content-Type'] == APPLICATION_WWW_FORM_URLENCODED
        assert request.headers['Authorization'] == BASIC_AUTH_CREDENTIALS
        assert request.form['grant_type'] == CLIENT_CREDENTIALS
        assert request.form['scope'] == SCOPE_ROLES

    r = do_test(httpserver, token_request_type='basic', token_assertions=assertions)
    assert HTTP_OK in r.stdout
    assert len(r.stderr) == 0


def test_token_request_type_form(httpserver: HTTPServer):
    def assertions(request: Request):
        assert request.headers['Content-Type'] == APPLICATION_WWW_FORM_URLENCODED
        assert request.form['grant_type'] == CLIENT_CREDENTIALS
        assert request.form['client_id'] == CLIENT_ID
        assert request.form['client_secret'] == CLIENT_SECRET
        assert request.form['scope'] == SCOPE_ROLES

    r = do_test(httpserver, token_request_type='form', token_assertions=assertions)
    assert HTTP_OK in r.stdout
    assert len(r.stderr) == 0


def test_token_request_type_json(httpserver: HTTPServer):
    def assertions(request: Request):
        assert request.headers['Content-Type'] == APPLICATION_JSON
        assert request.json['grant_type'] == CLIENT_CREDENTIALS
        assert request.json['client_id'] == CLIENT_ID
        assert request.json['client_secret'] == CLIENT_SECRET
        assert request.json['scope'] == SCOPE_ROLES

    r = do_test(httpserver, token_request_type='json', token_assertions=assertions)
    assert HTTP_OK in r.stdout
    assert len(r.stderr) == 0


def test_token_request_type_private_key_jwt_when_given_secret(httpserver: HTTPServer):
    def assertions(request: Request):
        assert request.headers['Content-Type'] == APPLICATION_WWW_FORM_URLENCODED
        assert request.form['grant_type'] == CLIENT_CREDENTIALS
        assert request.form['client_assertion_type'] == JWT_BEARER
        verify_client_assertion(request.form['client_assertion'], httpserver.url_for('/token'), key.public_key)

    key = generate_key()
    client_secret = key.private_key_pem.decode('utf8')
    r = do_test(httpserver, token_request_type='private-key-jwt', client_secret=client_secret,
                token_assertions=assertions)
    assert HTTP_OK in r.stdout
    assert len(r.stderr) == 0


def test_token_request_type_private_key_jwt_when_given_secret_file(httpserver: HTTPServer, tmp_path):
    def assertions(request: Request):
        assert request.headers['Content-Type'] == APPLICATION_WWW_FORM_URLENCODED
        assert request.form['grant_type'] == CLIENT_CREDENTIALS
        assert request.form['client_assertion_type'] == JWT_BEARER
        verify_client_assertion(request.form['client_assertion'], httpserver.url_for('/token'), key.public_key)

    key = generate_key()
    private_key_pem_path = Path(tmp_path / 'private_key.pem')
    private_key_pem_path.write_bytes(key.private_key_pem)

    client_secret = f'@{private_key_pem_path}'
    r = do_test(httpserver, token_request_type='private-key-jwt', client_secret=client_secret,
                token_assertions=assertions)
    assert HTTP_OK in r.stdout
    assert len(r.stderr) == 0


@dataclass
class GeneratedKey:
    private_key_pem: bytes
    public_key: RSAPublicKey


def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return GeneratedKey(private_key_pem, public_key)


def verify_client_assertion(client_assertion: str, audience: str, public_key: RSAPublicKey):
    jwt.decode(client_assertion, issuer=CLIENT_ID, audience=audience, algorithms='RS256', verify=True, key=public_key)


def test_token_request_type_private_key_jwt_when_given_missing_file(httpserver: HTTPServer):
    client_secret = '@missing_private_key.pem'
    r = do_test(httpserver, token_request_type='private-key-jwt', client_secret=client_secret)
    assert HTTP_OK not in r.stdout
    assert 'ValueError: file "missing_private_key.pem" is not a file' in r.stderr


def test_token_request_type_form_failure(httpserver: HTTPServer):
    token_response = Response(status=400, response=json.dumps({
        'error': 'invalid_client',
        'error_description': 'Client authentication failed'
    }))

    r = do_test(httpserver, token_request_type='form', token_response=token_response, print_token_response=True)
    assert len(r.stdout) == 0
    assert '400: BAD REQUEST' in r.stderr


def test_when_no_client_id_provided(httpserver: HTTPServer):
    try:
        do_test(httpserver, token_request_type='form', client_id='')
        assert 1 == 0
    except ValueError as e:
        assert 'client_id is required.' in e.args


def test_when_no_client_secret_provided(httpserver: HTTPServer):
    try:
        do_test(httpserver, token_request_type='form', client_secret='')
        assert 1 == 0
    except ValueError as e:
        assert 'client_secret is required.' in e.args
