"""
OAuth2.0 client credentials flow plugin for HTTPie.
"""
import json
import sys
import uuid
from base64 import b64encode
from datetime import datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import jwt
from httpie.cli.definition import parser as httpie_args_parser
from httpie.plugins import AuthPlugin


class OAuth2ClientCredentials:

    def __init__(self, client_id, client_secret):
        if not client_id:
            raise ValueError('client_id is required.')
        self.client_id = client_id
        if not client_secret:
            raise ValueError('client_secret is required.')
        self.client_secret = client_secret
        options = httpie_args_parser.args
        if not options.token_endpoint:
            raise ValueError('token_endpoint is required.')
        self.token_endpoint = options.token_endpoint
        self.token_request_type = options.token_request_type
        self.token_assertion_algorithm = options.token_assertion_algorithm
        if self.token_request_type == 'private-key-jwt' and not self.token_assertion_algorithm:
            raise ValueError(f'token_assertion_algorithm required when token_request_type={self.token_request_type}')
        self.token_assertion_headers = options.token_assertion_headers
        self.scope = options.scope
        self.print_token_request = options.print_token_request
        self.print_token_response = options.print_token_response

    def __call__(self, request):
        token_response = self.__get_token()
        token_type = token_response.get('token_type', 'Bearer')
        token = token_response.get('access_token', '')
        request.headers['Authorization'] = '%s %s' % (token_type, token)
        return request

    def __get_token(self):
        req_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        post_params = {'grant_type': 'client_credentials'}
        if self.scope:
            post_params['scope'] = self.scope

        post_data = None
        if self.token_request_type == 'basic':
            credentials = u'%s:%s' % (self.client_id, self.client_secret)
            token = b64encode(credentials.encode('utf8')).strip().decode('latin1')
            req_headers['Authorization'] = 'Basic %s' % token
            post_data = urlencode(post_params).encode()
        elif self.token_request_type == 'form':
            post_params['client_id'] = self.client_id
            post_params['client_secret'] = self.client_secret
            post_data = urlencode(post_params).encode()
        elif self.token_request_type == 'json':
            req_headers = {'Content-Type': 'application/json'}
            post_params['client_id'] = self.client_id
            post_params['client_secret'] = self.client_secret
            post_data = json.dumps(post_params).encode('utf8')
        elif self.token_request_type == 'private-key-jwt':
            post_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            post_params['client_assertion'] = self.__create_client_assertion()
            post_data = urlencode(post_params).encode()
        else:
            raise ValueError('token-request-type is invalid value.')

        # Execute token request.
        try:
            if self.print_token_request:
                sys.stdout.write(f'token_request: \n========== \nheaders:\n{req_headers}\n\ndata:\n{post_data.decode('utf8')}\n==========\n')
            res = urlopen(Request(self.token_endpoint, method='POST', headers=req_headers, data=post_data))
            res_body = json.loads(res.read())
            if self.print_token_response:
                sys.stdout.write(f'token_response: \n========== \n{json.dumps(res_body, indent=2)}\n==========\n')
            return res_body
        except HTTPError as e:
            if self.print_token_response:
                sys.stderr.write(f'oauth2 error response:\nstatus={e.status}\n')
                res_body = e.read()
                try:
                    res_body = json.loads(res_body)
                    sys.stderr.write(f'token_error_response: \n========== \n{json.dumps(res_body, indent=2)}\n==========\n')
                except:
                    sys.stderr.write(f'error_response: \n========== \n{res_body}\n==========\n')
            raise e

    def __create_client_assertion(self):
        now = datetime.now()
        expiration_time = now + timedelta(seconds=600)  # Token is valid for 10 minutes

        payload = {
            'iss': self.client_id,
            'sub': self.client_id,
            'jti': str(uuid.uuid4()),
            'aud': self.token_endpoint,
            'exp': int(expiration_time.timestamp()),
            'iat': int(now.timestamp()),
        }

        algorithm = self.token_assertion_algorithm

        key = self.client_secret
        if self.client_secret.startswith('@'):
            key_path = Path(self.client_secret[1:])
            if not key_path.is_file():
                raise ValueError(f'client_secret "{self.client_secret}" is not a file')
            key = key_path.read_bytes()

        headers = {}
        extra_headers = self.token_assertion_headers
        if extra_headers:
            headers = dict(item.split(':') for item in extra_headers.split(';'))

        return jwt.encode(payload, algorithm=algorithm, key=key, headers=headers)


class OAuth2ClientCredentialsPlugin(AuthPlugin):

    name = 'OAuth2.0 client credentials flow.'
    auth_type = 'oauth2-client-credentials-flow'
    netrc_parse = True
    description = 'Set the Bearer token obtained in the OAuth2.0 client_credentials flow to the Authorization header.'

    params = httpie_args_parser.add_argument_group(title='OAuth2.0 client credentials flow options')
    params.add_argument(
        '--token-endpoint',
        default=None,
        metavar='TOKEN_ENDPOINT_URL',
        help='OAuth 2.0 Token endpoint URI'
    )
    params.add_argument(
        '--token-request-type',
        default='basic',
        choices=('basic', 'form', 'json', 'private-key-jwt'),
        help='OAuth 2.0 Token request types.'
    )
    params.add_argument(
        '--token-assertion-algorithm',
        default='RS256',
        choices=(
            # for ECDSA, RSA based algorithms:
            'ES256',
            'ES384',
            'ES512',
            'PS256',
            'PS384',
            'PS512',
            'RS256',
            'RS384',
            'RS512',
            # for HMAC based algorithms:
            'HS256',
            'HS384',
            'HS512',
        ),
        help='OAuth 2.0 Token request algorithm for private-key-jwt.'
    )
    params.add_argument(
        '--token-assertion-headers',
        default=None,
        help='Additional OAuth 2.0 Token assertion headers.'
    )
    params.add_argument(
        '--scope',
        default=None,
        metavar='OAUTH2_SCOPE',
        help='OAuth 2.0 Scopes'
    )
    params.add_argument(
        '--print-token-request',
        dest='print_token_request',
        action='store_true',
        default=False,
        help='Print OAuth2 token request.'
    )
    params.add_argument(
        '--print-token-response',
        dest='print_token_response',
        action='store_true',
        default=False,
        help='Print OAuth2 token response.'
    )

    def get_auth(self, username=None, password=None):
        """Add to authorization header
        Args:
            username str: client_id(client_id)
            password str: client_secret(client_secret)

        Returns:
            requests.models.PreparedRequest:
                Added authorization header at the request object.
        """
        return OAuth2ClientCredentials(username, password)
