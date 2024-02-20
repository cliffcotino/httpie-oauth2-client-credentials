'''
OAuth2.0 client credentials flow plugin for HTTPie.
'''
import os.path
import sys
import uuid
from base64 import b64encode, urlsafe_b64encode
from datetime import datetime, timedelta
from httpie.plugins import AuthPlugin
from httpie.cli.definition import parser as httpie_args_parser
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import json


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
        self.scope = options.scope
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
            post_data = json.dumps(post_params).encode("utf-8")
        elif self.token_request_type == 'private-key-jwt':
            post_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            post_params['client_assertion'] = self.__create_client_assertion()
            post_data = urlencode(post_params).encode()
        else:
            raise ValueError('token-request-type is invalid value.')

        # Execute token request.
        try:
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

        header = {
            "alg": "RS256",
            "typ": "JWT"
        }

        payload = {
            'iss': self.client_id,
            'sub': self.client_id,
            'jti': str(uuid.uuid4()),
            'aud': self.token_endpoint,
            'exp': int(expiration_time.timestamp()),
            'iat': int(now.timestamp()),
        }

        # Encode header and payload
        encoded_header = urlsafe_b64encode(json.dumps(header).encode('utf-8')).rstrip(b'=')
        encoded_payload = urlsafe_b64encode(json.dumps(payload).encode('utf-8')).rstrip(b'=')

        # Create a signature using client_secret
        signature_input = encoded_header + b'.' + encoded_payload

        if self.token_request_type == 'private-key-jwt':
            if self.client_secret.startswith('@'):
                filename = self.client_secret[1:]
                if not os.path.isfile(filename):
                    raise ValueError('file "' + filename + '" is not a file')
                with open(filename, 'rb') as key_file:
                    certificate = key_file.read()
            else:
                certificate = self.client_secret.encode('ascii')
            private_key = serialization.load_pem_private_key(
                certificate.strip(),
                password=None,
                backend=default_backend()
            )
            # Sign the data
            signature = private_key.sign(
                signature_input,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:
            raise ValueError('token-request-type is invalid value.')

        encoded_signature = urlsafe_b64encode(signature).rstrip(b'=')

        # Combine all parts to create the final JWT
        jwt_token = encoded_header + b'.' + encoded_payload + b'.' + encoded_signature

        return jwt_token.decode('utf-8')

class OAuth2ClientCredentialsPlugin(AuthPlugin):

    name = 'OAuth2.0 client credentials flow.'
    auth_type = 'oauth2-client-credentials'
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
        '--scope',
        default=None,
        metavar='OAUTH2_SCOPE',
        help='OAuth 2.0 Scopes'
    )
    params.add_argument(
        '--print-token-response',
        dest='print_token_response',
        action='store_true',
        default=False,
        help='print oauth2 token response.'
    )

    def get_auth(self, username=None, password=None):
        '''Add to authorization header
        Args:
            username str: client_id(client_id)
            password str: client_secret(client_secret)

        Returns:
            requests.models.PreparedRequest:
                Added authorization header at the request object.
        '''
        return OAuth2ClientCredentials(username, password)
