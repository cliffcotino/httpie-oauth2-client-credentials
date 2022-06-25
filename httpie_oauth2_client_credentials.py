'''
OAuth2.0 client credentials flow plugin for HTTPie.
'''

import sys
from httpie.plugins import AuthPlugin
from httpie.cli.definition import parser as httpie_args_parser
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError
import json
from base64 import b64encode

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

        else:
            post_params['client_id'] = self.client_id
            post_params['client_secret'] = self.client_secret
            if self.token_request_type == 'form':
                post_data = urlencode(post_params).encode()
            elif self.token_request_type == 'json':
                req_headers = {'Content-Type': 'application/json'}
                post_data = json.dumps(post_params).encode("utf-8")
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

class OAuth2ClientCredentialsPlugin(AuthPlugin):

    name = 'OAuth2.0 client credentilas flow.'
    auth_type = 'oauth2-client-credentials'
    description = 'Set the Bearer token obtained in the OAuth2.0 client_credentials flow to the Authorization header.'

    params = httpie_args_parser.add_argument_group(title='OAuth2.0 client credentilas flow options')
    params.add_argument(
        '--token-endpoint',
        default=None,
        metavar='TOKEN_ENDPOINT_URL',
        help='OAuth 2.0 Token endpoint URI'
    )
    params.add_argument(
        '--token-request-type',
        default='basic',
        choices=('basic','form','json'),
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
            password str: client_secret(client_sercret)

        Returns:
            requests.models.PreparedRequest:
                Added authorization header at the request object.
        '''
        return OAuth2ClientCredentials(username, password)
