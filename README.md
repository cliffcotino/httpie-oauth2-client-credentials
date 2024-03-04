# httpie-oauth2-client-credentials-flow

As an auth plugin for httpie, it obtains a token with the OAuth2.0 client_credentials flow before executing http, and adds the `Authorization: Bearer ${token}` header to the executed request.

**This implementation builds upon the work done by [satodoc](https://github.com/satodoc/httpie-oauth2-client-credentials)**

## Installation

Recommended installation method using [httpie cli plugins](https://httpie.io/docs/cli/httpie-cli-plugins):
```bash
httpie cli plugins install httpie-oauth2-client-credentials-flow
```

Otherwise, to install in the default pip location:
```bash
pip install httpie-oauth2-client-credentials-flow
```

Another option is to install from local source (after cloning the repository):
```bash
httpie cli plugins install .
```

## Development

Create and activate a venv:

```bash
python -m venv venv
source venv/bin/activate
```

Install the dependencies used for testing/development:
```
pip install -e '.[testing]'
```

Run the tests for the project:
```bash
python -m pytest tests --cov=httpie_oauth2_client_credentials_flow --cov-report=html:build/coverage --capture=no
```

## Usage

Since the format of the request to get the token depends on the support of the server, this module supports the following three patterns depending on the `--token-request-type` option.  
The SCOPE parameter is optional in all patterns.

### Basic authentication (application/x-www-form-urlencoded) - default

Set CLIENT_ID and CLIENT_SECRET to Basic authentication to get the token.  
Since this pattern is the default, you can omit the `--token-request-type` option.

Execute command:

```bash
http --auth-type=oauth2-client-credentials-flow \
     --auth="${CLIENT_ID}:${CLIENT_SECRET}" \
     --token-endpoint="${TOKEN_ENDPOINT_URL}" \
     --token-request-type="basic" \
     --scope="${SCOPE}" \
     ${TARGET_ENDPOINT_URL}
```

Token request:

```text
POST ${TOKEN_ENDPOINT_URL} HTTP/1.1
Host: ${TOKEN_ENDPOINT_HOST}
Authorization: Basic ${CLIENT_ID:CLIENT_SECRET base64 strings}
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=${SCOPE}
```

### Form request (application/x-www-form-urlencoded)

Send CLIENT_ID and CLIENT_SECRET as part of the Form data.

Execute command:

```bash
http --auth-type=oauth2-client-credentials-flow \
     --auth="${CLIENT_ID}:${CLIENT_SECRET}" \
     --token-endpoint="${TOKEN_ENDPOINT_URL}" \
     --token-request-type="form" \
     --scope="${SCOPE}" \
     ${TARGET_ENDPOINT_URL}
```

Token request:

```text
POST ${TOKEN_ENDPOINT_URL} HTTP/1.1
Host: ${TOKEN_ENDPOINT_HOST}
Content-Type: application/x-www-form-urlencoded

client_id=${CLIENT_ID}
&client_secret=${CLIENT_SECRET}
&grant_type=client_credentials
&scope=${SCOPE}
```

### JSON request (application/json)

Sends all request properties as JSON format.

Execute command:

```bash
http --auth-type=oauth2-client-credentials-flow \
     --auth="${CLIENT_ID}:${CLIENT_SECRET}" \
     --token-endpoint="${TOKEN_ENDPOINT_URL}" \
     --token-request-type="json" \
     --scope="${SCOPE}" \
     ${TARGET_ENDPOINT_URL}
```

Token request:

```text
POST ${TOKEN_ENDPOINT_URL} HTTP/1.1
Host: ${TOKEN_ENDPOINT_HOST}
Content-Type: application/json

{
    "client_id": "${client_id}",
    "client_secret": "${client_secret}",
    "grant_type": "client_credentials",
    "scope": "${SCOPE}"
}
```

### Private Key JWT request (application/x-www-form-urlencoded)

Sends a request with `client_assertion_type` set to `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` as defined by the [private_key_jwt](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) client authentication method.
The `${CLIENT_SECRET}` value must be a private key in PEM format (or a reference to a certificate in PEM format if the value starts with a `@`-character).

Private key example:
```text
-----BEGIN PRIVATE KEY-----
....
-----END PRIVATE KEY-----
```

The private key is used to generate a signature for the JWT with the following header and payload:

Header:
```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

**Note**: the `alg` value in the header is `RS256` by default, but can be changed using the `--token-assertion-algorithm` parameter.

Payload:
```json
{
  "iss": "${CLIENT_ID}",
  "sub": "${CLIENT_ID}",
  "jti": "${random_uuid}",
  "aud": "${TOKEN_ENDPOINT}",
  "exp": 1708426923,
  "iat": 1708426323
}
```

Execute command:

```bash
http --auth-type=oauth2-client-credentials-flow \
     --auth="${CLIENT_ID}:${CLIENT_SECRET}" \
     --token-endpoint="${TOKEN_ENDPOINT_URL}" \
     --token-request-type="private-key-jwt" \
     --token-request-algorithm="RS256" \
     --scope="${SCOPE}" \
     ${TARGET_ENDPOINT_URL}
```

Token request:

```text
POST ${TOKEN_ENDPOINT_URL} HTTP/1.1
Host: ${TOKEN_ENDPOINT_HOST}
Content-Type: application/x-www-form-urlencoded

client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=JWT signed using private key ${CLIENT_SECRET}
&grant_type=client_credentials
&scope=${SCOPE}
```

### Client assertion additional headers

It's possible to specify additional headers in the `private-key-jwt` client_assertion header.
This could, for instance, be necessary for requesting tokens from [Microsoft Identity Platform](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials).
In case of multiple header claims, use `;` to separate them.

Example parameter value:
```bash
  --token-assertion-headers="x5t:hOBcHZi846VCHSJbFAs26Go9VTQ;kid:XYZ"
```

## Supported .netrc

Supported `.netrc`.  
Please check the [httpie documentation](https://httpie.io/docs/cli/netrc) for usage instructions.

### Important Notes before Use

The value for "machine" in the ".netrc" file is the TARGET_ENDPOINT host, not the TOKEN_ENDPOINT host.
It should be TOKEN_ENDPOINT, but the main body of httpie is designed to extract authentication information from the TARGET_ENDPOINT host.

```bash
# Create(or add) .netrc file.
cat <<EOF>> ~/.netrc

machine   {TARGET_ENDPOINT_HOST}
login     {Your Client ID}
password  {Your Client Secret}
EOF

# Change permission.
chmod 600 ~/.netrc
# Example request.
http --auth-type=oauth2-client-credentials-flow \
     --token-endpoint="${TOKEN_ENDPOINT_URL}" \
     --token-request-type="form" \
     --scope="${SCOPE}" \
     ${TARGET_ENDPOINT_URL}
```

## Options

- `--print-token-request`  
  Output the token acquisition request to the console
- `--print-token-response`  
  Output the token acquisition response to the console

## Note

### Token response

The token response must be JSON in the following format.  
The format to be given to the Authorization header of the target endpoint is `${token_type} ${access_token}`.  
If `token_type` is not included in the response, the default value of the Prefix is `Bearer`.

```json
{
    "token_type":"Bearer",
    "access_token": "xxxxxxxxxxxx",
    "expires_in": 3599
}
```

### Caution

This plugin does not have a function to cache the token until "expires_in", so it will send a token request every time you execute the http command.
