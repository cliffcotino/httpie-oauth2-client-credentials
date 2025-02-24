# httpie-oauth2-client-credentials-flow

As an auth plugin for httpie, it obtains a token with the OAuth2.0 client_credentials flow before executing http, and adds the `Authorization: Bearer ${token}` header to the executed request.

**This implementation builds upon the work done by [satodoc](https://github.com/satodoc/httpie-auth-plugin-for-oauth2-client-credentials) and [totycro](https://github.com/totycro/httpie-oauth2-client-credentials)**

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
The `${CLIENT_SECRET}` value can also contain a key in JWK format (or a reference to a file with a JWK if the value starts with a `@`-character).

Private key example:
```text
-----BEGIN PRIVATE KEY-----
....
-----END PRIVATE KEY-----
```

Private JWK example:
```json
{
  "p": "4Rbv6bQKVPdT5DOjvM8jaD95uQ3TIOYawN5aNemrt6tUBWZHFYA-XhL-bPo-i6BFMc0bOGaAuEEGXLXO6iiCV8Cuel7y1zULoWM4-Yv4xwbwG00nNQKajftbBkC0AfSdWw5H-3cCT35C8FdrbB-uB6q5h7JRcM28NzjXMDZZ9u0",
  "kty": "RSA",
  "q": "8kGdDO2zS9SbInE7DHCGzW9GNTXB4zLlerL0KmkJ1OM9eIrxkycsqZsXJK9-h-S93HCD7gAITCYefMsyGVBc76VmzyQ5GCGHZoYNVInsGi5_yZP_5CijPO_xAG_ptwThxZznMGCLQllpcaXgE0Y6Z86tUWRoz1PUepjoxFBLJBE",
  "d": "Ho5rZceJdzgU1B0o88w-ghIlOS-D8IJuzsGP_aysevFL5Gst_EcrmU_-V0PrsHWOqiWyny6bEjhkqPI8TbzLQ8SMFK9fRFY9ttFKeQHpGlhCCc1y0p4pMXP4tNtQHag83UPCZHwA7HW4xD6tFbE7Z4j7Qz_8r3f4q-JNKbfymKXmmVWlQIc6Yyb0FOismh-JuM_PDwpMCjzMsgT4arR4XSeX7Uek47IKdqeB6qSoRiwBBY-9jmA0oFE5twPYz8JRy_FKyzGqXDpNo26IL2eJyFXnv4HBBJuBnAm__9XY04qMAgTBHjWOcJSQV7U-P_pW6APLACVXXfxhe0w7tP8IIQ",
  "e": "AQAB",
  "qi": "BamCvtzPOnm0GR6LmJxQrjuH4VxdCXBGuElNNe8N5LhqalKyJaYufKF8IaFbyc53SHYkg-GVW4DkfQl60T15OwQCuwPjrSzM-6kXtviHYXN8_NNLN8doMkf_uZ1ImSVTUms9AhzK96FEOGULkVVJafmJQR6ZLI3E_wA5Gn5mJrU",
  "dp": "X5xcoErHsLu2ONLulD7wbVG5JLAIpIrZhl9stkXhmQz_jaOaQjnNRCyRQj0x4CFeAv96toRj3OBSEYNwtuoqI5hHBNfcEyoHHLCG_QlFzVTXHOGy68OFXxYL3iYR0FrVlF4GmXw90QJy8KBRkwYJ6FvOnyNRkLbzYgmU7nfH0yk",
  "dq": "uUSEnwaKQEvv-H8v8Wt9LE8VGkxqYx7hcNy67lQ2OKEwuadI6IjlFzCMmnm8AqFksdk6jCFqNxJP7pBXWBSlfoC4B2JkZ5f8vON3_lccQUmeYMLWx95sOIYngXYU_uq03zQHem_bEHrgsRFyNEtZD1p4Ie7wWN57eObH3JqrXIE",
  "n": "1QFftEW97yHqd3TUsKT3QRVJu8FZDi7l7sYP2qixM07ruEBvvGSVSU4LY5mIjby--yY84eBkqdgh6QPqDVhfwUH1tqfQuKiNn41z21v4p6m_KvDdG2EHIyT3-eas9lRYNe6JU3TJIZQDYCWBF6hZqTq-GMkr1q7mcOTCChP3yvoqyXAhJ9wtcseCJ3iJ9huQDcu7NEZrb2_tVO3G9OLcc8XsynmzmI_4rohii9Ct68HVCGwHifDiixw-9Ge0pSM7bMHAvLvtUf2XNsLpSwZ4_0vDNSSNknTJ96DSB63K4AUO5zEpqaKG6dlrKN1hLdupXE_vRAUT_LB4hPDRqiG5vQ"
}
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
