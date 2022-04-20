# hca-httpie-auth

As an auth plugin for httpie, it obtains a token with the OAuth2.0 client_credentials flow before executing http, and adds the `Authorization: Bearer ${token}` header to the executed request.  

## Token request patterns

Token request patterns are supported for the following:

## Installation

```bash
pip install httpie-oauth2-client-credentials
```

## Usage

Since the format of the request to get the token depends on the support of the server, this module supports the following three patterns depending on the `--token-request-type` option.  
The SCOPE parameter is optional in all patterns.

### Basic authentication (default)

Set CLIENT_ID and CLIENT_SECRET to Basic authentication to get the token.  
Since this pattern is the default, you can omit the `--token-request-type` option.

Execute command:

```bash
http --auth-type=oauth2-client-credentials \
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
http --auth-type=oauth2-client-credentials \
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
http --auth-type=oauth2-client-credentials \
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

## Options

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
