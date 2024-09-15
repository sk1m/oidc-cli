# oidc-cli
[![Go](https://github.com/sk1m/oidc-cli/actions/workflows/go.yml/badge.svg)](https://github.com/sk1m/oidc-cli/actions/workflows/go.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/sk1m/oidc-cli)](https://goreportcard.com/report/github.com/sk1m/oidc-cli)

This is a simple command line tool to interact with Open ID Connect providers.

Here is an example of authentication with the Keycloak:

<img src="./docs/usage.gif" width="500" />

## Getting Started

### Setup

```sh
brew install sk1m/tools/oidc
```

### Usage

Simple example of login into the OIDC provider via device code flow:

```sh
oidc login {ANYNAME} \
  --oidc-issuer-url {OIDC_URL} \
  --oidc-client-id {OIDC_CLIENT}
```

#### Login

This command needs to login into OpenID Connect provider and use later saved users to receive access/id/refresh tokens.

`oidc` writes the ID, access and refresh tokens to the config (default `~/.config/oidc/config.yaml`).

If the cached token is valid, tool just returns it.
If the cached token has expired, tool will refresh the token using the refresh token.
If the refresh token has expired or empty, tool will refresh token.
If the refresh token is empty, tool ask you to login again.

```
~ ❯❯❯ oidc login -h
Login via OpenID Connect provider to using a token later

Usage:
  oidc login <name> [flags]

Flags:
      --oidc-issuer-url string                          Issuer URL of the provider (OIDC_ISSUER_URL)
      --oidc-client-id string                           Client ID of the provider (OIDC_CLIENT_ID)
      --oidc-client-secret string                       Client secret of the provider (OIDC_CLIENT_SECRET)
      --oidc-extra-scopes strings                       Extra scopes to request to the provider
      --oidc-use-pkce                                   Force PKCE usage
      --force-refresh                                   If set, refresh the token regardless of its expiration time
      --grant-type string                               Authorization grant type to use. One of (auto|device|authcode|password|clientcreds) (default "auto")
      --listen-address strings                          [authcode] Address to bind to the local server. If multiple addresses are set, it will try binding in order (default [127.0.0.1:8000,127.0.0.1:18000])
      --skip-open-browser                               [authcode] Do not open the browser automatically
      --browser-command string                          [authcode] Command to open the browser
      --authentication-timeout-sec int                  [authcode] Timeout of authentication in seconds (default 180)
      --open-url-after-login string                     [authcode] If set, open the URL in the browser after authentication
      --oidc-redirect-url-hostname string               [authcode] Hostname of the redirect URL (default "localhost")
      --oidc-auth-request-extra-params stringToString   [authcode] Extra query parameters to send with an authentication request (default [])
      --username string                                 [password] Username for password grant (OIDC_USERNAME)
      --password string                                 [password] Password for password grant (OIDC_PASSWORD)

Global Flags:
      --config string   Path to the config file (OIDC_CONFIG_FILE) (default "~/.config/oidc/config.yaml")
      --help            Show help for command
  -v, --verbose count   verbose output (-v or -vv)
```

#### Token

```
~ ❯❯❯ oidc token -h
Receive token of logged user or issue a new one by client credentials flow

Usage:
  oidc token [name] [flags]

Flags:
      --token-cache-dir string      Path to a directory for token cache (OIDC_TOKEN_CACHE_DIR). Default is a system tmp directory
      --oidc-issuer-url string      Issuer URL of the provider (OIDC_ISSUER_URL)
      --oidc-client-id string       Client ID of the provider (OIDC_CLIENT_ID)
      --oidc-client-secret string   Client secret of the provider (OIDC_CLIENT_SECRET)
      --oidc-extra-scopes strings   Extra scopes to request to the provider
      --force-refresh               If set, refresh the token regardless of its expiration time
      --return-id-token             If set, id_token will be returned. By default access_token is returned
      --return-refresh-token        If set, refresh_token will be returned. By default access_token is returned

Global Flags:
      --config string   Path to the config file (OIDC_CONFIG_FILE) (default "~/.config/oidc/config.yaml")
      --help            Show help for command
  -v, --verbose count   verbose output (-v or -vv)
```

## Contributions

This is an open source software.<br>
Feel free to open issues and pull requests for improving code and documents.
