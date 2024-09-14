package oidc

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

var noopMiddleware = func(h http.Handler) http.Handler { return h }

// DefaultLocalServerSuccessHTML is a default response body on authorization success.
const DefaultLocalServerSuccessHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Authorized</title>
	<script>
		window.close()
	</script>
	<style>
		body {
			background-color: #eee;
			margin: 0;
			padding: 0;
			font-family: sans-serif;
		}
		.placeholder {
			margin: 2em;
			padding: 2em;
			background-color: #fff;
			border-radius: 1em;
		}
	</style>
</head>
<body>
	<div class="placeholder">
		<h1>Authenticated</h1>
		<p>You can close this window.</p>
	</div>
</body>
</html>
`

type AuthCodeFlowOpts struct {
	OAuth2Config oauth2.Config

	// Hostname of the redirect URL.
	// You can set this if your provider does not accept localhost.
	// Default to localhost.
	RedirectURLHostname string
	// Options for an authorization request.
	// You can set oauth2.AccessTypeOffline and the PKCE options here.
	AuthCodeOptions []oauth2.AuthCodeOption
	// Options for a token request.
	// You can set the PKCE options here.
	TokenRequestOptions []oauth2.AuthCodeOption
	// State parameter in the authorization request.
	// Default to a string of random 32 bytes.
	State string

	// Candidates of hostname and port which the local server binds to.
	// You can set port number to 0 to allocate a free port.
	// If multiple addresses are given, it will try the ports in order.
	// If nil or an empty slice is given, it defaults to "127.0.0.1:0" i.e. a free port.
	LocalServerBindAddress []string

	// Response HTML body on authorization completed.
	// Default to DefaultLocalServerSuccessHTML.
	LocalServerSuccessHTML string
	// Middleware for the local server. Default to none.
	LocalServerMiddleware func(h http.Handler) http.Handler
	// A channel to send its URL when the local server is ready. Default to none.
	LocalServerReadyChan chan<- string

	// Redirect URL upon successful login
	SuccessRedirectURL string
	// Redirect URL upon failed login
	FailureRedirectURL string

	Logf func(string, ...any)
}

func (o *AuthCodeFlowOpts) validateAndSetDefaults() error {
	if o.RedirectURLHostname == "" {
		o.RedirectURLHostname = "localhost"
	}
	if o.State == "" {
		s, err := NewState()
		if err != nil {
			return fmt.Errorf("could not generate a state parameter: %w", err)
		}
		o.State = s
	}
	if o.LocalServerMiddleware == nil {
		o.LocalServerMiddleware = noopMiddleware
	}
	if o.LocalServerSuccessHTML == "" {
		o.LocalServerSuccessHTML = DefaultLocalServerSuccessHTML
	}
	if (o.SuccessRedirectURL != "" && o.FailureRedirectURL == "") ||
		(o.SuccessRedirectURL == "" && o.FailureRedirectURL != "") {
		return fmt.Errorf("when using success and failure redirect URLs, set both URLs")
	}
	if o.Logf == nil {
		o.Logf = func(string, ...interface{}) {}
	}
	return nil
}

// authCodeFlow performs the Authorization Code Grant Flow and returns a token received from the provider.
// See https://tools.ietf.org/html/rfc6749#section-4.1
//
// This performs the following steps:
//
//  1. Start a local server at the port.
//  2. Open a browser and navigate it to the local server.
//  3. Wait for the user authorization.
//  4. Receive a code via an authorization response (HTTP redirect).
//  5. Exchange the code and a token.
//  6. Return the code.
func authCodeFlow(ctx context.Context, opts AuthCodeFlowOpts) (*oauth2.Token, error) {
	if err := opts.validateAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	code, err := receiveCodeViaLocalServer(ctx, &opts)
	if err != nil {
		return nil, fmt.Errorf("authorization error: %w", err)
	}

	opts.Logf("oidc.flow: exchanging the code and token")
	token, err := opts.OAuth2Config.Exchange(ctx, code, opts.TokenRequestOptions...)
	if err != nil {
		return nil, fmt.Errorf("could not exchange the code and token: %w", err)
	}

	return token, nil
}
