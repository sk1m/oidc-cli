package authctl

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/sk1m/oidc-cli/internal/oidc"
	"github.com/sk1m/oidc-cli/internal/pkce"
)

type AuthCodeOpts struct {
	Browser *BrowserOpts

	BindAddress            []string
	AuthenticationTimeout  time.Duration
	OpenURLAfterAuth       string
	RedirectURLHostname    string
	AuthRequestExtraParams map[string]string
}

func (s *Service) authCodeFlow(
	ctx context.Context,
	oidcClient oidc.Client,
	opts *AuthCodeOpts,
) (*oidc.Token, error) {
	s.logger.Debugf("starting the authentication code flow using the browser")

	state, err := oidc.NewState()
	if err != nil {
		return nil, fmt.Errorf("could not generate a state: %w", err)
	}

	nonce, err := oidc.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("could not generate a nonce: %w", err)
	}

	pkceParams, err := pkce.New(oidcClient.SupportedPKCEMethods())
	if err != nil {
		return nil, fmt.Errorf("could not generate PKCE parameters: %w", err)
	}

	var successHTML string
	if opts.OpenURLAfterAuth != "" {
		successHTML = browserRedirectHTML(opts.OpenURLAfterAuth)
	}
	in := oidc.GetTokenByAuthCodeOpts{
		BindAddress:            opts.BindAddress,
		State:                  state,
		Nonce:                  nonce,
		PKCEParams:             pkceParams,
		RedirectURLHostname:    opts.RedirectURLHostname,
		AuthRequestExtraParams: opts.AuthRequestExtraParams,
		LocalServerSuccessHTML: successHTML,
	}

	ctx, cancel := context.WithTimeout(ctx, opts.AuthenticationTimeout)
	defer cancel()

	readyChan := make(chan string, 1)
	var out *oidc.Token
	var g errgroup.Group

	g.Go(func() error {
		select {
		case url, ok := <-readyChan:
			if !ok {
				return nil
			}
			s.openURL(ctx, url, opts.Browser)
			return nil
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for the local server: %w", ctx.Err())
		}
	})

	g.Go(func() error {
		defer close(readyChan)

		token, err := oidcClient.GetTokenByAuthCode(ctx, in, readyChan)
		if err != nil {
			return fmt.Errorf("authorization code flow error: %w", err)
		}

		out = token
		s.logger.Debugf("got a token set by the authorization code flow")

		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("authentication error: %w", err)
	}

	s.logger.Debugf("finished the authorization code flow via the browser")

	return out, nil
}
