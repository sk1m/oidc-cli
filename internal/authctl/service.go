package authctl

import (
	"context"
	"fmt"
	"time"

	"github.com/sk1m/oidc-cli/internal/browser"
	"github.com/sk1m/oidc-cli/internal/clock"
	"github.com/sk1m/oidc-cli/internal/ioreader"
	"github.com/sk1m/oidc-cli/internal/logger"
	"github.com/sk1m/oidc-cli/internal/oidc"
)

type Service struct {
	browser browser.Opener
	reader  ioreader.Reader
	logger  logger.LogWriter
	clock   clock.Clock
}

func New(browser browser.Opener, reader ioreader.Reader, logger logger.LogWriter, clock clock.Clock) *Service {
	return &Service{
		browser: browser,
		reader:  reader,
		clock:   clock,
		logger:  logger,
	}
}

type AuthenticateOpts struct {
	OIDCConfig         oidc.Config
	GrantOpts          *GrantOpts
	CachedToken        *oidc.Token // optional
	CachedTokenReserve time.Duration
	ForceRefresh       bool
}

type GrantOpts struct {
	AuthCodeOpts          *AuthCodeOpts
	PasswordOpts          *PasswordOpts
	DeviceOpts            *DeviceOpts
	ClientCredentialsOpts *ClientCredentialsOpts
}

// AuthResult represents an output DTO of the Authentication use-case.
type AuthResult struct {
	AlreadyHasValidToken bool
	Token                oidc.Token
}

// Authenticate provides the internal use-case of authentication.
//
// If the IDToken is not set, it performs the authentication flow.
// If the IDToken is valid, it does nothing.
// If the IDtoken has expired and the RefreshToken is set, it refreshes the token.
// If the RefreshToken has expired, it performs the authentication flow.
//
// The authentication flow is determined as:
//
// If the Username is not set, it performs the authorization code flow.
// Otherwise, it performs the resource owner password credentials flow.
// If the Password is not set, it asks a password by the prompt.
func (s *Service) Authenticate(ctx context.Context, opts AuthenticateOpts) (*AuthResult, error) {
	if opts.CachedToken != nil {
		if opts.ForceRefresh {
			s.logger.Debugf("forcing refresh of the existing token")
		} else {
			s.logger.Debugf("checking expiration of the existing token")
			// Skip verification of the token to reduce time of a discovery request.
			// Here it trusts the signature and claims and checks only expiration,
			// because the token has been verified before caching.
			claims, err := opts.CachedToken.DecodeWithoutVerify()
			if err != nil {
				return nil, fmt.Errorf("invalid token cache (you may need to remove): %w", err)
			}
			if !claims.IsExpired(s.clock) {
				if claims.Expiry.Add(-opts.CachedTokenReserve).After(s.clock.Now()) {
					s.logger.Debugf("token exists and valid until %s", claims.Expiry)
					return &AuthResult{
						AlreadyHasValidToken: true,
						Token:                *opts.CachedToken,
					}, nil
				}
				s.logger.Debugf("token exists, but it'd expire soon: %s", claims.Expiry)
			} else {
				s.logger.Debugf("you have an expired token at %s", claims.Expiry)
			}
		}
	}

	s.logger.Debugf("initializing an OpenID Connect client")
	oidcClient, err := oidc.NewClient(ctx, &opts.OIDCConfig, oidc.WithLogger(s.logger))
	if err != nil {
		return nil, fmt.Errorf("oidc error: %w", err)
	}

	if opts.CachedToken != nil {
		if opts.CachedToken.RefreshToken != "" {
			s.logger.Debugf("refreshing the token")
			token, err := oidcClient.Refresh(ctx, opts.CachedToken.RefreshToken)
			if err == nil {
				return &AuthResult{Token: *token}, nil
			}
			s.logger.Debugf("could not refresh the token: %s", err)
		} else {
			s.logger.Infof("refresh token is empty, you have to authenticate again")
		}
	}

	if o := opts.GrantOpts.AuthCodeOpts; o != nil {
		token, err := s.authCodeFlow(ctx, oidcClient, o)
		if err != nil {
			return nil, fmt.Errorf("authcode-browser error: %w", err)
		}
		return &AuthResult{Token: *token}, nil
	}
	if o := opts.GrantOpts.PasswordOpts; o != nil {
		token, err := s.passwordAuth(ctx, oidcClient, o)
		if err != nil {
			return nil, fmt.Errorf("password error: %w", err)
		}
		return &AuthResult{Token: *token}, nil
	}
	if o := opts.GrantOpts.DeviceOpts; o != nil {
		token, err := s.deviceAuth(ctx, oidcClient, o)
		if err != nil {
			return nil, fmt.Errorf("device error: %w", err)
		}
		return &AuthResult{Token: *token}, nil
	}
	if o := opts.GrantOpts.ClientCredentialsOpts; o != nil {
		token, err := s.clientCredentialsAuth(ctx, oidcClient, o)
		if err != nil {
			return nil, fmt.Errorf("clientcreds error: %w", err)
		}
		return &AuthResult{Token: *token}, nil
	}
	return nil, fmt.Errorf("any authorization grant must be set")
}
