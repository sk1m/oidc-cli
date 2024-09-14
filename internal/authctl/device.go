package authctl

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/sk1m/oidc-cli/internal/oidc"
)

type DeviceOpts struct {
	Browser *BrowserOpts
}

func (s *Service) deviceAuth(ctx context.Context, oidcClient oidc.Client, opts *DeviceOpts) (*oidc.Token, error) {
	s.logger.Debugf("starting the oauth2 device code flow")

	resp, err := oidcClient.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("authorization error: %w", err)
	}

	if resp.VerificationURIComplete != "" {
		s.openURL(ctx, resp.VerificationURIComplete, opts.Browser)
	} else if resp.VerificationURI != "" {
		s.logger.Printf("Please enter the following code when asked in your browser: %s", resp.UserCode)
		s.openURL(ctx, resp.VerificationURI, opts.Browser)
	} else {
		return nil, fmt.Errorf("no verification URI in the authorization response")
	}

	confirm, err := s.reader.ReadString("Have you completed device login in your browser [Y/n]?")
	if err != nil {
		return nil, fmt.Errorf("could not read a confirm answer: %w", err)
	}

	var token *oidc.Token
	if slices.Contains([]string{"", "y", "yes"}, strings.TrimSpace(strings.ToLower(confirm))) {
		s.logger.Debugf("exchanging a device code for a token")
		token, err = oidcClient.GetTokenByDeviceCodeManual(ctx, resp)
		if err != nil {
			return nil, fmt.Errorf("unable to exchange device code: %w", err)
		}
	} else {
		if resp.Interval > 10 {
			resp.Interval = 10
		}
		s.logger.Infof("polling the server to exchange a device code for a token (interval_secs=%d)...", resp.Interval)
		token, err = oidcClient.GetTokenByDeviceCode(ctx, resp)
		if err != nil {
			return nil, fmt.Errorf("unable to exchange device code: %w", err)
		}
	}

	s.logger.Debugf("finished the oauth2 device code flow")

	return token, nil
}
