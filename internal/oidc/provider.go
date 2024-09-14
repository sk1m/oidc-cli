package oidc

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/sk1m/oidc-cli/internal/pkce"
)

type provider struct {
	client               *oidc.Provider
	config               oauth2.Config
	supportedPKCEMethods []string
}

func newProvider(ctx context.Context, cfg *Config, httpClient *http.Client) (*provider, error) {
	ctx = oidc.ClientContext(ctx, httpClient)
	oidcProvider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery error: %w", err)
	}

	supportedPKCEMethods, err := extractSupportedPKCEMethods(oidcProvider)
	if err != nil {
		return nil, fmt.Errorf("could not determine supported PKCE methods: %w", err)
	}
	if len(supportedPKCEMethods) == 0 && cfg.UsePKCE {
		supportedPKCEMethods = []string{pkce.MethodS256}
	}

	p := &provider{
		client: oidcProvider,
		config: oauth2.Config{
			Endpoint:     oidcProvider.Endpoint(),
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       unique(append(cfg.ExtraScopes, oidc.ScopeOpenID)),
		},
		supportedPKCEMethods: supportedPKCEMethods,
	}

	return p, nil
}
