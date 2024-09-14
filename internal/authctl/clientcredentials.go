package authctl

import (
	"context"
	"fmt"

	"github.com/sk1m/oidc-cli/internal/oidc"
)

const clientSecretPrompt = "Client secret: "

type ClientCredentialsOpts struct{}

func (s *Service) clientCredentialsAuth(
	ctx context.Context,
	oidcClient oidc.Client,
	_ *ClientCredentialsOpts,
) (*oidc.Token, error) {
	s.logger.Debugf("starting the client credentials flow")

	if oidcClient.ClientSecret() == "" {
		secret, err := s.reader.ReadPassword(clientSecretPrompt)
		if err != nil {
			return nil, fmt.Errorf("could not read a client secret: %w", err)
		}
		oidcClient.SetClientSecret(secret)
	}

	token, err := oidcClient.GetTokenByClientCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("client credentials flow error: %w", err)
	}

	s.logger.Debugf("finished the client credentials flow")

	return token, nil
}
