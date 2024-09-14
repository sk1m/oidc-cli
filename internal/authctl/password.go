package authctl

import (
	"context"
	"fmt"

	"github.com/sk1m/oidc-cli/internal/oidc"
)

const (
	usernamePrompt = "Username: "
	passwordPrompt = "Password: "
)

type PasswordOpts struct {
	Username string
	Password string // If empty, read a password using Reader.ReadPassword()
}

func (s *Service) passwordAuth(
	ctx context.Context,
	oidcClient oidc.Client,
	opts *PasswordOpts,
) (*oidc.Token, error) {
	s.logger.Debugf("starting the resource owner password credentials flow")

	if opts.Username == "" {
		var err error
		opts.Username, err = s.reader.ReadString(usernamePrompt)
		if err != nil {
			return nil, fmt.Errorf("could not read a username: %w", err)
		}
	}

	if opts.Password == "" {
		var err error
		opts.Password, err = s.reader.ReadPassword(passwordPrompt)
		if err != nil {
			return nil, fmt.Errorf("could not read a password: %w", err)
		}
	}

	token, err := oidcClient.GetTokenByPassword(ctx, opts.Username, opts.Password)
	if err != nil {
		return nil, fmt.Errorf("resource owner password credentials flow error: %w", err)
	}

	s.logger.Debugf("finished the resource owner password credentials flow")

	return token, nil
}
