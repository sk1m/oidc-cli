package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/sk1m/oidc-cli/internal/jwt"
)

// Token represents a set of ID token, access token and refresh token.
type Token struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
}

func (t Token) Username() (string, error) {
	var claims *jwt.Claims
	var err error
	if t.AccessToken != "" {
		claims, err = jwt.DecodeWithoutVerify(t.AccessToken)
		if err != nil {
			return "", fmt.Errorf("decode access_token: %w", err)
		}
	} else {
		claims, err = jwt.DecodeWithoutVerify(t.IDToken)
		if err != nil {
			return "", fmt.Errorf("decode access_token: %w", err)
		}
	}

	switch {
	case claims.ClientID != "":
		return claims.ClientID, nil
	case claims.Username != "":
		return claims.Username, nil
	case claims.Email != "":
		return claims.Email, nil
	default:
		return "", fmt.Errorf("no username fields")
	}
}

func (t Token) DecodeWithoutVerify() (*jwt.Claims, error) {
	if t.AccessToken != "" {
		return jwt.DecodeWithoutVerify(t.AccessToken)
	}
	return jwt.DecodeWithoutVerify(t.IDToken)
}

// verifyToken verifies the token with the certificates of the provider and the nonce.
// If the nonce is an empty string, it does not verify the nonce.
func (c *OIDCClient) verifyToken(ctx context.Context, token *oauth2.Token, nonce string) (*Token, error) {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("id_token is missing in the token response: %#v", token)
	}

	verifyConf := &oidc.Config{
		ClientID: c.provider.config.ClientID,
		Now:      c.clock.Now,
	}
	verifier := c.provider.client.Verifier(verifyConf)
	verifiedIDToken, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify the ID token: %w", err)
	}
	if nonce != "" && nonce != verifiedIDToken.Nonce {
		return nil, fmt.Errorf("nonce did not match (wants %s but got %s)", nonce, verifiedIDToken.Nonce)
	}

	if token.AccessToken != "" {
		verifyConf := &oidc.Config{
			Now:               c.clock.Now,
			SkipClientIDCheck: true,
		}
		verifier = c.provider.client.Verifier(verifyConf)

		_, err := verifier.Verify(ctx, token.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("could not verify the access token: %w", err)
		}
	}

	tokenSet := &Token{
		IDToken:      idToken,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return tokenSet, nil
}
