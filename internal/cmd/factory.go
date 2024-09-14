package cmd

import (
	"github.com/sk1m/oidc-cli/internal/browser"
	"github.com/sk1m/oidc-cli/internal/clock"
	"github.com/sk1m/oidc-cli/internal/ioreader"
	"github.com/sk1m/oidc-cli/internal/logger"
	"github.com/sk1m/oidc-cli/internal/tokencache"
)

type Factory struct {
	Browser        browser.Opener
	Reader         ioreader.Reader
	TokenCacheRepo tokencache.Repo
	Logger         logger.LogWriter
	Clock          clock.Clock
}

func NewFactory() *Factory {
	return &Factory{
		Browser:        browser.New(),
		Reader:         ioreader.New(),
		TokenCacheRepo: tokencache.NewRepository(),
		Logger:         logger.New(),
		Clock:          clock.New(),
	}
}
