package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sk1m/oidc-cli/internal/authctl"
	"github.com/sk1m/oidc-cli/internal/config"
	"github.com/sk1m/oidc-cli/internal/logger"
	"github.com/sk1m/oidc-cli/internal/oidc"
	"github.com/sk1m/oidc-cli/internal/tokencache"
)

type TokenOpts struct {
	ConfigFile    string
	TokenCacheDir string
	LoginUser     string

	IssuerURL          string
	ClientID           string
	ClientSecret       string
	ExtraScopes        []string
	ForceRefresh       bool
	ReturnIDToken      bool
	ReturnRefreshToken bool
}

func (o *TokenOpts) expandHomedir() error {
	if p, err := expandHomedir(o.TokenCacheDir); err != nil {
		return fmt.Errorf("expand tokenCacheDir %s: %w", o.TokenCacheDir, err)
	} else {
		o.TokenCacheDir = p
		if o.TokenCacheDir == "" {
			o.TokenCacheDir = os.TempDir()
		}
	}

	return nil
}

func NewCmdToken(f *Factory) *cobra.Command {
	opts := &TokenOpts{}

	cmd := &cobra.Command{
		Use:   "token [name]",
		Short: "Receive token of logged user or issue a new one by client credentials flow",
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			configFile := cmd.Flags().Lookup("config").Value.String()
			usernames, err := config.UserList(configFile)
			if err != nil {
				f.Logger.Debugf("user list: %s", err)
			}
			return usernames, cobra.ShellCompDirectiveNoFileComp
		},
		Args: func(c *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("only one name is allowed")
			}

			if len(args) > 0 {
				opts.LoginUser = args[0]
			}
			if opts.LoginUser == "" {
				if opts.IssuerURL == "" {
					return errors.New("--oidc-issuer-url is missing")
				}
				if opts.ClientID == "" {
					return errors.New("--oidc-client-id is missing")
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ConfigFile = cmd.Flags().Lookup("config").Value.String()
			return tokenRun(cmd.Context(), f, opts)
		},
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().
		StringVar(&opts.TokenCacheDir, "token-cache-dir", env("OIDC_TOKEN_CACHE_DIR"), "Path to a directory for token cache (OIDC_TOKEN_CACHE_DIR). Default is a system tmp directory")

	cmd.Flags().
		StringVar(&opts.IssuerURL, "oidc-issuer-url", env("OIDC_ISSUER_URL"), "Issuer URL of the provider (OIDC_ISSUER_URL)")
	cmd.Flags().
		StringVar(&opts.ClientID, "oidc-client-id", env("OIDC_CLIENT_ID"), "Client ID of the provider (OIDC_CLIENT_ID)")
	cmd.Flags().
		StringVar(&opts.ClientSecret, "oidc-client-secret", env("OIDC_CLIENT_SECRET"), "Client secret of the provider (OIDC_CLIENT_SECRET)")
	cmd.Flags().StringSliceVar(&opts.ExtraScopes, "oidc-extra-scopes", nil, "Extra scopes to request to the provider")
	cmd.Flags().
		BoolVar(&opts.ForceRefresh, "force-refresh", false, "If set, refresh the token regardless of its expiration time")
	cmd.Flags().
		BoolVar(&opts.ReturnIDToken, "return-id-token", false, "If set, id_token will be returned. By default access_token is returned")
	cmd.Flags().
		BoolVar(&opts.ReturnRefreshToken, "return-refresh-token", false, "If set, refresh_token will be returned. By default access_token is returned")

	return cmd
}

func tokenRun(ctx context.Context, f *Factory, opts *TokenOpts) error {
	if f.Logger.Level() < logger.InfoLevel {
		f.Logger.Warnf("log may contain your secrets such as token or password")
	}
	if err := opts.expandHomedir(); err != nil {
		return fmt.Errorf("expand homedir: %w", err)
	}

	var userConf *config.User
	var cachedToken *oidc.Token
	var tokenCacheKey *tokencache.Key
	grantOpts := &authctl.GrantOpts{}

	var err error
	if opts.LoginUser != "" {
		userConf, err = config.FindUser(opts.ConfigFile, opts.LoginUser)
		if err != nil {
			return fmt.Errorf("%s. check login first", err)
		} else {
			if userConf.AccessToken != "" || userConf.IDToken != "" {
				f.Logger.Debugf("received a token from config")
				cachedToken = &oidc.Token{
					IDToken:      userConf.IDToken,
					AccessToken:  userConf.AccessToken,
					RefreshToken: userConf.RefreshToken,
				}
			} else {
				f.Logger.Debugf("a token in config is empty")
			}
			if opts.IssuerURL == "" {
				opts.IssuerURL = userConf.IssuerURL
			}
			if opts.ClientID == "" {
				opts.ClientID = userConf.ClientID
			}
			if len(opts.ExtraScopes) == 0 {
				opts.ExtraScopes = userConf.ExtraScopes
			}
			if userConf.GrantType == "clientcreds" {
				grantOpts.ClientCredentialsOpts = &authctl.ClientCredentialsOpts{}
			}
		}
	} else {
		f.Logger.Debugf("user not specified, switched to client-credentials flow")
		grantOpts.ClientCredentialsOpts = &authctl.ClientCredentialsOpts{}

		f.Logger.Debugf("finding a token from cache directory %s", opts.TokenCacheDir)
		tokenCacheKey = &tokencache.Key{
			IssuerURL:   opts.IssuerURL,
			ClientID:    opts.ClientID,
			ExtraScopes: opts.ExtraScopes,
		}
		cachedToken, err = f.TokenCacheRepo.FindByKey(opts.TokenCacheDir, tokenCacheKey)
		if err != nil {
			f.Logger.Debugf("could not find a token cache: %s", err)
		}
	}

	ctl := authctl.New(f.Browser, f.Reader, f.Logger, f.Clock)

	authenticationInput := authctl.AuthenticateOpts{
		OIDCConfig: oidc.Config{
			IssuerURL:    opts.IssuerURL,
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			ExtraScopes:  opts.ExtraScopes,
		},
		GrantOpts:          grantOpts,
		CachedToken:        cachedToken,
		CachedTokenReserve: 10 * time.Second,
		ForceRefresh:       opts.ForceRefresh,
	}
	authResult, err := ctl.Authenticate(ctx, authenticationInput)
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}

	if !authResult.AlreadyHasValidToken {
		if userConf != nil {
			userConf.IDToken = authResult.Token.IDToken
			userConf.AccessToken = authResult.Token.AccessToken
			userConf.RefreshToken = authResult.Token.RefreshToken

			f.Logger.Debugf("saving user in config")
			if err := config.SaveUser(opts.ConfigFile, userConf); err != nil {
				return fmt.Errorf("save user config: %w", err)
			}
		} else if tokenCacheKey != nil {
			f.Logger.Debugf("saving token in cache")
			if err := f.TokenCacheRepo.Save(opts.TokenCacheDir, tokenCacheKey, authResult.Token); err != nil {
				f.Logger.Errorf("could not write the token cache: %s", err)
			}
		}
	}

	rToken := authResult.Token.AccessToken
	switch {
	case opts.ReturnIDToken:
		rToken = authResult.Token.IDToken
	case opts.ReturnRefreshToken:
		rToken = authResult.Token.RefreshToken
	}
	if rToken == "" {
		return fmt.Errorf("token is empty")
	}
	fmt.Print(rToken)

	return nil
}
