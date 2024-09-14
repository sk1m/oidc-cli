package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sk1m/oidc-cli/internal/authctl"
	"github.com/sk1m/oidc-cli/internal/config"
	"github.com/sk1m/oidc-cli/internal/logger"
	"github.com/sk1m/oidc-cli/internal/oidc"
)

var defaultListenAddress = []string{"127.0.0.1:8000", "127.0.0.1:18000"}

const defaultAuthenticationTimeoutSec = 180

var allGrantTypes = strings.Join([]string{
	"auto",
	"device",
	"authcode",
	"password",
	"clientcreds",
}, "|")

type LoginOpts struct {
	ConfigFile string
	LoginUser  string

	IssuerURL    string
	ClientID     string
	ClientSecret string
	ExtraScopes  []string
	UsePKCE      bool
	ForceRefresh bool

	GrantType                   string
	ListenAddress               []string
	AuthenticationTimeoutSec    int
	SkipOpenBrowser             bool
	BrowserCommand              string
	OpenURLAfterAuth            string
	RedirectURLHostname         string
	RedirectURLAuthCodeKeyboard string
	AuthRequestExtraParams      map[string]string
	Username                    string
	Password                    string
}

func (o *LoginOpts) grantOptions() (*authctl.GrantOpts, error) {
	var opts authctl.GrantOpts
	switch {
	case o.GrantType == "device" || (o.GrantType == "auto" && o.Username == ""):
		o.GrantType = "device"
		opts.DeviceOpts = &authctl.DeviceOpts{
			Browser: &authctl.BrowserOpts{
				SkipOpenBrowser: o.SkipOpenBrowser,
				BrowserCommand:  o.BrowserCommand,
			},
		}
	case o.GrantType == "authcode":
		o.GrantType = "authcode"
		opts.AuthCodeOpts = &authctl.AuthCodeOpts{
			Browser: &authctl.BrowserOpts{
				SkipOpenBrowser: o.SkipOpenBrowser,
				BrowserCommand:  o.BrowserCommand,
			},
			BindAddress:            o.ListenAddress,
			AuthenticationTimeout:  time.Duration(o.AuthenticationTimeoutSec) * time.Second,
			OpenURLAfterAuth:       o.OpenURLAfterAuth,
			RedirectURLHostname:    o.RedirectURLHostname,
			AuthRequestExtraParams: o.AuthRequestExtraParams,
		}
	case o.GrantType == "password" || (o.GrantType == "auto" && o.Username != ""):
		o.GrantType = "password"
		opts.PasswordOpts = &authctl.PasswordOpts{
			Username: o.Username,
			Password: o.Password,
		}
	case o.GrantType == "clientcreds" || (o.GrantType == "auto" && o.ClientSecret != ""):
		o.GrantType = "clientcreds"
		opts.ClientCredentialsOpts = &authctl.ClientCredentialsOpts{}
	default:
		return nil, fmt.Errorf("grant-type must be one of (%s)", allGrantTypes)
	}

	return &opts, nil
}

func NewCmdLogin(f *Factory) *cobra.Command {
	opts := &LoginOpts{}

	cmd := &cobra.Command{
		Use:   "login <name>",
		Short: "Login via OpenID Connect provider to using a token later",
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			configFile := cmd.Flags().Lookup("config").Value.String()
			usernames, err := config.UserList(configFile)
			if err != nil {
				f.Logger.Debugf("user list: %s", err)
			}
			return usernames, cobra.ShellCompDirectiveNoFileComp
		},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("name is required")
			} else if len(args) > 1 {
				return fmt.Errorf("only one name is allowed")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ConfigFile = cmd.Flags().Lookup("config").Value.String()
			opts.LoginUser = args[0]
			return loginRun(cmd.Context(), f, opts)
		},
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().
		StringVar(&opts.IssuerURL, "oidc-issuer-url", env("OIDC_ISSUER_URL"), "Issuer URL of the provider (OIDC_ISSUER_URL)")
	cmd.Flags().
		StringVar(&opts.ClientID, "oidc-client-id", env("OIDC_CLIENT_ID"), "Client ID of the provider (OIDC_CLIENT_ID)")
	cmd.Flags().
		StringVar(&opts.ClientSecret, "oidc-client-secret", env("OIDC_CLIENT_SECRET"), "Client secret of the provider (OIDC_CLIENT_SECRET)")
	cmd.Flags().StringSliceVar(&opts.ExtraScopes, "oidc-extra-scopes", nil, "Extra scopes to request to the provider")
	cmd.Flags().BoolVar(&opts.UsePKCE, "oidc-use-pkce", false, "Force PKCE usage")
	cmd.Flags().
		BoolVar(&opts.ForceRefresh, "force-refresh", false, "If set, refresh the token regardless of its expiration time")

	cmd.Flags().
		StringVar(&opts.GrantType, "grant-type", "auto", fmt.Sprintf("Authorization grant type to use. One of (%s)", allGrantTypes))
	cmd.Flags().
		StringSliceVar(&opts.ListenAddress, "listen-address", defaultListenAddress, "[authcode] Address to bind to the local server. If multiple addresses are set, it will try binding in order")
	cmd.Flags().
		BoolVar(&opts.SkipOpenBrowser, "skip-open-browser", false, "[authcode] Do not open the browser automatically")
	cmd.Flags().StringVar(&opts.BrowserCommand, "browser-command", "", "[authcode] Command to open the browser")
	cmd.Flags().
		IntVar(&opts.AuthenticationTimeoutSec, "authentication-timeout-sec", defaultAuthenticationTimeoutSec, "[authcode] Timeout of authentication in seconds")
	cmd.Flags().
		StringVar(&opts.OpenURLAfterAuth, "open-url-after-login", "", "[authcode] If set, open the URL in the browser after authentication")
	cmd.Flags().
		StringVar(&opts.RedirectURLHostname, "oidc-redirect-url-hostname", "localhost", "[authcode] Hostname of the redirect URL")
	cmd.Flags().
		StringToStringVar(&opts.AuthRequestExtraParams, "oidc-auth-request-extra-params", nil, "[authcode] Extra query parameters to send with an authentication request")
	cmd.Flags().
		StringVar(&opts.Username, "username", env("OIDC_USERNAME"), "[password] Username for password grant (OIDC_USERNAME)")
	cmd.Flags().
		StringVar(&opts.Password, "password", env("OIDC_PASSWORD"), "[password] Password for password grant (OIDC_PASSWORD)")

	return cmd
}

func loginRun(ctx context.Context, f *Factory, opts *LoginOpts) error {
	if f.Logger.Level() < logger.InfoLevel {
		f.Logger.Warnf("log may contain your secrets such as token or password")
	}

	var cachedToken *oidc.Token

	userConf, err := config.FindUser(opts.ConfigFile, opts.LoginUser)
	if err != nil {
		if errors.Is(err, config.ErrUserNotFound) {
			f.Logger.Debugf("no user %s: %s", opts.LoginUser, err)
		} else {
			return fmt.Errorf("search user %s in config %s: %w", opts.LoginUser, opts.ConfigFile, err)
		}
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
		if opts.GrantType == "" || opts.GrantType == "auto" {
			opts.GrantType = userConf.GrantType
		}
	}

	grantOpts, err := opts.grantOptions()
	if err != nil {
		return fmt.Errorf("grant opts: %w", err)
	}
	f.Logger.Infof("current grant_type: %s", opts.GrantType)

	ctl := authctl.New(f.Browser, f.Reader, f.Logger, f.Clock)
	authOpts := authctl.AuthenticateOpts{
		OIDCConfig: oidc.Config{
			IssuerURL:    opts.IssuerURL,
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			UsePKCE:      opts.UsePKCE,
			ExtraScopes:  opts.ExtraScopes,
		},
		GrantOpts:          grantOpts,
		CachedToken:        cachedToken,
		CachedTokenReserve: 10 * time.Second,
		ForceRefresh:       opts.ForceRefresh,
	}
	authResult, err := ctl.Authenticate(ctx, authOpts)
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}

	tokenClaims, err := authResult.Token.DecodeWithoutVerify()
	if err != nil {
		return fmt.Errorf("you got an invalid token: %w", err)
	}

	if authResult.AlreadyHasValidToken {
		f.Logger.Printf("you already have a valid token until %s", tokenClaims.Expiry)
	} else {
		f.Logger.Printf("you got a valid token until %s", tokenClaims.Expiry)

		if userConf == nil {
			userConf = &config.User{
				Name:        opts.LoginUser,
				IssuerURL:   opts.IssuerURL,
				ClientID:    opts.ClientID,
				ExtraScopes: opts.ExtraScopes,
				GrantType:   opts.GrantType,
			}
		}
		userConf.IDToken = authResult.Token.IDToken
		userConf.AccessToken = authResult.Token.AccessToken
		userConf.RefreshToken = authResult.Token.RefreshToken

		if err := config.SaveUser(opts.ConfigFile, userConf); err != nil {
			return fmt.Errorf("save user config: %w", err)
		}
	}

	return nil
}
