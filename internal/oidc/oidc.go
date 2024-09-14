package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/sk1m/oidc-cli/internal/logger"
	"github.com/sk1m/oidc-cli/internal/pkce"
)

type Client interface {
	ClientSecret() string
	SetClientSecret(s string)
	SupportedPKCEMethods() []string
	GetTokenByAuthCode(
		ctx context.Context,
		opts GetTokenByAuthCodeOpts,
		localServerReadyChan chan<- string,
	) (*Token, error)
	GetTokenByPassword(ctx context.Context, username string, password string) (*Token, error)
	DeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error)
	GetTokenByDeviceCode(ctx context.Context, resp *oauth2.DeviceAuthResponse) (*Token, error)
	GetTokenByDeviceCodeManual(ctx context.Context, resp *oauth2.DeviceAuthResponse) (*Token, error)
	GetTokenByClientCredentials(ctx context.Context) (*Token, error)
	Refresh(ctx context.Context, refreshToken string) (*Token, error)
}

type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string   // optional
	ExtraScopes  []string // optional
	UsePKCE      bool     // optional
}

type option struct {
	logger     logger.LogWriter
	httpClient *http.Client
	clock      Clock
}

type Option func(*option)

func WithLogger(l logger.LogWriter) Option {
	return func(o *option) {
		o.logger = l
	}
}

func WithHttpClient(c *http.Client) Option {
	return func(o *option) {
		o.httpClient = c
	}
}

func WithClock(c Clock) Option {
	return func(o *option) {
		o.clock = c
	}
}

type Clock interface {
	Now() time.Time
}

type clock struct{}

var _ Clock = (*clock)(nil)

func (c *clock) Now() time.Time {
	return time.Now()
}

type OIDCClient struct {
	provider   *provider
	logger     logger.LogWriter
	httpClient *http.Client
	clock      Clock
}

var _ Client = (*OIDCClient)(nil)

func NewClient(ctx context.Context, cfg *Config, opts ...Option) (*OIDCClient, error) {
	options := &option{
		logger:     logger.New(),
		clock:      &clock{},
		httpClient: &http.Client{},
	}
	for _, opt := range opts {
		opt(options)
	}

	options.httpClient = &http.Client{
		Transport: &Transport{
			Base:   &http.Transport{},
			Logger: options.logger,
		},
	}

	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("issuerURL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("clientID is required")
	}

	provider, err := newProvider(ctx, cfg, options.httpClient)
	if err != nil {
		return nil, fmt.Errorf("new provider: %w", err)
	}

	client := &OIDCClient{
		provider:   provider,
		logger:     options.logger,
		httpClient: options.httpClient,
		clock:      options.clock,
	}

	return client, nil
}

func (c *OIDCClient) httpContext(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, c.httpClient)
}

func (c *OIDCClient) ClientSecret() string {
	return c.provider.config.ClientSecret
}

func (c *OIDCClient) SetClientSecret(s string) {
	cfg := c.provider.config
	cfg.ClientSecret = s
	c.provider.config = cfg
}

// SupportedPKCEMethods returns the PKCE methods supported by the provider.
// This may return nil if PKCE is not supported.
func (c *OIDCClient) SupportedPKCEMethods() []string {
	return c.provider.supportedPKCEMethods
}

type GetTokenByAuthCodeOpts struct {
	BindAddress            []string
	State                  string
	Nonce                  string
	PKCEParams             pkce.Params
	RedirectURLHostname    string
	AuthRequestExtraParams map[string]string
	LocalServerSuccessHTML string
}

// GetTokenByAuthCode performs the authentication code flow
func (c *OIDCClient) GetTokenByAuthCode(
	ctx context.Context,
	ops GetTokenByAuthCodeOpts,
	localServerReadyChan chan<- string,
) (*Token, error) {
	ctx = c.httpContext(ctx)

	flowOpts := AuthCodeFlowOpts{
		OAuth2Config:           c.provider.config,
		State:                  ops.State,
		AuthCodeOptions:        authorizationRequestOptions(ops.Nonce, ops.PKCEParams, ops.AuthRequestExtraParams),
		TokenRequestOptions:    tokenRequestOptions(ops.PKCEParams),
		LocalServerBindAddress: ops.BindAddress,
		LocalServerReadyChan:   localServerReadyChan,
		RedirectURLHostname:    ops.RedirectURLHostname,
		LocalServerSuccessHTML: ops.LocalServerSuccessHTML,
		Logf:                   c.logger.Debugf,
	}
	token, err := authCodeFlow(ctx, flowOpts)
	if err != nil {
		return nil, fmt.Errorf("authCodeFlow error: %w", err)
	}
	return c.verifyToken(ctx, token, ops.Nonce)
}

// GetTokenByPassword performs the resource owner password credentials flow
func (c *OIDCClient) GetTokenByPassword(ctx context.Context, username string, password string) (*Token, error) {
	ctx = c.httpContext(ctx)
	token, err := c.provider.config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("resource owner password credentials flow error: %w", err)
	}
	return c.verifyToken(ctx, token, "")
}

// DeviceAuth initializes the device authorization code challenge
func (c *OIDCClient) DeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error) {
	ctx = c.httpContext(ctx)
	cfg := c.provider.config

	resp, err := cfg.DeviceAuth(ctx, oauth2.AccessTypeOffline)
	if err != nil {
		return nil, fmt.Errorf("device auth: %w", err)
	}

	return resp, nil
}

// GetTokenByDeviceCode exchanges the device code to a token
func (c *OIDCClient) GetTokenByDeviceCode(ctx context.Context, resp *oauth2.DeviceAuthResponse) (*Token, error) {
	ctx = c.httpContext(ctx)
	cfg := c.provider.config

	token, err := cfg.DeviceAccessToken(ctx, resp)
	if err != nil {
		return nil, fmt.Errorf("device: exchange failed: %w", err)
	}

	return c.verifyToken(ctx, token, "")
}

// GetTokenByDeviceCodeManual manually exchanges the device code to a token
func (c *OIDCClient) GetTokenByDeviceCodeManual(ctx context.Context, resp *oauth2.DeviceAuthResponse) (*Token, error) {
	ctx = c.httpContext(ctx)
	cfg := c.provider.config

	resp.Interval = 1
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	token, err := cfg.DeviceAccessToken(ctx, resp)
	if err != nil {
		return nil, fmt.Errorf("device: manual exchange failed: %w", err)
	}

	return c.verifyToken(ctx, token, "")
}

// GetTokenByClientCredentials performs the client credentials token flow.
func (c *OIDCClient) GetTokenByClientCredentials(ctx context.Context) (*Token, error) {
	ctx = c.httpContext(ctx)
	cfg := c.provider.config

	clientCredsConf := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.Endpoint.TokenURL,
		Scopes:       cfg.Scopes,
	}
	token, err := clientCredsConf.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("clientcreds: exchange failed: %w", err)
	}

	return c.verifyToken(ctx, token, "")
}

// Refresh sends a refresh token request and returns a token set.
func (c *OIDCClient) Refresh(ctx context.Context, refreshToken string) (*Token, error) {
	ctx = c.httpContext(ctx)
	currentToken := &oauth2.Token{
		Expiry:       time.Now(),
		RefreshToken: refreshToken,
	}
	source := c.provider.config.TokenSource(ctx, currentToken)
	token, err := source.Token()
	if err != nil {
		return nil, fmt.Errorf("could not refresh the token: %w", err)
	}
	return c.verifyToken(ctx, token, "")
}

func authorizationRequestOptions(nonce string, pkceParams pkce.Params, extra map[string]string) []oauth2.AuthCodeOption {
	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oidc.Nonce(nonce),
	}
	if !pkceParams.IsZero() {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", pkceParams.CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", pkceParams.CodeChallengeMethod),
		)
	}
	for key, value := range extra {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	return opts
}

func tokenRequestOptions(pkceParams pkce.Params) []oauth2.AuthCodeOption {
	var opts []oauth2.AuthCodeOption
	if !pkceParams.IsZero() {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", pkceParams.CodeVerifier))
	}
	return opts
}

func extractSupportedPKCEMethods(provider *oidc.Provider) ([]string, error) {
	var d struct {
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&d); err != nil {
		return nil, fmt.Errorf("invalid discovery document: %w", err)
	}
	return d.CodeChallengeMethodsSupported, nil
}

func NewState() (string, error) {
	b, err := random32()
	if err != nil {
		return "", fmt.Errorf("could not generate a random: %w", err)
	}
	return base64URLEncode(b), nil
}

func NewNonce() (string, error) {
	b, err := random32()
	if err != nil {
		return "", fmt.Errorf("could not generate a random: %w", err)
	}
	return base64URLEncode(b), nil
}

func random32() ([]byte, error) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}
	return b, nil
}

func base64URLEncode(b []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func unique[T comparable](input []T) []T {
	filtered := make([]T, 0, len(input))
	seen := make(map[T]bool, len(input))
	for _, x := range input {
		if !seen[x] {
			filtered = append(filtered, x)
			seen[x] = true
		}
	}
	return filtered
}
