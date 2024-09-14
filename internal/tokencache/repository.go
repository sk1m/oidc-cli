package tokencache

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sk1m/oidc-cli/internal/oidc"
)

type Repo interface {
	FindByKey(dir string, key *Key) (*oidc.Token, error)
	Save(dir string, key *Key, token oidc.Token) error
}

// Key represents a key of a token cache.
type Key struct {
	IssuerURL   string
	ClientID    string
	Username    string
	ExtraScopes []string
}

type entity struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Repository provides access to the token cache on the local filesystem.
// Filename of a token cache is sha256 digest of the issuer, zero-character and client ID.
type Repository struct{}

var _ Repo = (*Repository)(nil)

func NewRepository() *Repository {
	return &Repository{}
}

func (r *Repository) FindByKey(dir string, key *Key) (*oidc.Token, error) {
	filename, err := computeFilename(key)
	if err != nil {
		return nil, fmt.Errorf("could not compute the key: %w", err)
	}

	p := filepath.Join(dir, filename)
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %w", p, err)
	}
	defer f.Close()

	d := json.NewDecoder(f)
	var e entity
	if err := d.Decode(&e); err != nil {
		return nil, fmt.Errorf("invalid json file %s: %w", p, err)
	}

	return &oidc.Token{
		IDToken:      e.IDToken,
		AccessToken:  e.AccessToken,
		RefreshToken: e.RefreshToken,
	}, nil
}

func (r *Repository) Save(dir string, key *Key, tokenSet oidc.Token) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("could not create directory %s: %w", dir, err)
	}

	filename, err := computeFilename(key)
	if err != nil {
		return fmt.Errorf("could not compute the key: %w", err)
	}

	p := filepath.Join(dir, filename)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("could not create file %s: %w", p, err)
	}
	defer f.Close()

	e := entity{
		IDToken:      tokenSet.IDToken,
		AccessToken:  tokenSet.AccessToken,
		RefreshToken: tokenSet.RefreshToken,
	}
	if err := json.NewEncoder(f).Encode(&e); err != nil {
		return fmt.Errorf("json encode error: %w", err)
	}
	return nil
}

func computeFilename(key *Key) (string, error) {
	s := sha256.New()
	e := gob.NewEncoder(s)
	if err := e.Encode(key); err != nil {
		return "", fmt.Errorf("could not encode the key: %w", err)
	}
	h := hex.EncodeToString(s.Sum(nil))
	return h, nil
}
