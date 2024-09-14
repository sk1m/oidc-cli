package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var (
	ErrConfigNotFound = errors.New("config file not found")
	ErrUserNotFound   = errors.New("user not found")
)

type User struct {
	Name         string   `yaml:"name"`
	IssuerURL    string   `yaml:"issuer_url"`
	ClientID     string   `yaml:"client_id"`
	ExtraScopes  []string `yaml:"extra_scopes"`
	GrantType    string   `yaml:"grant_type"`
	IDToken      string   `yaml:"id_token,omitempty"`
	AccessToken  string   `yaml:"access_token,omitempty"`
	RefreshToken string   `yaml:"refresh_token"`
}

type Config struct {
	Users []*User `yaml:"users"`
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w (filename=%s)", ErrConfigNotFound, filename)
		}
		return nil, fmt.Errorf("read file %s: %w", filename, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal yaml (filename=%s): %w", filename, err)
	}

	return &cfg, nil
}

func writeConfig(filename string, cfg *Config) error {
	var buf bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&buf)
	yamlEncoder.SetIndent(2)
	if err := yamlEncoder.Encode(cfg); err != nil {
		return fmt.Errorf("encode yaml: %w", err)
	}

	dir := filepath.Dir(filename)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(filename, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write file %s: %w", filename, err)
	}

	return nil
}

func FindUser(filename string, username string) (*User, error) {
	cfg, err := loadConfig(filename)
	if err != nil {
		if errors.Is(err, ErrConfigNotFound) {
			cfg = &Config{}
		} else {
			return nil, fmt.Errorf("load config: %w", err)
		}
	}

	for _, user := range cfg.Users {
		if user.Name == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("%w (username=%s)", ErrUserNotFound, username)
}

func UserList(filename string) ([]string, error) {
	cfg, err := loadConfig(filename)
	if err != nil {
		if errors.Is(err, ErrConfigNotFound) {
			cfg = &Config{}
		} else {
			return nil, fmt.Errorf("load config: %w", err)
		}
	}

	var users []string
	for _, user := range cfg.Users {
		users = append(users, user.Name)
	}

	return users, nil
}

func SaveUser(filename string, user *User) error {
	cfg, err := loadConfig(filename)
	if err != nil {
		if errors.Is(err, ErrConfigNotFound) {
			cfg = &Config{}
		} else {
			return fmt.Errorf("load config: %w", err)
		}
	}

	var replaced bool
	for i, u := range cfg.Users {
		if u.Name == user.Name {
			cfg.Users[i] = user
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.Users = append(cfg.Users, user)
	}

	return writeConfig(filename, cfg)
}
