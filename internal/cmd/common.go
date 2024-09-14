package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func expandHomedir(s string) (string, error) {
	if !strings.HasPrefix(s, "~") {
		return s, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("homedir: %w", err)
	}

	return filepath.Join(home, strings.TrimPrefix(s, "~")), nil
}

func env(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return ""
}

func envDefault(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
