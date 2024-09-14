package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sk1m/oidc-cli/internal/logger"
)

func NewCmdRoot(f *Factory, version, buildDate string) (*cobra.Command, error) {
	var verboseLevel int
	var configFile string

	cmd := &cobra.Command{
		Use:   "oidc",
		Short: "OIDC CLI",
		Long:  "The OpenID connect command line tool.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if p, err := expandHomedir(configFile); err != nil {
				return fmt.Errorf("expand configFile %s: %w", configFile, err)
			} else {
				configFile = p
			}

			f.Logger.SetLevel(logger.Level(-verboseLevel))
			return nil
		},
	}

	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	cmd.PersistentFlags().Bool("help", false, "Show help for command")
	cmd.PersistentFlags().CountVarP(&verboseLevel, "verbose", "v", "verbose output (-v or -vv)")

	cmd.PersistentFlags().StringVar(
		&configFile,
		"config",
		envDefault("OIDC_CONFIG_FILE", filepath.Join("~", ".config", "oidc", "config.yaml")),
		"Path to the config file (OIDC_CONFIG_FILE)",
	)

	cmd.AddCommand(NewCmdVersion(f, version, buildDate))
	cmd.AddCommand(NewCmdLogin(f))
	cmd.AddCommand(NewCmdToken(f))

	return cmd, nil
}
