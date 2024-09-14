package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewCmdVersion(f *Factory, version string, buildDate string) *cobra.Command {
	v := version
	if buildDate != "" {
		v = fmt.Sprintf(" (%s)", buildDate)
	}

	cmd := &cobra.Command{
		Use:  "version",
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			f.Logger.Printf("oidc version %s", v)
		},
	}

	return cmd
}
