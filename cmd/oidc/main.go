package main

import (
	"context"
	"os"

	"github.com/sk1m/oidc-cli/internal/build"
	"github.com/sk1m/oidc-cli/internal/cmd"
)

type exitCode int

const (
	exitOK    exitCode = 0
	exitError exitCode = 1
)

func main() {
	code := mainRun()
	os.Exit(int(code))
}

func mainRun() exitCode {
	buildDate := build.Date
	buildVersion := build.Version

	factory := cmd.NewFactory()
	ctx := context.Background()

	rootCmd, err := cmd.NewCmdRoot(factory, buildVersion, buildDate)
	if err != nil {
		factory.Logger.Errorf("failed to create root command: %s", err)
		return exitError
	}

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		factory.Logger.Errorf("exec: %s", err)
		return exitError
	}

	return exitOK
}
