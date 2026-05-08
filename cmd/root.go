// Package cmd contains all Cobra command definitions for the gopn CLI.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopn/pkg/config"
)

// JSONOutput is the global --json flag value, shared by all sub-commands.
// Declared here on the root persistent flags so it is available everywhere.
var JSONOutput bool

var rootCmd = &cobra.Command{
	Use:   "gopn",
	Short: "gopn - OPNsense automation CLI",
	Long: `gopn is a command-line tool for automating and auditing OPNsense
firewall configuration via the OPNsense REST API.

Config file: ~/.config/gopn/config.json
Run 'gopn init' to create it interactively.`,
	SilenceUsage: true,
}

// Execute is the entry point called from main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// --json is a global persistent flag available on every command.
	rootCmd.PersistentFlags().BoolVar(
		&JSONOutput, "json", false,
		"Output results as JSON instead of a human-readable table",
	)

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(fwCmd)
}

// ---------------------------------------------------------------------------
// gopn init
// ---------------------------------------------------------------------------

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Interactively create the gopn config file",
	Long: `Walks you through entering your OPNsense host URL, API key, API
secret, and TLS preference, then saves the result to
~/.config/gopn/config.json.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := config.RunSetup()
		return err
	},
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

// loadConfig loads the application config and prints a structured error
// message (including setup instructions) when the file is missing.
func loadConfig() (*config.AppConfig, error) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil, fmt.Errorf("cannot continue without a valid config")
	}
	return cfg, nil
}
