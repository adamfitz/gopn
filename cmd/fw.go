package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopn/pkg/fwrules"
	"gopn/pkg/httpclient"
)

// ---------------------------------------------------------------------------
// fw (parent command)
// ---------------------------------------------------------------------------

var fwCmd = &cobra.Command{
	Use:   "fw",
	Short: "Firewall rule operations",
	Long:  `Commands for listing, analysing, and auditing OPNsense firewall rules.`,
}

func init() {
	fwCmd.AddCommand(fwRulesCmd)
	fwCmd.AddCommand(fwDuplicatesCmd)
	fwCmd.AddCommand(fwConsolidateCmd)
}

// ---------------------------------------------------------------------------
// gopn fw rules
// ---------------------------------------------------------------------------

var fwRulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List all configured firewall rules",
	Long: `Fetches every firewall filter rule from OPNsense and displays them
in a human-readable table (default) or as JSON (--json).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		client, err := httpclient.New(cfg, nil)
		if err != nil {
			return fmt.Errorf("fw rules: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		rules, err := fwrules.FetchAll(ctx, client)
		if err != nil {
			return fmt.Errorf("fw rules: %w", err)
		}

		if JSONOutput {
			data, err := fwrules.MarshalJSON(rules)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}

		fwrules.PrintRulesTable(os.Stdout, rules)
		return nil
	},
}

// ---------------------------------------------------------------------------
// gopn fw duplicates
// ---------------------------------------------------------------------------

var fwDuplicatesCmd = &cobra.Command{
	Use:   "duplicates",
	Short: "Identify duplicate firewall rules",
	Long: `Fetches all firewall rules and identifies any that are logically
identical (same action, direction, interface, protocol, source and destination
networks and ports, gateway).

UUID, description, log flag, and sequence are excluded from comparison.

Use --json to receive a machine-parseable AnalysisResult payload.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		client, err := httpclient.New(cfg, nil)
		if err != nil {
			return fmt.Errorf("fw duplicates: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		rules, err := fwrules.FetchAll(ctx, client)
		if err != nil {
			return fmt.Errorf("fw duplicates: %w", err)
		}

		groups := fwrules.FindDuplicates(rules)

		if JSONOutput {
			result := fwrules.AnalysisResult{
				Rules:      rules,
				Duplicates: groups,
			}
			data, err := fwrules.MarshalJSON(result)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("Analysed %d rules.\n\n", len(rules))
		fwrules.PrintDuplicatesTable(os.Stdout, groups)
		return nil
	},
}

// ---------------------------------------------------------------------------
// gopn fw consolidate
// ---------------------------------------------------------------------------

var fwConsolidateCmd = &cobra.Command{
	Use:   "consolidate",
	Short: "Suggest rules that could potentially be consolidated",
	Long: `Fetches all firewall rules and identifies groups that share the same
source network, destination network, action, interface, and protocol but have
different destination ports.

These are candidates for merging into a single rule using an OPNsense port alias.
gopn never modifies your firewall — all output is read-only analysis.

Use --json to receive a machine-parseable AnalysisResult payload.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		client, err := httpclient.New(cfg, nil)
		if err != nil {
			return fmt.Errorf("fw consolidate: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		rules, err := fwrules.FetchAll(ctx, client)
		if err != nil {
			return fmt.Errorf("fw consolidate: %w", err)
		}

		suggestions := fwrules.FindConsolidations(rules)

		if JSONOutput {
			result := fwrules.AnalysisResult{
				Rules:       rules,
				Suggestions: suggestions,
			}
			data, err := fwrules.MarshalJSON(result)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("Analysed %d rules.\n\n", len(rules))
		fwrules.PrintConsolidationsTable(os.Stdout, suggestions)
		return nil
	},
}
