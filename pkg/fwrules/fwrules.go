// Package fwrules provides all firewall filter rule logic:
//
//   - Application-level structs (Rule, DuplicateGroup, ConsolidationSuggestion,
//     AnalysisResult) that decouple downstream code from the opnsense-go types.
//   - FetchAll: retrieves all rules from the OPNsense API.
//   - FindDuplicates: identifies logically identical rules.
//   - FindConsolidations: suggests rules that could be merged via a port alias.
//   - Table and JSON renderers for human and machine consumption.
//
// # Field mapping note
//
// firewall.FilterRule fields are typed as api.SelectedMap (a string-backed named
// type).  fromLibRule uses parser.ToString() on every field so this file is the
// only place that needs updating if upstream types change.
//
// # Method name note
//
// The generated controller method is GetFilterRules(ctx).  If your resolved
// version of opnsense-go names it differently, update FetchAll below.
// Run `go doc github.com/browningluke/opnsense-go/pkg/firewall` to confirm.
package fwrules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/browningluke/opnsense-go/pkg/firewall"
	"github.com/browningluke/opnsense-go/pkg/opnsense"
	"github.com/olekukonko/tablewriter"
	"github.com/yourusername/gopn/pkg/parser"
)

// ---------------------------------------------------------------------------
// Application-level structs
// ---------------------------------------------------------------------------

// Rule is the canonical in-application representation of a single OPNsense
// firewall filter rule.  It is safe to use across packages without importing
// the upstream opnsense-go library.
type Rule struct {
	UUID        string `json:"uuid"`
	Enabled     bool   `json:"enabled"`
	Action      string `json:"action"`
	Direction   string `json:"direction"`
	Interface   string `json:"interface"`
	IPProtocol  string `json:"ip_protocol"`
	Protocol    string `json:"protocol"`
	SourceNet   string `json:"source_net"`
	SourcePort  string `json:"source_port"`
	DestNet     string `json:"dest_net"`
	DestPort    string `json:"dest_port"`
	Gateway     string `json:"gateway"`
	Description string `json:"description"`
	Log         bool   `json:"log"`
	Sequence    string `json:"sequence"`
}

// DuplicateGroup holds two or more rules that are logically identical.
type DuplicateGroup struct {
	// Fingerprint is the normalised key that matched across these rules.
	Fingerprint string `json:"fingerprint"`
	Rules       []Rule `json:"rules"`
}

// ConsolidationSuggestion holds rules that share the same source/destination
// networks, action, interface, and protocol but differ only in destination
// port — candidates for a single rule using an OPNsense port alias.
type ConsolidationSuggestion struct {
	// Key is a human-readable description: "srcNet -> dstNet [proto action iface]"
	Key   string   `json:"key"`
	Ports []string `json:"ports"`
	Rules []Rule   `json:"rules"`
}

// AnalysisResult bundles the full rule list with any analysis output so that
// callers consuming --json output get everything in one payload.
type AnalysisResult struct {
	Rules       []Rule                    `json:"rules"`
	Duplicates  []DuplicateGroup          `json:"duplicates,omitempty"`
	Suggestions []ConsolidationSuggestion `json:"consolidation_suggestions,omitempty"`
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

// FetchAll retrieves every configured firewall filter rule from OPNsense and
// returns them sorted by sequence as application-level Rule structs.
func FetchAll(ctx context.Context, client opnsense.Client) ([]Rule, error) {
	rulesMap, err := client.Firewall().GetFilterRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("fwrules: fetch: %w", err)
	}

	rules := make([]Rule, 0, len(rulesMap))
	for uuid, r := range rulesMap {
		rules = append(rules, fromLibRule(uuid, r))
	}

	sortBySequence(rules)
	return rules, nil
}

// fromLibRule converts a firewall.FilterRule from the opnsense-go library into
// our application Rule.  parser.ToString handles both plain string fields and
// api.SelectedMap fields (named string type implementing fmt.Stringer).
func fromLibRule(uuid string, r firewall.FilterRule) Rule {
	return Rule{
		UUID:        uuid,
		Enabled:     parser.ToBool(parser.ToString(r.Enabled)),
		Action:      parser.ToString(r.Action),
		Direction:   parser.ToString(r.Direction),
		Interface:   parser.ToString(r.Interface),
		IPProtocol:  parser.ToString(r.IPProtocol),
		Protocol:    parser.ToString(r.Protocol),
		SourceNet:   parser.Coalesce("any", parser.ToString(r.SourceNet)),
		SourcePort:  parser.Coalesce("any", parser.ToString(r.SourcePort)),
		DestNet:     parser.Coalesce("any", parser.ToString(r.DestinationNet)),
		DestPort:    parser.Coalesce("any", parser.ToString(r.DestinationPort)),
		Gateway:     parser.ToString(r.Gateway),
		Description: parser.ToString(r.Description),
		Log:         parser.ToBool(parser.ToString(r.Log)),
		Sequence:    parser.ToString(r.Sequence),
	}
}

// ---------------------------------------------------------------------------
// Analysis — duplicates
// ---------------------------------------------------------------------------

// fingerprint produces a normalised key that captures the logical behaviour of
// a rule, deliberately excluding UUID, description, log flag, and sequence so
// that rules differing only in those fields are detected as duplicates.
func fingerprint(r Rule) string {
	return strings.Join([]string{
		norm(r.Action),
		norm(r.Direction),
		norm(r.Interface),
		norm(r.IPProtocol),
		norm(r.Protocol),
		norm(r.SourceNet),
		norm(r.SourcePort),
		norm(r.DestNet),
		norm(r.DestPort),
		norm(r.Gateway),
	}, "|")
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// FindDuplicates returns all groups of rules with identical fingerprints.
// Groups with only one member are not included.
func FindDuplicates(rules []Rule) []DuplicateGroup {
	index := make(map[string][]Rule)
	for _, r := range rules {
		fp := fingerprint(r)
		index[fp] = append(index[fp], r)
	}
	var groups []DuplicateGroup
	for fp, rs := range index {
		if len(rs) > 1 {
			groups = append(groups, DuplicateGroup{Fingerprint: fp, Rules: rs})
		}
	}
	return groups
}

// ---------------------------------------------------------------------------
// Analysis — consolidation suggestions
// ---------------------------------------------------------------------------

// consolidationKey groups rules that could be merged: same action, interface,
// protocol, source net, and destination net — varying only in destination port.
func consolidationKey(r Rule) string {
	return strings.Join([]string{
		norm(r.Action),
		norm(r.Interface),
		norm(r.Protocol),
		norm(r.SourceNet),
		norm(r.DestNet),
	}, "|")
}

// FindConsolidations returns groups of rules that are candidates for merging
// into a single rule with an OPNsense port alias.
func FindConsolidations(rules []Rule) []ConsolidationSuggestion {
	index := make(map[string][]Rule)
	for _, r := range rules {
		key := consolidationKey(r)
		index[key] = append(index[key], r)
	}
	var suggestions []ConsolidationSuggestion
	for _, rs := range index {
		if len(rs) < 2 {
			continue
		}
		ports := uniquePorts(rs)
		if len(ports) < 2 {
			continue
		}
		r0 := rs[0]
		label := fmt.Sprintf("%s -> %s [proto:%s action:%s iface:%s]",
			r0.SourceNet, r0.DestNet,
			parser.Coalesce("any", r0.Protocol),
			r0.Action, r0.Interface)
		suggestions = append(suggestions, ConsolidationSuggestion{
			Key:   label,
			Ports: ports,
			Rules: rs,
		})
	}
	return suggestions
}

func uniquePorts(rs []Rule) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, r := range rs {
		p := parser.Coalesce("any", r.DestPort)
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Rendering — tables
// ---------------------------------------------------------------------------

// PrintRulesTable writes all rules as a human-readable terminal table to w.
func PrintRulesTable(w io.Writer, rules []Rule) {
	tbl := tablewriter.NewWriter(w)
	tbl.SetHeader([]string{
		"#", "UUID", "En", "Action", "Dir", "Iface",
		"Proto", "Src", "SrcPort", "Dst", "DstPort", "Log", "Description",
	})
	tbl.SetBorder(true)
	tbl.SetRowLine(false)
	tbl.SetAutoWrapText(false)
	tbl.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	tbl.SetAlignment(tablewriter.ALIGN_LEFT)

	for i, r := range rules {
		tbl.Append([]string{
			fmt.Sprintf("%d", i+1),
			shortUUID(r.UUID),
			boolMark(r.Enabled),
			r.Action,
			r.Direction,
			r.Interface,
			parser.Coalesce("any", r.Protocol),
			r.SourceNet,
			parser.Coalesce("any", r.SourcePort),
			r.DestNet,
			parser.Coalesce("any", r.DestPort),
			boolMark(r.Log),
			truncate(r.Description, 40),
		})
	}
	tbl.Render()
	fmt.Fprintf(w, "\nTotal rules: %d\n", len(rules))
}

// PrintDuplicatesTable renders duplicate groups as terminal tables to w.
func PrintDuplicatesTable(w io.Writer, groups []DuplicateGroup) {
	if len(groups) == 0 {
		fmt.Fprintln(w, "No duplicate rules found.")
		return
	}
	fmt.Fprintf(w, "Found %d duplicate group(s):\n\n", len(groups))
	for i, g := range groups {
		fmt.Fprintf(w, "Group %d  fingerprint: %s\n", i+1, g.Fingerprint)
		tbl := tablewriter.NewWriter(w)
		tbl.SetHeader([]string{"UUID", "En", "Action", "Src", "SrcPort", "Dst", "DstPort", "Description"})
		tbl.SetBorder(true)
		tbl.SetAutoWrapText(false)
		for _, r := range g.Rules {
			tbl.Append([]string{
				shortUUID(r.UUID),
				boolMark(r.Enabled),
				r.Action,
				r.SourceNet,
				parser.Coalesce("any", r.SourcePort),
				r.DestNet,
				parser.Coalesce("any", r.DestPort),
				truncate(r.Description, 35),
			})
		}
		tbl.Render()
		fmt.Fprintln(w)
	}
}

// PrintConsolidationsTable renders consolidation suggestions as terminal tables to w.
func PrintConsolidationsTable(w io.Writer, suggestions []ConsolidationSuggestion) {
	if len(suggestions) == 0 {
		fmt.Fprintln(w, "No consolidation opportunities found.")
		return
	}
	fmt.Fprintf(w, "Found %d consolidation opportunity(ies):\n\n", len(suggestions))
	for i, s := range suggestions {
		fmt.Fprintf(w, "Suggestion %d  %s\n", i+1, s.Key)
		fmt.Fprintf(w, "  Unique destination ports: %s\n", strings.Join(s.Ports, ", "))
		fmt.Fprintf(w, "  %d rules could be merged using an OPNsense port alias:\n", len(s.Rules))
		tbl := tablewriter.NewWriter(w)
		tbl.SetHeader([]string{"UUID", "En", "Action", "Src", "Dst", "DstPort", "Description"})
		tbl.SetBorder(true)
		tbl.SetAutoWrapText(false)
		for _, r := range s.Rules {
			tbl.Append([]string{
				shortUUID(r.UUID),
				boolMark(r.Enabled),
				r.Action,
				r.SourceNet,
				r.DestNet,
				parser.Coalesce("any", r.DestPort),
				truncate(r.Description, 35),
			})
		}
		tbl.Render()
		fmt.Fprintln(w)
	}
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

// MarshalJSON returns pretty-printed JSON for any value.
func MarshalJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func shortUUID(u string) string {
	if len(u) > 8 {
		return u[:8] + "..."
	}
	return u
}

func boolMark(b bool) string {
	if b {
		return "Y"
	}
	return "N"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "~"
}

// sortBySequence performs an in-place insertion sort by Sequence.
// OPNsense stores sequence as a zero-padded decimal string so lexicographic
// ordering is equivalent to numeric ordering.
func sortBySequence(rules []Rule) {
	for i := 1; i < len(rules); i++ {
		for j := i; j > 0 && rules[j].Sequence < rules[j-1].Sequence; j-- {
			rules[j], rules[j-1] = rules[j-1], rules[j]
		}
	}
}
