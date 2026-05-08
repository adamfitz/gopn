// Package parser provides generic, reusable helpers used across all packages:
// type-safe conversions, JSON config file read/write, and path resolution.
package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

// WriteJSON serialises v as indented JSON and writes it to path.
// The parent directory is created if it does not exist.
func WriteJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("parser: mkdir %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("parser: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("parser: write %s: %w", path, err)
	}
	return nil
}

// ReadJSON reads path and unmarshals JSON into v (must be a pointer).
func ReadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("parser: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parser: unmarshal %s: %w", path, err)
	}
	return nil
}

// FileExists returns true when path exists and is a regular file.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ---------------------------------------------------------------------------
// Type-safe conversion helpers
// ---------------------------------------------------------------------------

// ToString returns the string representation of v.
// If v is already a string it is returned as-is.
// api.SelectedMap from opnsense-go is a named string type that also satisfies
// fmt.Stringer, so this function handles both plain strings and SelectedMap
// fields without requiring a direct cast.
func ToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ToBool converts common OPNsense "1"/"0"/"true"/"false" string values
// used in API responses to a Go bool.
func ToBool(s string) bool {
	switch s {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// Coalesce returns the first non-empty string from args, or fallback if all
// are empty.
func Coalesce(fallback string, args ...string) string {
	for _, s := range args {
		if s != "" {
			return s
		}
	}
	return fallback
}

// ExpandHomePath replaces a leading ~ with the current user's home directory.
func ExpandHomePath(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("parser: home dir: %w", err)
	}
	return filepath.Join(home, path[1:]), nil
}
