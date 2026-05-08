// Package config manages the gopn application configuration stored at
// ~/.config/gopn/config.json.  It handles first-run prompting, loading,
// saving, and validation so every other package can simply call config.Load().
package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gopn/pkg/parser"
)

const defaultConfigPath = "~/.config/gopn/config.json"

// AppConfig holds all settings persisted to disk.
type AppConfig struct {
	// Host is the OPNsense instance URL, e.g. "https://192.168.1.1".
	Host string `json:"host"`
	// APIKey is generated in OPNsense under System > Access > Users.
	APIKey string `json:"api_key"`
	// APISecret is the secret paired with APIKey.
	APISecret string `json:"api_secret"`
	// AllowInsecure skips TLS certificate verification.
	// Set true when OPNsense uses a self-signed certificate.
	AllowInsecure bool `json:"allow_insecure"`
}

// resolvedPath returns the ~ expanded path to the config file.
func resolvedPath() (string, error) {
	return parser.ExpandHomePath(defaultConfigPath)
}

// Load reads the config file and returns the parsed config.
// If the file does not exist it returns a *MissingConfigError which contains
// instructions for creating the file.
func Load() (*AppConfig, error) {
	path, err := resolvedPath()
	if err != nil {
		return nil, err
	}
	if !parser.FileExists(path) {
		return nil, &MissingConfigError{Path: path}
	}
	var cfg AppConfig
	if err := parser.ReadJSON(path, &cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes cfg to the standard config file path, creating parent directories
// as needed with mode 0700.
func Save(cfg *AppConfig) error {
	path, err := resolvedPath()
	if err != nil {
		return err
	}
	return parser.WriteJSON(path, cfg)
}

// Validate returns an error when required fields are missing.
func (c *AppConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("config: host is required")
	}
	if c.APIKey == "" {
		return fmt.Errorf("config: api_key is required")
	}
	if c.APISecret == "" {
		return fmt.Errorf("config: api_secret is required")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Interactive setup
// ---------------------------------------------------------------------------

// RunSetup walks the user through creating a config file interactively.
// It writes the result to disk and returns the populated config.
func RunSetup() (*AppConfig, error) {
	path, err := resolvedPath()
	if err != nil {
		return nil, err
	}

	fmt.Println("-----------------------------------------")
	fmt.Println("  gopn - first-run configuration wizard  ")
	fmt.Println("-----------------------------------------")
	fmt.Printf("Config will be saved to: %s\n\n", path)

	reader := bufio.NewReader(os.Stdin)

	host := prompt(reader, "OPNsense host URL (e.g. https://192.168.1.1): ")
	host = strings.TrimRight(host, "/")

	apiKey := prompt(reader, "API key: ")
	apiSecret := prompt(reader, "API secret: ")

	insecureStr := prompt(reader, "Allow insecure TLS (self-signed cert)? [y/N]: ")
	allowInsecure := strings.EqualFold(strings.TrimSpace(insecureStr), "y")

	cfg := &AppConfig{
		Host:          host,
		APIKey:        apiKey,
		APISecret:     apiSecret,
		AllowInsecure: allowInsecure,
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := Save(cfg); err != nil {
		return nil, err
	}

	fmt.Printf("\nConfig saved to %s\n\n", path)
	return cfg, nil
}

func prompt(r *bufio.Reader, label string) string {
	fmt.Print(label)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

// ---------------------------------------------------------------------------
// MissingConfigError
// ---------------------------------------------------------------------------

// MissingConfigError is returned when the config file is absent.
// The CLI root command prints this error directly — it includes setup
// instructions so the user knows exactly what to do.
type MissingConfigError struct {
	Path string
}

func (e *MissingConfigError) Error() string {
	return fmt.Sprintf(
		"config file not found at %s\n\n"+
			"Run the following command to create it interactively:\n"+
			"  gopn init\n\n"+
			"Or create %s manually with the following content:\n"+
			"  {\n"+
			"    \"host\": \"https://<opnsense-host>\",\n"+
			"    \"api_key\": \"<your-api-key>\",\n"+
			"    \"api_secret\": \"<your-api-secret>\",\n"+
			"    \"allow_insecure\": true\n"+
			"  }\n",
		e.Path, e.Path,
	)
}
