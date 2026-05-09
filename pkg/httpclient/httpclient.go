// Package httpclient wraps the opnsense-go library to provide a single,
// configured opnsense.Client ready for use by feature packages.
//
// It is the only package that directly imports opnsense-go/pkg/api and
// opnsense-go/pkg/opnsense, keeping the rest of the application insulated
// from upstream API changes.
package httpclient

import (
	"fmt"
	"log"
	//"os"

	"gopn/pkg/config"

	"github.com/browningluke/opnsense-go/pkg/api"
	"github.com/browningluke/opnsense-go/pkg/opnsense"
)

// DefaultRetries is used when the caller does not override retry settings.
const DefaultRetries = 3

// Options allows callers to tune the underlying HTTP client behaviour.
// All fields are optional; zero values fall back to sensible defaults.
type Options struct {
	// MaxRetries overrides DefaultRetries when > 0.
	MaxRetries int64
	// MinBackoffSecs sets the minimum backoff in seconds between retries.
	MinBackoffSecs int64
	// MaxBackoffSecs sets the maximum backoff in seconds between retries.
	MaxBackoffSecs int64
}

// New builds and returns a fully configured opnsense.Client using the
// credentials and settings from cfg.  opts may be nil to accept defaults.
func New(cfg *config.AppConfig, opts *Options) (opnsense.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("httpclient: config must not be nil")
	}

	// Disable opnsense-go debug output
	//os.Setenv("OPNSENSE_DEBUG", "")

	retries := int64(DefaultRetries)
	minBO := int64(1)
	maxBO := int64(30)

	if opts != nil {
		if opts.MaxRetries > 0 {
			retries = opts.MaxRetries
		}
		if opts.MinBackoffSecs > 0 {
			minBO = opts.MinBackoffSecs
		}
		if opts.MaxBackoffSecs > 0 {
			maxBO = opts.MaxBackoffSecs
		}
	}

	apiClient := api.NewClient(api.Options{
		Uri:           cfg.Host,
		APIKey:        cfg.APIKey,
		APISecret:     cfg.APISecret,
		AllowInsecure: cfg.AllowInsecure,
		MaxRetries:    retries,
		MinBackoff:    minBO,
		MaxBackoff:    maxBO,
	})

	log.Printf("Creating API client for host %s", cfg.Host)

	return opnsense.NewClient(apiClient), nil
}
