package ksm

import (
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
)

var errFieldDataNil = errors.New("field data passed for updating was nil")

// Config holds all configuration for the backend.
type Config struct {
	// KsmAppConfig stores the application configuration.
	KsmAppConfig string `json:"ksm_config"`
}

// NewConfig returns a pre-configured Config struct.
func NewConfig() *Config {
	return &Config{}
}

// Update updates the configuration from the given field data only when the data is different.
func (c *Config) Update(d *framework.FieldData) (bool, error) {
	if d == nil {
		// NOTE: Use of the path framework ensures `d` is never nil.
		return false, errFieldDataNil
	}

	// Track changes to the configuration.
	var changed bool

	if AppConfig, ok := d.GetOk(keyKsmAppConfig); ok {
		if nv := AppConfig.(string); c.KsmAppConfig != nv {
			c.KsmAppConfig = nv
			changed = true
		}
	}

	return changed, nil
}
