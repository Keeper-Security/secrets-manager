package ksm

import (
	"errors"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/keeper-security/secrets-manager-go/core"
)

var (
	errFieldDataNil    = errors.New("field data passed for updating was nil")
	errBadConfigFormat = errors.New("config string is not a valid JSON/Base64")
)

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

	if appConfig, ok := d.GetOk(keyKsmAppConfig); ok {
		if nv := strings.TrimSpace(appConfig.(string)); c.KsmAppConfig != nv {
			if err := validateConfigStr(nv); err != nil {
				return false, err
			}

			// config with token only - use it to generate new config
			if parts := strings.Split(nv, ":"); len(parts) == 2 {
				if cfg, err := NewClientConfig(nv); err != nil {
					return false, err
				} else if strings.TrimSpace(cfg) != "" {
					nv = cfg
				}
			}

			c.KsmAppConfig = nv
			changed = true
		}
	}

	return changed, nil
}

func validateConfigStr(cfg string) error {
	// check if config is actually a binding token
	if parts := strings.Split(cfg, ":"); len(parts) == 2 {
		if keyBytes := core.Base64ToBytes(parts[1]); len(keyBytes) == 32 {
			return nil
		}
	}
	// not a binding token - check if it is base64 encoded
	jsonCfg := strings.TrimSpace(core.Base64ToString(cfg))
	if jsonCfg == "" {
		jsonCfg = cfg // not base64 - restore original string
	}
	// verify it is correct JSON
	if v := core.JsonToDict(string(jsonCfg)); len(v) == 0 {
		return errBadConfigFormat
	}

	return nil
}
