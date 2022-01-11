package ksm

import (
	"errors"
	"fmt"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

var errClientConfigNil = errors.New("client configuration was nil")

// Client encapsulates KSM client for talking to the Keeper Vault.
type Client struct {
	*Config
	SecretsManager *ksm.SecretsManager
}

// NewClient returns a newly constructed client from the provided config.
// It will error if it fails to validate necessary configuration formats
func NewClient(config *Config) (c *Client, err error) {
	defer func() {
		if r := recover(); r != nil {
			c = nil
			switch x := r.(type) {
			case error:
				err = x
			default:
				err = fmt.Errorf("error creating new client: %v", r)
			}
		}
	}()

	if config == nil {
		return nil, errClientConfigNil
	}

	cfg := ksm.NewMemoryKeyValueStorage(config.KsmAppConfig)
	sm := ksm.NewSecretsManagerFromConfig(cfg)

	return &Client{
		SecretsManager: sm,
	}, nil
}

// recordOptions stores record options for current operation
type recordOptions struct {
	Uid         string `json:"uid,omitempty"`
	Type        string `json:"type,omitempty"`
	TemplateUid string `json:"template_uid,omitempty"`
	FolderUid   string `json:"folder_uid,omitempty"`
}
