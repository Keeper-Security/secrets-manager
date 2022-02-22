package ksm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/keeper-security/secrets-manager-go/core"
)

var errClientConfigNil = errors.New("client configuration was nil")

// Client encapsulates KSM client for talking to the Keeper Vault.
type Client struct {
	*Config
	SecretsManager *core.SecretsManager
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

	cfg := core.NewMemoryKeyValueStorage(config.KsmAppConfig)
	sm := core.NewSecretsManager(&core.ClientOptions{Config: cfg})

	return &Client{
		SecretsManager: sm,
	}, nil
}

// NewClientConfig returns a newly constructed client config form the provided token.
// It will error if it fails to bind the token and validate necessary configuration formats
func NewClientConfig(token string) (config string, err error) {
	defer func() {
		if r := recover(); r != nil {
			config = ""
			switch x := r.(type) {
			case error:
				err = x
			default:
				err = fmt.Errorf("error creating new client config: %v", r)
			}
		}
	}()

	if token := strings.TrimSpace(token); token == "" {
		return "", errClientConfigNil
	}
	if parts := strings.Split(token, ":"); len(parts) == 2 {
		cfg := core.NewMemoryKeyValueStorage()
		sm := core.NewSecretsManager(&core.ClientOptions{Token: token, Config: cfg})
		if _, err := sm.GetSecrets([]string{""}); err != nil {
			return "", err
		}

		confData := struct {
			// ClientKey         string `json:"clientKey,omitempty"`
			AppKey            string `json:"appKey,omitempty"`
			AppOwnerPublicKey string `json:"appOwnerPublicKey,omitempty"`
			ClientId          string `json:"clientId,omitempty"`
			Hostname          string `json:"hostname,omitempty"`
			PrivateKey        string `json:"privateKey,omitempty"`
			ServerPublicKeyId string `json:"serverPublicKeyId,omitempty"`
		}{
			// ClientKey:         cfg.Get(ksm.KEY_CLIENT_KEY),
			AppKey:            cfg.Get(core.KEY_APP_KEY),
			AppOwnerPublicKey: cfg.Get(core.KEY_OWNER_PUBLIC_KEY),
			ClientId:          cfg.Get(core.KEY_CLIENT_ID),
			Hostname:          cfg.Get(core.KEY_HOSTNAME),
			PrivateKey:        cfg.Get(core.KEY_PRIVATE_KEY),
			ServerPublicKeyId: cfg.Get(core.KEY_SERVER_PUBLIC_KEY_ID),
		}

		confJson, err := json.Marshal(confData)
		if err != nil {
			return "", err
		}
		config = core.BytesToBase64(confJson)
	} else {
		return "", fmt.Errorf("invalid device token: %v, expected format host:base64_token", token)
	}

	return config, nil
}

// recordOptions stores record options for current operation
type recordOptions struct {
	Uid         string `json:"uid,omitempty"`
	Type        string `json:"type,omitempty"`
	TemplateUid string `json:"template_uid,omitempty"`
	FolderUid   string `json:"folder_uid,omitempty"`
	RecordData  string `json:"data,omitempty"`
}
