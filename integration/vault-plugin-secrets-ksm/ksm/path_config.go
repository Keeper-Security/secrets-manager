package ksm

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathPatternConfig is the string used to define the base path of the config
// endpoint as well as the storage path of the config object.
const pathPatternConfig = "config"

const (
	fmtErrConfMarshal = "failed to marshal configuration to JSON"
	fmtErrConfPersist = "failed to persist configuration to storage"
	fmtErrConfDelete  = "failed to delete configuration from storage"
)

const (
	keyKsmAppConfig  = "ksm_config"
	descKsmAppConfig = "Configuration of the KSM App."
)

const pathConfigHelpSyn = `
Configure the Keeper secrets plugin.
`

var pathConfigHelpDesc = `
Configure the Keeper secrets plugin using the above parameters.
`

// pathConfig defines the /ksm/config base path on the backend.
func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternConfig,
		Fields: map[string]*framework.FieldSchema{
			keyKsmAppConfig: {
				Type:        framework.TypeString,
				Description: descKsmAppConfig,
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Password",
					Sensitive: true,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigWrite),
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigWrite),
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigRead),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigDelete),
			},
		},
		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

// pathConfigRead corresponds to READ on /ksm/config.
func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	c, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			keyKsmAppConfig: c.KsmAppConfig,
		},
	}, nil
}

// pathConfigWrite corresponds to both CREATE and UPDATE on /ksm/config.
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Update the configuration.
	changed, err := c.Update(d)
	if err != nil {
		return nil, logical.CodedError(400, err.Error())
	}

	// Persist only if changed.
	if changed {
		entry, err := logical.StorageEntryJSON(pathPatternConfig, c)
		if err != nil {
			// NOTE: Failure scenario cannot happen.
			return nil, fmt.Errorf("%s: %w", fmtErrConfMarshal, err)
		}

		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("%s: %w", fmtErrConfPersist, err)
		}

		// Invalidate existing client so it reads the new configuration.
		b.Invalidate(ctx, pathPatternConfig)
	}

	return nil, nil
	// return &logical.Response{Data: map[string]interface{}{"ksm_config": c.KsmAppConfig}}, nil
}

// pathConfigDelete corresponds to DELETE on /ksm/config.
func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, pathPatternConfig); err != nil {
		return nil, fmt.Errorf("%s: %w", fmtErrConfDelete, err)
	}

	// Invalidate existing client so it reads the new configuration.
	b.Invalidate(ctx, pathPatternConfig)

	return nil, nil
}
