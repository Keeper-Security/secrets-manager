package ksm

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = "Keeper Vault Backend"

const (
	fmtErrConfRetrieval = "failed to get configuration from storage"
	fmtErrConfUnmarshal = "failed to unmarshal configuration from JSON"
	fmtErrClientCreate  = "failed to create an authenticated Keeper client"
)

var errBackendConfigNil = errors.New("configuration passed into backend is nil")

// backend wraps the backend framework and the client
type backend struct {
	*framework.Backend

	// The actual Keeper client and a lock used for controlling access allowing
	// for safe rotation if the mounted configuration changes.
	client     *Client
	clientLock sync.RWMutex
}

// Factory configures and returns Keeper backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := new(backend)

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeLogical,
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathUidgen(),
			b.pathTotp(),
			b.pathRecord(),
			b.pathRecords(),
			b.pathRecordsCreate(),
			b.pathRecordsList(),
		},
		Invalidate: b.Invalidate,
	}

	if conf == nil {
		return nil, errBackendConfigNil
	}

	if err := b.Setup(ctx, conf); err != nil {
		// NOTE: Setup never errors in current Hashicorp SDK.
		return nil, err
	}

	b.Logger().Info("plugin backend successfully initialised")

	return b, nil
}

// Invalidate resets the plugin. It is called when a key is updated via replication.
func (b *backend) Invalidate(_ context.Context, key string) {
	if key == pathPatternConfig {
		// Configuration has changed so reset the client.
		b.clientLock.Lock()
		b.client = nil
		b.clientLock.Unlock()
	}
}

// Config parses and returns the configuration data from the storage backend.
// An empty config is returned in the case where there is no existing in storage.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*Config, error) {
	c := NewConfig()

	entry, err := s.Get(ctx, pathPatternConfig)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fmtErrConfRetrieval, err)
	}

	if entry == nil || len(entry.Value) == 0 {
		return c, nil
		// return c, fmt.Errorf("the plugin has not been configured yet")
	}

	if err := entry.DecodeJSON(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", fmtErrConfUnmarshal, err)
	}

	return c, nil
}

// Client returns a client for interfacing the configured Keeper SM App.
// Resets due to configuration updates are safely handled.
// Users are expected to use the returned closer when finished.
func (b *backend) Client(s logical.Storage) (*Client, func(), error) {
	b.clientLock.RLock()
	if b.client != nil {
		return b.client, func() { b.clientLock.RUnlock() }, nil
	}
	b.clientLock.RUnlock()

	// Acquire a globally exclusive lock to close any connections and create a
	// new client.
	//
	// NOTE: Since all invocations of this method acquire a read lock and defer
	// release, this will block until all clients are no longer in use.
	b.clientLock.Lock()

	// Clear the client once more in case of earlier concurrent creation.
	b.client = nil

	config, err := b.Config(context.Background(), s)
	if err != nil {
		b.clientLock.Unlock()
		return nil, nil, err
	}

	client, err := NewClient(config)
	if err != nil {
		b.clientLock.Unlock()
		return nil, nil, fmt.Errorf("%s: %w", fmtErrClientCreate, err)
	}

	b.client = client

	b.clientLock.Unlock()
	b.Logger().Debug("Created Keeper Secrets Manager Client",
		"ksm_config", config.KsmAppConfig,
	)
	b.clientLock.RLock()

	return b.client, func() { b.clientLock.RUnlock() }, nil
}
