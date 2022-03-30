package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
	"github.com/keeper-security/secrets-manager/integration/vault-plugin-secrets-ksm/ksm"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}

	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		fatalErr(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: ksm.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		fatalErr(err)
	}
}

func fatalErr(err error) {
	hclog.New(&hclog.LoggerOptions{}).Error(
		"plugin shutting down",
		"error",
		err,
	)
	os.Exit(1)
}
