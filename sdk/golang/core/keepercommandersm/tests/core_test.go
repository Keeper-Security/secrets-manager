package core

import (
	"keepercommandersm/core"
	"testing"
)

func TestPrepareContext(t *testing.T) {
	config := core.NewMemoryKeyValueStorage()
	config.Set(core.KEY_CLIENT_KEY, "MY CLIENT KEY")
	config.Set(core.KEY_APP_KEY, "MY APP KEY")

	// Pass in the config
	c := core.NewCommanderFromConfig(config)

	// There should be no app key
	if c.Config.Get(core.KEY_APP_KEY) != "" {
		t.Error("found the app key")
	}

	if context := c.PrepareContext(); context != nil {
		if len(context.TransmissionKey.Key) < 1 {
			t.Error("did not find a transmission key")
		}
		if len(context.ClientId) < 1 {
			t.Error("did not find a client id")
		}
	}
}
