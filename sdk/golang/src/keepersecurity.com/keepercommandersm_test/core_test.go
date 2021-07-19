package keepercommandersm

import (
	"testing"

	ksm "keepersecurity.com/keepercommandersm"
)

func TestPrepareContext(t *testing.T) {
	config := ksm.NewMemoryKeyValueStorage()
	config.Set(ksm.KEY_CLIENT_KEY, "MY CLIENT KEY")
	config.Set(ksm.KEY_APP_KEY, "MY APP KEY")

	// Pass in the config
	c := ksm.NewCommanderFromConfig(config)

	// There should be no app key
	if c.Config.Get(ksm.KEY_APP_KEY) != "" {
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
