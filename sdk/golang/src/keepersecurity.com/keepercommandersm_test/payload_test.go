package keepercommandersm

import (
	"testing"

	ksm "keepersecurity.com/keepercommandersm"
)

func TestTransmissionKey(t *testing.T) {
	c := ksm.NewCommanderFromSettings("1234", "EU", true)
	for _, keyNum := range []int{1, 2, 3, 4, 5, 6} {
		transmissionKey := c.GenerateTransmissionKey(keyNum)
		if keyNum != transmissionKey.PublicKeyId {
			t.Error("public key id does not match the key num")
		}
		if len(transmissionKey.Key) != 32 {
			t.Error("the transmission key is not 32 bytes long")
		}
		if len(transmissionKey.EncryptedKey) != 125 {
			t.Error("the transmission encryptedKey is not 125 bytes long")
		}
	}
}
