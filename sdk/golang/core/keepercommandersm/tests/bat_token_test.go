package core

import (
	"keepercommandersm/core"
	"testing"
)

func TestDecryptionWithBatToken(t *testing.T) {
	secretKey, _ := core.GetRandomBytes(32)

	plaintext := "ABC123"
	plaintextBytes := []byte(plaintext)
	encrTextBytes, _ := core.EncryptAesGcm(plaintextBytes, secretKey)

	decryptedPlaintextBytes, _ := core.Decrypt(encrTextBytes, secretKey)
	decryptedPlaintext := string(decryptedPlaintextBytes[:])

	if plaintext != decryptedPlaintext {
		t.Errorf("Decryption with BAT token failed, got: %s, want: %s.", decryptedPlaintext, plaintext)
	}
}
