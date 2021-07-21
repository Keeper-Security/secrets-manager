package keeper_secrets_manager

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
)

const (
	Aes256KeySize    = 32
	AesGcmNonceSize  = 12
	DefaultBlockSize = 16
)

type PublicKey ecdsa.PublicKey
type PrivateKey ecdsa.PrivateKey

// Bytes concatenates public key x and y values
func (pub *PublicKey) Bytes() (buf []byte) {
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	buf = append(x, y...)
	return
}

// SetBytes decodes buf and stores the values in pub X and Y
func (pub *PublicKey) SetBytes(buf []byte) *PublicKey {
	bigX := new(big.Int)
	bigY := new(big.Int)
	bigX.SetBytes(buf[:32])
	bigY.SetBytes(buf[32:64])

	pub.X = bigX
	pub.Y = bigY
	pub.Curve = elliptic.P256()
	return pub
}

// Check if public key is valid for the curve
func (pub *PublicKey) Check(curve elliptic.Curve) bool {
	if pub.Curve != curve {
		return false
	}
	if !curve.IsOnCurve(pub.X, pub.Y) {
		return false
	}
	return true
}

// Bytes returns private key D value
func (priv *PrivateKey) Bytes() []byte {
	return priv.D.Bytes()
}

// SetBytes reconstructs the private key from D bytes
func (priv *PrivateKey) SetBytes(d []byte) *PrivateKey {
	bigD := new(big.Int)
	bigD.SetBytes(d)
	priv.D = bigD
	priv.Curve = elliptic.P256()
	if priv.PublicKey.X == nil {
		priv.PublicKey.Curve = elliptic.P256()
		priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(priv.D.Bytes())
	}
	return priv
}

// GetPublicKey returns the associated PublicKey for this privatekey,
// If the key is missing then one is generated.
func (priv *PrivateKey) GetPublicKey() *PublicKey {
	if priv.PublicKey.X == nil {
		priv.PublicKey.Curve = elliptic.P256()
		priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(priv.D.Bytes())
	}
	return (*PublicKey)(&priv.PublicKey)
	//return PublicKey(priv.PublicKey)
}

// Hex returns private key bytes as a hex string
func (priv *PrivateKey) Hex() string {
	return hex.EncodeToString(priv.Bytes())
}

// Equals compares two private keys with constant time (to resist timing attacks)
func (priv *PrivateKey) Equals(k *PrivateKey) bool {
	return subtle.ConstantTimeCompare(priv.D.Bytes(), k.D.Bytes()) == 1
}

// Sign signs digest with priv, reading randomness from rand.
//  The opts argument is not currently used but, in keeping with the crypto.Signer interface,
//  should be the hash function used to digest the message.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return (*ecdsa.PrivateKey)(priv).Sign(rand, digest, opts)
}

func GenerateP256Keys() (PrivateKey, error) {
	return GenerateKeys(elliptic.P256()) // golang suppors only SECP256R1
}

func GenerateKeys(curve elliptic.Curve) (PrivateKey, error) {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	return PrivateKey(*k), err
}

func EcPublicKeyFromEncodedPoint(publicKey []byte) (crypto.PublicKey, error) {
	// see https://tools.ietf.org/html/rfc6637#section-6
	if x, y := elliptic.Unmarshal(elliptic.P256(), publicKey); x != nil {
		return PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	} else {
		return PublicKey{}, errors.New("bad ECC public key")
	}
}

func EcPublicKeyToEncodedPoint(pub *ecdsa.PublicKey) ([]byte, error) {
	// see https://tools.ietf.org/html/rfc6637#section-6
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("unsupported ECC curve type")
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y), nil
}

// Encrypt a message using AES-GCM.
func EncryptAesGcm(data []byte, key []byte) ([]byte, error) {
	return EncryptAesGcmFull(data, key, nil)
}

// Encrypt a message using AES-GCM with custom nonce.
func EncryptAesGcmFull(data, key, nonce []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	if len(nonce) == 0 {
		nonce, err = GetRandomBytes(AesGcmNonceSize)
		if err != nil {
			return nil, err
		}
	}
	if len(nonce) != AesGcmNonceSize {
		return nil, errors.New("incorrect nonce size")
	}

	result := gcm.Seal(nonce, nonce, data, nil)
	return result, nil
}

// Decrypt AES-GCM encrypted message
func Decrypt(data, key []byte) ([]byte, error) {
	if len(data) <= AesGcmNonceSize {
		return nil, errors.New("error decrpyting AES-GCM - message is too short")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, AesGcmNonceSize)
	copy(nonce, data)

	result, err := gcm.Open(nil, nonce, data[AesGcmNonceSize:], nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ErrKeyExchange is returned if the key exchange fails.
var ErrKeyExchange = errors.New("key exchange failed")

// ECDH computes a shared key from a private key and a peer's public key.
func ECDH(priv PrivateKey, pub PublicKey) ([]byte, error) {
	privKey := (*ecdsa.PrivateKey)(&priv)
	pubKey := (*ecdsa.PublicKey)(&pub)
	return ECDH_Ecdsa(privKey, pubKey)
}

// ECDH computes a shared key from a private key and a peer's public key.
func ECDH_Ecdsa(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || priv == nil {
		return nil, ErrKeyExchange
	} else if priv.Curve != pub.Curve {
		return nil, ErrKeyExchange
	} else if !priv.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, ErrKeyExchange
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	if x == nil {
		return nil, ErrKeyExchange
	}

	shared := sha256.Sum256(x.Bytes())
	return shared[:Aes256KeySize], nil
}

func pkcs7Pad(data []byte) []byte {
	n := DefaultBlockSize - (len(data) % DefaultBlockSize)
	pb := make([]byte, len(data)+n)
	copy(pb, data)
	copy(pb[len(data):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
}

func pkcs7Unpad(data []byte) []byte {
	if len(data) > 0 && len(data)%DefaultBlockSize == 0 {
		c := data[len(data)-1]
		if n := int(c); n > 0 && n <= DefaultBlockSize {
			ok := true
			for i := 0; i < n; i++ {
				if data[len(data)-n+i] != c {
					ok = false
					break
				}
			}
			if ok {
				return data[:len(data)-n]
			}
		}
	}
	return data
}
