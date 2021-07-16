package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	klog "keepercommandersm/core/logger"
	"math/big"
	"os"
	"runtime"
	"strings"
)

// ECDSASignature needed for compatibility with openssl (python > hazmat > openssl > ec > _ecdsa_sig_sign)
// which uses ASN.1/DER SEQUENCE format
// NB! MaxLen for ASN.1, depends on the encoding. P1363 only needs 64 bytes. And an OpePGP encoding only needs 66 bytes.
// ECDSASignature using ASN.1/DER needs up to 72 bytes. DER requires a minimum number of bytes.
// If ASN.1/BER is used, then the signature can be hundreds of bytes.
type ECDSASignature struct {
	R, S *big.Int
}

func PadBinary(s []byte) []byte {
	return pkcs7Pad(s)
}

func UnpadBinary(s []byte) []byte {
	return pkcs7Unpad(s)
}

// PadBinary = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
// UnpadBinary = lambda s: s[0:-s[-1]]

func GetOS() string {
	os := runtime.GOOS
	switch os {
	case "windows":
		return "Windows"
	case "darwin":
		return "MacOS"
	case "linux":
		return "Linux"
	default:
		return os
	}
}

func BytesToString(b []byte) string {
	return string(b)
}

func StringToBytes(s string) []byte {
	return []byte(s)
}

func ByteToInt(b []byte) string {
	return string(b)
}

func BytesToUrlSafeStr(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func UrlSafeStrToBytes(text string) []byte {
	text = strings.TrimRight(text, "=")
	// fix non URL Safe strings
	text = strings.ReplaceAll(text, "+", "-")
	text = strings.ReplaceAll(text, "/", "_")
	result, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil
	}

	return result
}

func BytesToBase64(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

func Base64ToBytes(text string) []byte {
	return UrlSafeStrToBytes(text)
}

func GetRandomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	return data, err
}

func ClearBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

func GenerateRandomBytes(size int) ([]byte, error) {
	return GetRandomBytes(size)
}

func GenerateUid() string {
	uid, _ := GetRandomBytes(16)
	return BytesToUrlSafeStr(uid)
}

// UrlSafeSha256FromString generates URL safe encoded SHA256 sum of data in URL safe base64 encoded string
func UrlSafeSha256FromString(text string) string {
	if text == "" {
		return ""
	}

	bytes := UrlSafeStrToBytes(text)
	if len(bytes) == 0 {
		return ""
	}

	sha256 := sha256.Sum256(bytes)
	result := BytesToUrlSafeStr(sha256[:])
	return result
}

// UrlSafeHmacFromString generates URL safe encoded HMAC of the message string where key is URL safe base64 encoded string
func UrlSafeHmacFromString(key string, message string) string {
	keyBytes := UrlSafeStrToBytes(key)
	msgBytes := StringToBytes(message)
	hmac := HmacDigest(keyBytes, msgBytes)
	result := BytesToUrlSafeStr(hmac)
	return result
}

func HmacDigest(key []byte, message []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	result := mac.Sum(nil)
	return result
}

func JsonToDict(content string) map[string]interface{} {
	var payload map[string]interface{}
	err := json.Unmarshal([]byte(content), &payload)
	if err != nil {
		klog.Error("Error parsing JSON: " + err.Error())
		return map[string]interface{}{}
	}
	return payload
}

func DictToJson(dict map[string]interface{}) string {
	content, err := json.Marshal(dict)
	if err != nil {
		klog.Error("Error converting to JSON: " + err.Error())
		return ""
	}
	return string(content)
}

func DictToJsonWithIndent(dict map[string]interface{}, indent string) string {
	content, err := json.MarshalIndent(dict, "", indent)
	if err != nil {
		klog.Error("Error converting to JSON: " + err.Error())
		return ""
	}
	return string(content)
}

func DictToJsonWithDefultIndent(dict map[string]interface{}) string {
	return DictToJsonWithIndent(dict, "    ")
}

// Encryption methods
func GeneratePrivateKeyEcc() (PrivateKey, error) {
	return GenerateP256Keys()
}

func GeneratePrivateKeyDer() ([]byte, error) {
	privateKey, err := GeneratePrivateKeyEcc()
	if err != nil {
		return []byte{}, err
	}
	// Export to DER - PKCS #8 ASN.1 DER form with NoEncryption
	if privateKeyDer, err := x509.MarshalPKCS8PrivateKey((*ecdsa.PrivateKey)(&privateKey)); err != nil {
		return []byte{}, err
	} else {
		return privateKeyDer, nil
	}
}

func LoadDerPrivateKeyDer(data []byte) (*PrivateKey, error) {
	if len(data) < 1 {
		return nil, errors.New("private key data is empty")
	}
	// Import private key - PKCS #8 ASN.1 DER form with NoEncryption
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			return (*PrivateKey)(k), nil
		case *rsa.PrivateKey:
			return nil, errors.New("private key is in an unsupported format: RSA Private Key")
		case ed25519.PrivateKey:
			return nil, errors.New("private key is in an unsupported format: Ed25519 Private Key")
		default:
			return nil, errors.New("private key is in an unsupported format")
		}
	} else {
		return nil, errors.New("private key data parsing error: " + err.Error())
	}
}

func DerBase64PrivateKeyToPrivateKey(privateKeyDerBase64 string) (*PrivateKey, error) {
	if strings.TrimSpace(privateKeyDerBase64) != "" {
		privateKeyDerBase64Bytes := Base64ToBytes(privateKeyDerBase64)
		return LoadDerPrivateKeyDer(privateKeyDerBase64Bytes)
	}
	return nil, errors.New("private key data is empty")
}

func Sign(data []byte, privateKey *PrivateKey) ([]byte, error) {
	msgHash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, (*ecdsa.PrivateKey)(privateKey), msgHash[:])
	if err != nil {
		return []byte{}, errors.New("signature generation failed: " + err.Error())
	}
	ecdsaSig := ECDSASignature{R: r, S: s}
	if signature, err := asn1.Marshal(ecdsaSig); err == nil {
		return signature, nil
	} else {
		return []byte{}, errors.New("signature serialization failed: " + err.Error())
	}
}

// Verify validates decrypted message against the given public key.
// On success, returns nil, on failure returns a relevant error.
func Verify(data []byte, signature []byte, publicKey *PublicKey) error {
	sig := &ECDSASignature{}
	_, err := asn1.Unmarshal(signature, sig)
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	valid := ecdsa.Verify(
		(*ecdsa.PublicKey)(publicKey),
		h[:],
		sig.R,
		sig.S,
	)
	if !valid {
		return errors.New("signature validation failed")
	}
	// signature is valid
	return nil
}

func extractPublicKeyBytes(privateKeyDerBase64 interface{}) ([]byte, error) {
	pkDerBase64 := ""
	switch v := privateKeyDerBase64.(type) {
	case string:
		pkDerBase64 = v
	case []byte:
		pkDerBase64 = BytesToUrlSafeStr(v)
	default:
		return nil, errors.New("extracting public key DER bytes failed - PK must be string or byte slice")
	}

	if ecPrivateKey, err := DerBase64PrivateKeyToPrivateKey(pkDerBase64); err == nil {
		pubKey := ecPrivateKey.GetPublicKey()
		if pubKeyBytes, err := EcPublicKeyToEncodedPoint((*ecdsa.PublicKey)(pubKey)); err == nil {
			return pubKeyBytes, nil
		} else {
			return nil, errors.New("error extracting public key from DER: " + err.Error())
		}
	} else {
		return nil, errors.New("error extracting private key from DER: " + err.Error())
	}
}

func DecryptRecord(data, secretKey []byte) (string, error) {
	if record, err := Decrypt(data, secretKey); err == nil {
		recordJson := BytesToString(record)
		return recordJson, nil
	} else {
		return "", err
	}
}

func GenerateNewEccKey() (PrivateKey, error) {
	return GenerateP256Keys()
}

func PublicEncrypt(data []byte, serverPublicRawKeyBytes []byte, idz []byte) (encrypted []byte, err error) {
	ephemeralKey2, err := GenerateNewEccKey()
	if err != nil {
		return nil, err
	}
	ephemeralKey2PublicKey := (*ecdsa.PublicKey)(ephemeralKey2.GetPublicKey())

	ephemeralPublicKey, err := EcPublicKeyFromEncodedPoint(serverPublicRawKeyBytes)
	if err != nil {
		return nil, err
	}

	epk, ok := ephemeralPublicKey.(PublicKey)
	if !ok {
		return nil, errors.New("bad format for ECC public key")
	}

	sharedKey, err := ECDH(ephemeralKey2, epk)
	if err != nil {
		return nil, err
	}

	encryptedData, err := EncryptAesGcm(data, sharedKey)
	if err != nil {
		return nil, err
	}

	ephPublicKey, err := EcPublicKeyToEncodedPoint(ephemeralKey2PublicKey)
	if err != nil {
		return nil, err
	}
	encrypted = append(ephPublicKey, encryptedData...)

	return encrypted, nil
}

var strToBoolMap = map[string]bool{
	"y":     true,
	"yes":   true,
	"t":     true,
	"true":  true,
	"on":    true,
	"1":     true,
	"n":     false,
	"no":    false,
	"f":     false,
	"false": false,
	"off":   false,
	"0":     false,
}

// StrToBool convert a string representation of truth to a boolean true or false.
func StrToBool(val string) (bool, error) {
	// true values are 'y', 'yes', 't', 'true', 'on', and '1'
	// false values are 'n', 'no', 'f', 'false', 'off', and '0'.
	val = strings.ToLower(val)
	if res, ok := strToBoolMap[val]; ok {
		return res, nil
	}
	return false, fmt.Errorf("invalid truth value %s", val)
}

// PathExists returns whether the given file or directory exists
func PathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}
