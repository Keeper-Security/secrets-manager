package core

import (
	"encoding/json"
	klog "keepercommandersm/core/logger"
)

type Context struct {
	TransmissionKey TransmissionKey
	ClientId        []byte
	ClientKey       []byte
}

func NewContext(transmissionKey TransmissionKey, clientId []byte, clientKey []byte) *Context {
	return &Context{
		TransmissionKey: transmissionKey,
		ClientId:        clientId,
		ClientKey:       clientKey,
	}
}

type TransmissionKey struct {
	PublicKeyId  int
	Key          []byte
	EncryptedKey []byte
}

func NewTransmissionKey(publicKeyId int, key []byte, encryptedKey []byte) *TransmissionKey {
	return &TransmissionKey{
		PublicKeyId:  publicKeyId,
		Key:          key,
		EncryptedKey: encryptedKey,
	}
}

type GetPayload struct {
	ClientVersion    string   `json:"clientVersion"`
	ClientId         string   `json:"clientId"`
	PublicKey        string   `json:"publicKey"`
	RequestedRecords []string `json:"requestedRecords"`
}

func (p *GetPayload) GetPayloadToJson() (string, error) {
	if emp, err := json.Marshal(p); err == nil {
		return string(emp), nil
	} else {
		klog.Error("Error serializing GetPayload to JSON: " + err.Error())
		return "", err
	}
}

func (p *GetPayload) GetPayloadFromJson(jsonData string) {
	bytes := []byte(jsonData)
	res := GetPayload{}

	if err := json.Unmarshal(bytes, &res); err == nil {
		*p = res
	} else {
		klog.Error("Error deserializing GetPayload from JSON: " + err.Error())
	}
}

type UpdatePayload struct {
	ClientVersion string `json:"clientVersion"`
	ClientId      string `json:"clientId"`
	RecordUid     string `json:"recordUid"`
	Data          string `json:"data"`
}

func (p *UpdatePayload) UpdatePayloadToJson() (string, error) {
	if emp, err := json.Marshal(p); err == nil {
		return string(emp), nil
	} else {
		klog.Error("Error serializing UpdatePayload to JSON: " + err.Error())
		return "", err
	}
}

func (p *UpdatePayload) UpdatePayloadFromJson(jsonData string) {
	bytes := []byte(jsonData)
	res := UpdatePayload{}

	if err := json.Unmarshal(bytes, &res); err == nil {
		*p = res
	} else {
		klog.Error("Error deserializing UpdatePayload from JSON: " + err.Error())
	}
}

type SignedPayload struct {
	Payload   []byte
	Signature []byte
}
