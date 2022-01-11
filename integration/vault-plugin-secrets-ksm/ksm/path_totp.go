package ksm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/keeper-security/secrets-manager-go/core"
)

// pathPatternTotp is the string used to define the base path of the TOTP code generator.
const pathPatternTotp = "record/totp/?$"

const pathTotpHelpSyn = `
Generate and return TOTP code from the corresponding field in a vault record.
`

const pathTotpHelpDesc = `
Generates a TOTP code with validity interval. The generated TOTP is not stored.
`

func (b *backend) pathTotp() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternTotp,
		Fields: map[string]*framework.FieldSchema{
			keyRecordUid: {
				Type:        framework.TypeString,
				Description: descRecordUid,
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathTotpRead),
				Summary:  "Generate TOTP.",
			},
		},
		HelpSynopsis:    pathTotpHelpSyn,
		HelpDescription: pathTotpHelpDesc,
	}
}

// pathTotpRead generates TOTP codes from keeper record totpURL on /ksm/totp.
func (b *backend) pathTotpRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := validateFields(req, d); err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	client, done, err := b.Client(req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	opts := new(recordOptions)
	if uid, ok := d.GetOk(keyRecordUid); ok {
		opts.Uid = uid.(string)
	}

	records, err := client.SecretsManager.GetSecrets([]string{opts.Uid})
	if err != nil {
		return nil, err
	}
	if len(records) < 1 {
		return nil, fmt.Errorf("record UID: %s not found", opts.Uid)
	}
	totpItems := []interface{}{}
	record := records[0]

	if totp := strings.TrimSpace(record.GetFieldValueByType("oneTimeCode")); totp != "" {
		if code, seconds, err := getTotpCode(totp); err != nil {
			return nil, err
		} else {
			totpItems = []interface{}{
				map[string]interface{}{
					"url":   totp,
					"token": code,
					"ttl":   seconds,
				},
			}
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"UID":  opts.Uid,
			"TOTP": totpItems,
		},
	}, nil
}

func getTotpCode(totpUrl string) (code string, seconds int, err error) {
	if totp, err := core.GetTotpCode(totpUrl); err == nil {
		return totp.Code, totp.TimeLeft, nil
	} else {
		return "", 0, err
	}
}
