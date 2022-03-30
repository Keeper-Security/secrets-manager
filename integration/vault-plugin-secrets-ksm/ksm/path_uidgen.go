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

// pathPatternUidgen is the string used to define the base path of the UID generator.
const pathPatternUidgen = "uidgen"

const (
	keyUidBitLength  = "bit_length"
	descUidBitLength = "The bit length of the generated UID."
)

const pathUidgenHelpSyn = `
Generate and return a random UID that could be used by the Keeper secrets plugin.
`

const pathUidgenHelpDesc = `
Generates a random UID with the provided number bit length, returning it as
part of the response. The generated UID is not stored.
`

func (b *backend) pathUidgen() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternUidgen,
		Fields: map[string]*framework.FieldSchema{
			keyUidBitLength: {
				Type:        framework.TypeInt,
				Description: descUidBitLength,
				Default:     128,
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathUidgenRead),
				Summary:  "Generate new UID.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathUidgenRead),
				Summary:  "Generate new UID with the specified bit length.",
			},
		},
		HelpSynopsis:    pathUidgenHelpSyn,
		HelpDescription: pathUidgenHelpDesc,
	}
}

// pathUidgenRead generates new UID on /ksm/uidgen.
func (b *backend) pathUidgenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := validateFields(req, d); err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	uidlen := d.Get(keyUidBitLength).(int)
	if uidlen <= 0 {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, "must generate UID with at least 1 bit")
	}

	uid := core.GenerateUid()
	if uidlen != 128 {
		uid = core.GenerateUidWithLength(uidlen)
	}
	if strings.TrimSpace(uid) == "" {
		return nil, fmt.Errorf("failed to generate new UID")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"UID": uid,
		},
	}, nil
}
