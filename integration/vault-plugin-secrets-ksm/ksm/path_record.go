package ksm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathPatternRecord is the string used to define the base path of the record endpoint.
const pathPatternRecord = "record"

// pathPatternList is the string used to define the base path of the list endpoint.
const pathPatternRecordList = "secrets"

const (
	keyRecordUid    = "uid"
	descRecordUid   = "The UID of the record to access."
	keyRecordType   = "type"
	descRecordType  = "The type of the record to access."
	keyTemplateUid  = "template_uid"
	descTemplateUid = "The UID of the template record."
	keyFolderUid    = "folder_uid"
	descFolderUid   = "The UID of the folder to place the record in."
)

const pathRecordListHelpSyn = "Return a list of all records in the Keeper vault."
const pathRecordListHelpDesc = "Returns list of UIDs of all records in the Keeper vault."

const pathRecordHelpSyn = "Create and return a record using the KSM plugin."

var pathRecordHelpDesc = fmt.Sprintf(`
Create and return a record using the KSM plugin, optionally
constrained by the above parameters.

NOTE: '%s' is the UID of the record to access.

NOTE: '%s' is the type of the record to access.

NOTE: '%s' is the UID of the template record.

NOTE: '%s' is the UID of the folder to put the new record in.
`, keyRecordUid, keyRecordType, keyTemplateUid, keyFolderUid)

func (b *backend) pathRecordsList() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternRecordList,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathRecordList),
				Summary:  "List all record UIDs.",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathRecordList),
				Summary:  "List all record UIDs.",
			},
		},

		HelpSynopsis:    pathRecordListHelpSyn,
		HelpDescription: pathRecordListHelpDesc,
	}
}

func (b *backend) pathRecords() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternRecord,
		Fields: map[string]*framework.FieldSchema{
			keyRecordUid: {
				Type:        framework.TypeString,
				Description: descRecordUid,
				Required:    true,
			},
			keyRecordType: {
				Type:        framework.TypeCommaIntSlice,
				Description: descRecordType,
				Required:    false,
			},
			keyTemplateUid: {
				Type:        framework.TypeKVPairs,
				Description: descTemplateUid,
				Required:    false,
			},
			keyFolderUid: {
				Type:        framework.TypeKVPairs,
				Description: descFolderUid,
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathRecordRead),
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathRecordWrite),
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathRecordWrite),
			},
		},
		ExistenceCheck:  b.recordExistenceCheck,
		HelpSynopsis:    pathRecordHelpSyn,
		HelpDescription: pathRecordHelpDesc,
	}
}

// pathRecordList lists all records in the vault
func (b *backend) pathRecordList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	records, err := client.SecretsManager.GetSecrets([]string{})
	if err != nil {
		return nil, err
	}
	recordList := map[string]interface{}{}
	for _, rec := range records {
		recordList[rec.Uid] = rec.Title()
	}
	return &logical.Response{
		Data: recordList,
	}, nil
}

func (b *backend) recordExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	uid := d.Get("uid").(string)
	if uid == "" {
		return false, fmt.Errorf("missing record UID")
	}

	records, err := b.client.SecretsManager.GetSecrets([]string{uid})
	if err != nil {
		return false, err
	}
	if len(records) == 0 {
		return false, nil
	}

	return strings.TrimSpace(records[0].RawJson) != "", nil
}

// pathRecordRead reads record from Keeper Vault on /ksm/record.
func (b *backend) pathRecordRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, done, err := b.Client(req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	// Safely parse any options from interface types.
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
	record := records[0]
	recordRes := &logical.Response{Data: record.RecordDict}
	return recordRes, nil
}

// pathRecordWrite creates new record on /ksm/record.
func (b *backend) pathRecordWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, done, err := b.Client(req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	// Safely parse any options from interface types.
	opts := new(recordOptions)

	if uid, ok := d.GetOk(keyRecordUid); ok {
		opts.Uid = uid.(string)
	}

	// TODO: Perform the RecordCreate request.
	resData := map[string]interface{}{"UID": "Sample"}
	recordRes := &logical.Response{Data: resData}
	return recordRes, nil
}
