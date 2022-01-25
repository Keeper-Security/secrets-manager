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

// pathPatternRecord is the string used to define the base path of the record endpoint.
const pathPatternRecord = "record/?$"

// pathPatternRecordCreate is the string used to define the base path of the record create endpoint.
const pathPatternRecordCreate = "record/create/?$"

// pathPatternList is the string used to define the base path of the list endpoint.
const pathPatternRecordList = "records/?$"

const (
	keyRecordUid    = "uid"
	descRecordUid   = "The UID of the record to access."
	keyTemplateUid  = "template_uid"
	descTemplateUid = "The UID of the template record."
	keyFolderUid    = "folder_uid"
	descFolderUid   = "The UID of the folder to place the record in."
	keyRecordData   = "data"
	descRecordData  = "The record data in JSON format."
)

const pathRecordListHelpSyn = "Return a list of all records in the Keeper vault."
const pathRecordListHelpDesc = "Returns list of UIDs of all records in the Keeper vault."
const pathRecordHelpSyn = "Returns record data using the KSM plugin."
const pathRecordHelpDesc = "Return record data as JSON using the KSM plugin."

const pathRecordCreateHelpSyn = "Create a record and returns its record UID using the KSM plugin."

var pathRecordCreateHelpDesc = fmt.Sprintf(`
Creates a record and returns its record UID using the KSM plugin,
using the following parameters.

NOTE: '%s' is the UID of the record to create - if emty, generates new random UID.

NOTE: '%s' is the UID of the folder to put the new record in.
`, keyRecordUid, keyFolderUid)

func (b *backend) pathRecordsList() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternRecordList,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
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
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathRecordRead),
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

func (b *backend) pathRecordsCreate() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternRecordCreate,
		Fields: map[string]*framework.FieldSchema{
			keyRecordUid: {
				Type:        framework.TypeString,
				Description: descRecordUid,
				Required:    false,
			},
			keyFolderUid: {
				Type:        framework.TypeString,
				Description: descFolderUid,
				Required:    true,
			},
			keyRecordData: {
				Type:        framework.TypeString,
				Description: descRecordData,
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathRecordCreate),
			},
		},
		ExistenceCheck:  b.recordExistenceCheck,
		HelpSynopsis:    pathRecordCreateHelpSyn,
		HelpDescription: pathRecordCreateHelpDesc,
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

	keys := []string{}
	keyInfo := map[string]interface{}{}

	folderList := map[string]int{}
	recordList := map[string]interface{}{}
	for _, rec := range records {
		key := fmt.Sprintf("%v\t%v:\t%v", rec.Uid, rec.Type(), rec.Title())
		keys = append(keys, key)
		keyInfo[key] = rec.Uid
		recordList[rec.Uid] = rec.Title()
		if folderUid := strings.TrimSpace(rec.FolderUid()); folderUid != "" {
			folderList[folderUid] = folderList[folderUid] + 1
		}
	}
	for fkey, fval := range folderList {
		if _, found := recordList[fkey]; found {
			fkey += ":2" // tag as duplicate
		}
		key := fmt.Sprintf("%v\t%v:\t%v record(s)", fkey, "folder", fval)
		keys = append(keys, key)
		keyInfo[key] = fkey
		recordList[fkey] = fmt.Sprintf("Folder - %d record(s)", fval)
	}

	return logical.ListResponseWithInfo(keys, keyInfo), nil
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

// pathRecordWrite updates new record on /ksm/record.
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

	recordRes := &logical.Response{}
	return recordRes, nil
}

// pathRecordCreate creates new record on /ksm/record.
func (b *backend) pathRecordCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	// Safely parse any options from interface types.
	opts := new(recordOptions)

	if uid, ok := d.GetOk(keyRecordUid); ok {
		opts.Uid = uid.(string)
	}
	if folderUid, ok := d.GetOk(keyFolderUid); ok {
		opts.FolderUid = folderUid.(string)
	}
	if recordData, ok := d.GetOk(keyRecordData); ok {
		opts.RecordData = recordData.(string)
	}

	records, err := client.SecretsManager.GetSecrets([]string{})
	if err != nil {
		return nil, err
	}

	templateRecordUid := ""
	for _, record := range records {
		if record.FolderUid() == opts.FolderUid {
			templateRecordUid = record.Uid
			break
		}
	}
	if templateRecordUid == "" {
		return nil, fmt.Errorf("folder UID: %s not found or the folder is empty", opts.FolderUid)
	}

	newRecord, err := core.NewRecord(templateRecordUid, records, "")
	if err != nil {
		return nil, err
	}
	newRecord.RawJson = opts.RecordData
	newRecord.RecordDict = core.JsonToDict(newRecord.RawJson)

	newRecUID, err := client.SecretsManager.CreateSecret(newRecord)
	if err != nil {
		return nil, err
	}

	resData := map[string]interface{}{newRecUID: newRecord.Title()}
	recordRes := &logical.Response{Data: resData}
	return recordRes, nil
}
