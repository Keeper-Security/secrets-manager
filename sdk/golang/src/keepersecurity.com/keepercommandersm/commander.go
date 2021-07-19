package keepercommandersm

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	klog "keepersecurity.com/keepercommandersm/logger"
)

const CommanderNotationPrefix string = "keeper"

type commander struct {
	ClientKey      string
	Server         string
	VerifySslCerts bool
	Config         IKeyValueStorage
	context        **Context
}

func NewCommander() *commander {
	c := &commander{
		VerifySslCerts: true,
	}
	c.init()
	return c
}

func NewCommanderFromConfig(config IKeyValueStorage, arg ...interface{}) *commander {
	c := &commander{
		VerifySslCerts: true,
		Config:         config,
	}
	if len(arg) > 0 {
		if ctx, ok := arg[0].(**Context); ok && ctx != nil {
			c.context = ctx
		}
	}
	c.init()
	return c
}

func NewCommanderFromSettings(clientKey string, server string, verifySslCerts bool) *commander {
	return NewCommanderFromFullSetup(clientKey, server, verifySslCerts, NewFileKeyValueStorage())
}

func NewCommanderFromFullSetup(clientKey string, server string, verifySslCerts bool, config IKeyValueStorage) *commander {
	// If the server or client key are set in the args, make sure they makes it's way into the config.
	// They will override what is already in the config if they exist.
	if cKey := strings.TrimSpace(clientKey); cKey != "" {
		config.Set(KEY_CLIENT_KEY, cKey)
	}
	if srv := strings.TrimSpace(server); srv != "" {
		config.Set(KEY_SERVER, srv)
	}
	c := &commander{
		ClientKey:      clientKey,
		Server:         server,
		VerifySslCerts: verifySslCerts,
		Config:         config,
	}
	c.init()
	return c
}

func (c *commander) NotationPrefix() string {
	return CommanderNotationPrefix
}

func (c *commander) init() {
	klog.SetLogLevel(klog.DebugLevel)

	// Accept the env var KSM_SKIP_VERIFY
	if ksv := strings.TrimSpace(os.Getenv("KSM_SKIP_VERIFY")); ksv != "" {
		if ksvBool, err := StrToBool(ksv); err == nil {
			// We need to flip the value of KSM_SKIP_VERIFY, if true, we want VerifySslCerts to be false.
			c.VerifySslCerts = !ksvBool
		} else {
			klog.Error("error parsing boolean value from KSM_SKIP_VERIFY=" + ksv)
		}
	}

	if c.Config == nil {
		c.Config = NewFileKeyValueStorage()
	}
	c.loadConfig()
}

func (c *commander) loadConfig() {
	existingSecretKey := c.LoadSecretKey()
	if esk := strings.TrimSpace(existingSecretKey); esk == "" {
		klog.Panicln("Cannot find the client key in the configuration file.")
	}

	existingSecretKeyHash := UrlSafeHmacFromString(existingSecretKey, "KEEPER_SECRETS_MANAGER_CLIENT_ID")

	clientId := c.Config.Get(KEY_CLIENT_ID)

	if existingSecretKey == "" {
		// Secret key was not supplied (Probably already bound and client id is present?)
		if clientId == "" {
			// Instruct user how to bind using commander or web ui
			klog.Panicln("runtime error: Not bound")
		}
	} else if existingSecretKeyHash == clientId {
		// Already bound
		klog.Debug("Already bound")
	} else {
		c.Config.Delete(KEY_CLIENT_ID)
		c.Config.Delete(KEY_PRIVATE_KEY)
		c.Config.Delete(KEY_APP_KEY)

		c.Config.Set(KEY_CLIENT_KEY, existingSecretKey)
		c.Config.Set(KEY_CLIENT_ID, existingSecretKeyHash)

		if privateKeyStr := strings.TrimSpace(c.Config.Get(KEY_PRIVATE_KEY)); privateKeyStr == "" {
			if privateKeyDer, err := GeneratePrivateKeyDer(); err == nil {
				c.Config.Set(KEY_PRIVATE_KEY, BytesToUrlSafeStr(privateKeyDer))
			} else {
				klog.Panicln("Failed to generate private key. " + err.Error())
			}
		}
	}

	if !c.VerifySslCerts {
		klog.Warning("WARNING: Running without SSL cert verification. " +
			"Execute 'Commander.VerifySslCerts = True' or set 'KSM_SKIP_VERIFY=FALSE' " +
			"to enable verification.")
	}
}

// Returns client_id from the environment variable, config file, or in the code
func (c *commander) LoadSecretKey() string {
	// Case 1: Environment Variable
	currentSecretKey := ""
	if envSecretKey := strings.TrimSpace(os.Getenv("KSM_SECRET_KEY")); envSecretKey != "" {
		currentSecretKey = envSecretKey
		klog.Info("Secret key found in environment variable")
	}

	// Case 2: Code
	if currentSecretKey == "" && strings.TrimSpace(c.ClientKey) != "" {
		currentSecretKey = strings.TrimSpace(c.ClientKey)
		klog.Info("Secret key found in code")
	}

	// Case 3: Config storage
	if currentSecretKey == "" {
		if configSecretKey := strings.TrimSpace(c.Config.Get(KEY_CLIENT_KEY)); configSecretKey != "" {
			currentSecretKey = configSecretKey
			klog.Info("Secret key found in configuration file")
		}
	}

	return currentSecretKey
}

func (c *commander) GenerateTransmissionKey(keyNumber int) TransmissionKey {
	transmissionKey, _ := GenerateRandomBytes(Aes256KeySize)
	serverPublicRawKeyBytes := UrlSafeStrToBytes(keeperServerPublicKeyRawString)
	encryptedKey, _ := PublicEncrypt(transmissionKey, serverPublicRawKeyBytes, nil)
	result := TransmissionKey{
		PublicKeyId:  keyNumber,
		Key:          transmissionKey,
		EncryptedKey: encryptedKey,
	}
	return result
}

func (c *commander) PrepareContext() *Context {
	transmissionKey := c.GenerateTransmissionKey(1)
	clientId := strings.TrimSpace(c.Config.Get(KEY_CLIENT_ID))
	secretKey := []byte{}

	// While not used in the normal operations, it's used for mocking unit tests.
	if appKey := c.Config.Get(KEY_APP_KEY); appKey != "" {
		secretKey = Base64ToBytes(appKey)
	}

	if clientId == "" {
		klog.Panicln("Client ID is missing from the configuration")
	}
	clientIdBytes := Base64ToBytes(clientId)
	context := &Context{
		TransmissionKey: transmissionKey,
		ClientId:        clientIdBytes,
		ClientKey:       secretKey,
	}
	if c.context != nil {
		*c.context = context
	}

	return context
}

func (c *commander) encryptAndSignPayload(context *Context, payloadJson string) (res SignedPayload, err error) {
	payloadBytes := StringToBytes(payloadJson)

	encryptedPayload, err := EncryptAesGcm(payloadBytes, context.TransmissionKey.Key)
	if err != nil {
		klog.Error("Error encrypting the payload: " + err.Error())
	}

	signatureBase := make([]byte, 0, len(context.TransmissionKey.EncryptedKey)+len(encryptedPayload))
	signatureBase = append(signatureBase, ([]byte)(context.TransmissionKey.EncryptedKey)...)
	signatureBase = append(signatureBase, encryptedPayload...)

	if pk, err := DerBase64PrivateKeyToPrivateKey(c.Config.Get(KEY_PRIVATE_KEY)); err == nil {
		if signature, err := Sign(signatureBase, pk); err == nil {
			return SignedPayload{
				Payload:   encryptedPayload,
				Signature: signature,
			}, nil
		} else {
			return SignedPayload{}, errors.New("error generating signature: " + err.Error())
		}
	} else {
		return SignedPayload{}, errors.New("error loading private key: " + err.Error())
	}
}

func (c *commander) prepareGetPayload(context *Context, recordsFilter []string) (res SignedPayload, err error) {
	payload := GetPayload{
		ClientVersion: keeperCommanderSmClientId,
		ClientId:      BytesToUrlSafeStr(context.ClientId),
	}

	if appKeyStr := c.Config.Get(KEY_APP_KEY); strings.TrimSpace(appKeyStr) == "" {
		if publicKeyBytes, err := extractPublicKeyBytes(c.Config.Get(KEY_PRIVATE_KEY)); err == nil {
			publicKeyBase64 := BytesToUrlSafeStr(publicKeyBytes)
			// passed once when binding
			payload.PublicKey = publicKeyBase64
		} else {
			return SignedPayload{}, errors.New("error extracting public key for get payload")
		}
	}

	if len(recordsFilter) > 0 {
		payload.RequestedRecords = recordsFilter
	}
	if payloadJson, err := payload.GetPayloadToJson(); err == nil {
		if encryptedPayload, err := c.encryptAndSignPayload(context, payloadJson); err == nil {
			return encryptedPayload, nil
		} else {
			return SignedPayload{}, errors.New("error encrypting get payload: " + err.Error())
		}
	} else {
		return SignedPayload{}, errors.New("error converting get payload to JSON: " + err.Error())
	}
}

func (c *commander) prepareUpdatePayload(context *Context, record *Record) (res *SignedPayload, err error) {
	payload := UpdatePayload{
		ClientVersion: keeperCommanderSmClientId,
		ClientId:      BytesToUrlSafeStr(context.ClientId),
	}

	if len(context.ClientKey) < 1 {
		klog.Panicln("To save and update, client must be authenticated by device token only")
	}

	// for update, uid of the record
	payload.RecordUid = record.Uid

	// #TODO: This is where we need to get JSON of the updated Record
	rawJson := DictToJson(record.RecordDict)
	rawJsonBytes := StringToBytes(rawJson)
	if encryptedRawJsonBytes, err := EncryptAesGcm(rawJsonBytes, record.RecordKeyBytes); err == nil {
		// for create and update, the record data
		payload.Data = BytesToUrlSafeStr(encryptedRawJsonBytes)
	} else {
		return nil, err
	}

	if payloadJson, err := payload.UpdatePayloadToJson(); err == nil {
		if encryptedPayload, err := c.encryptAndSignPayload(context, payloadJson); err == nil {
			return &encryptedPayload, nil
		} else {
			return &SignedPayload{}, errors.New("error encrypting update payload: " + err.Error())
		}
	} else {
		return &SignedPayload{}, errors.New("error converting update payload to JSON: " + err.Error())
	}
}

func (c *commander) PostQuery(path string, context *Context, payloadAndSignature *SignedPayload) (res *http.Response, body []byte, err error) {
	keeperServer := GetServer(c.Server, c.Config)

	transmissionKey := context.TransmissionKey
	payload := payloadAndSignature.Payload
	signature := payloadAndSignature.Signature

	url := fmt.Sprintf("https://%s/api/rest/sm/v1/%s", keeperServer, path)
	rq, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, nil, err
	}

	rq.Header.Set("Content-Type", "application/octet-stream")
	rq.Header.Set("Content-Length", fmt.Sprint(len(payload)))
	rq.Header.Set("PublicKeyId", fmt.Sprint(transmissionKey.PublicKeyId))
	rq.Header.Set("TransmissionKey", BytesToUrlSafeStr(transmissionKey.EncryptedKey))
	rq.Header.Set("Authorization", fmt.Sprintf("Signature %s", BytesToUrlSafeStr(signature)))
	// klog.Debug(rq.Header)

	tr := http.DefaultClient.Transport
	if insecureSkipVerify := !c.VerifySslCerts; insecureSkipVerify {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		}
	}
	client := &http.Client{Transport: tr}

	rs, err := client.Do(rq)
	if err != nil {
		return nil, nil, err
	}
	defer rs.Body.Close()

	if rsBody, err := io.ReadAll(rs.Body); err == nil {
		return rs, rsBody, nil
	} else {
		return rs, rsBody, err
	}
}

func (c *commander) Fetch(recordFilter []string) (records []*Record, justBound bool, err error) {
	records = []*Record{}
	justBound = false

	context := c.PrepareContext()
	payloadAndSignature, err := c.prepareGetPayload(context, recordFilter)
	if err != nil {
		return records, justBound, err
	}

	rs, body, err := c.PostQuery("get_secret", context, &payloadAndSignature)
	if err != nil {
		return records, justBound, err
	}

	if rs.StatusCode != 200 {
		if rs.StatusCode == 403 {
			responseDict := JsonToDict(string(body))
			if rc, found := responseDict["result_code"]; found && rc != nil && rc.(string) == "invalid_client_version" {
				klog.Error(fmt.Sprintf("Client version %s was not registered in the backend", keeperCommanderSmClientId))
				if additionalInfo, found := responseDict["additional_info"]; found {
					klog.Panicln(additionalInfo)
				}
			} else if rerr, found := responseDict["error"]; found {
				// Errors:
				//     1. error: throttled,     message: Due to repeated attempts, your request has been throttled. Try again in 2 minutes.
				//     2. error: access_denied, message: Unable to validate application access
				//     3. error: access_denied, message: Signature is invalid
				strError := fmt.Sprintf("Error: %s, message=%s", rerr, responseDict["message"])
				klog.Panicln(strError)
			} else {
				additinalInfo := responseDict["additional_info"]
				if additinalInfo == nil || strings.TrimSpace(additinalInfo.(string)) == "" {
					additinalInfo = responseDict["message"]
				}
				if additinalInfo != nil {
					additinalInfo = strings.TrimSpace(additinalInfo.(string))
				}
				klog.Error(fmt.Sprintf("Error code: %v, additional info: %s", responseDict["result_code"], additinalInfo))
				klog.Panicln("Access denied. One-Time Token cannot be reused.")
			}
		} else if rs.StatusCode == 400 {
			// Example errors:
			//   - error: invalid,     message Invalid secrets manager payload
			//   - error: bad_request, message: unable to decrypt the payload
			klog.Panicln(body)
		} else {
			respDict := JsonToDict(string(body))
			klog.Error(fmt.Sprintf("Error: %s  (http error code: %d, raw: %s)", rs.Status, rs.StatusCode, respDict))
			klog.Panicln("HttpError!")
		}
	}

	decryptedResponseBytes, err := Decrypt(body, context.TransmissionKey.Key)
	if err != nil {
		return records, justBound, err
	}

	decryptedResponseStr := BytesToString(decryptedResponseBytes)
	decryptedResponseDict := JsonToDict(decryptedResponseStr)

	secretKey := Base64ToBytes(c.Config.Get(KEY_APP_KEY))
	if encryptedAppKey, found := decryptedResponseDict["encryptedAppKey"]; found && encryptedAppKey != nil && fmt.Sprintf("%v", encryptedAppKey) != "" {
		justBound = true
		encryptedMasterKey := UrlSafeStrToBytes(encryptedAppKey.(string))
		if secretKey, err = Decrypt(encryptedMasterKey, UrlSafeStrToBytes(c.Config.Get(KEY_CLIENT_KEY))); err == nil {
			c.Config.Set(KEY_APP_KEY, BytesToUrlSafeStr(secretKey))
		} else {
			klog.Error("failed to decrypt APP_KEY")
		}
	}

	if bound, found := decryptedResponseDict["justBound"]; found && bound != nil && reflect.TypeOf(justBound) == reflect.TypeOf(bound) && bound.(bool) {
		justBound = true
	} else {
		justBound = false
	}

	recordsResp := decryptedResponseDict["records"]
	foldersResp := decryptedResponseDict["folders"]

	emptyInterfaceSlice := []interface{}{}
	if recordsResp != nil {
		if reflect.TypeOf(recordsResp) == reflect.TypeOf(emptyInterfaceSlice) {
			for _, r := range recordsResp.([]interface{}) {
				record := NewRecordFromJson(r.(map[string]interface{}), secretKey)
				records = append(records, record)
			}
		} else {
			klog.Error("record JSON is in incorrect format")
		}
	}

	if foldersResp != nil {
		if reflect.TypeOf(foldersResp) == reflect.TypeOf(emptyInterfaceSlice) {
			for _, f := range foldersResp.([]interface{}) {
				folder := NewFolderFromJson(f.(map[string]interface{}), secretKey)
				if f != nil {
					records = append(records, folder.Records()...)
				} else {
					klog.Error("error parsing folder JSON: ", f)
				}
			}
		} else {
			klog.Error("folder JSON is in incorrect format")
		}
	}

	return records, justBound, nil
}

func (c *commander) GetSecrets(uids []string) (records []*Record, err error) {
	// Retrieve all records associated with the given application
	recordsResp, justBound, err := c.Fetch(uids)
	if err != nil {
		return nil, err
	}
	if justBound {
		recordsResp, _, err = c.Fetch(uids)
		if err != nil {
			return nil, err
		}
	}

	// #TODO: Erase client key because we are already bound

	return recordsResp, nil
}

func (c *commander) Save(record *Record) (err error) {
	// Save updated secret values
	klog.Info("Updating record uid: " + record.Uid)

	context := c.PrepareContext()
	payloadAndSignature, err := c.prepareUpdatePayload(context, record)
	if err != nil {
		return err
	}

	rs, body, err := c.PostQuery("update_secret", context, payloadAndSignature)
	if err != nil {
		return err
	}

	if rs.StatusCode != 200 {
		if rs.StatusCode == 403 {
			klog.Error(fmt.Sprintf("Error: %s  (http error code: %d) Details: %s", rs.Status, rs.StatusCode, string(body)))
			return errors.New(rs.Status)
		} else {
			respDict := JsonToDict(string(body))
			klog.Error(fmt.Sprintf("Error: %s  (http error code: %d, raw: %s)", rs.Status, rs.StatusCode, respDict))
			klog.Panicln("HttpError!")
			// return errors.New(rs.Status)
		}
	}

	return nil
}

func (c *commander) GetNotation(url string) (fieldValue []interface{}, err error) {
	/*
		Simple string notation to get a value

		* A system of figures or symbols used in a specialized field to represent numbers, quantities, tones,
			or values.

		<uid>/<field|custom_field|file>/<label|type>[INDEX][FIELD]

		Example:

			EG6KdJaaLG7esRZbMnfbFA/field/password                => MyPasswprd
			EG6KdJaaLG7esRZbMnfbFA/field/password[0]             => MyPassword
			EG6KdJaaLG7esRZbMnfbFA/field/password[]              => ["MyPassword"]
			EG6KdJaaLG7esRZbMnfbFA/custom_field/name[first]      => John
			EG6KdJaaLG7esRZbMnfbFA/custom_field/name[last]       => Smitht
			EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[0][number] => "555-5555555"
			EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[1][number] => "777-7777777"
			EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[]          => [{"number": "555-555...}, { "number": "777.....}]
			EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[0]         => [{"number": "555-555...}]
	*/

	fieldValue = []interface{}{}
	// If the URL starts with keeper:// we want to remove it.
	if strings.HasPrefix(strings.ToLower(url), c.NotationPrefix()) {
		errMisingPath := errors.New("keeper url missing information about the uid, field type, and field key")
		if urlParts := strings.Split(url, "//"); len(urlParts) > 1 {
			if url = urlParts[1]; url == "" {
				return fieldValue, errMisingPath
			}
		} else {
			return fieldValue, errMisingPath
		}
	}

	uid, fieldType, key := "", "", ""
	if urlParts := strings.Split(url, "/"); len(urlParts) == 3 {
		uid = urlParts[0]
		fieldType = urlParts[1]
		key = urlParts[2]
	} else {
		return fieldValue, fmt.Errorf("could not parse the notation '%s'. Is it valid? ", url)
	}

	if uid == "" {
		return fieldValue, errors.New("record UID is missing in the keeper url")
	}
	if fieldType == "" {
		return fieldValue, errors.New("field type is missing in the keeper url")
	}
	if key == "" {
		return fieldValue, errors.New("field key is missing in the keeper url")
	}

	// By default we want to return a single value, which is the first item in the array
	returnSingle := true
	index := 0
	dictKey := ""

	// Check it see if the key has a predicate, possibly with an index.
	rePredicate := regexp.MustCompile(`\[([^\]]*)\]`)
	rePredicateValue := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if predicates := rePredicate.FindAllStringSubmatch(key, 3); len(predicates) > 0 {
		if len(predicates) > 2 {
			return fieldValue, errors.New("the predicate of the notation appears to be invalid. Too many [], max 2 allowed. ")
		}
		if firstPredicate := predicates[0]; len(firstPredicate) > 1 {
			value := firstPredicate[1]
			// If the first predicate is an index into an array - fileRef[2]
			if i, err := strconv.ParseInt(value, 10, 64); err == nil {
				index = int(i)
			} else if matched := rePredicateValue.MatchString(value); matched {
				// the first predicate is a key to a dictionary - name[first]
				dictKey = value
			} else {
				// else it was an array indicator (.../name[] or .../name) - return all the values
				returnSingle = false
			}
		}
		if len(predicates) > 1 {
			if !returnSingle {
				return fieldValue, errors.New("if the second [] is a dictionary key, the first [] needs to have any index. ")
			}
			if secondPredicate := predicates[1]; len(secondPredicate) > 1 {
				if value := secondPredicate[1]; len(value) > 0 {
					// If the second predicate is an index into an array - fileRef[2]
					if _, err := strconv.ParseInt(value, 10, 64); err == nil {
						return fieldValue, errors.New("the second [] can only by a key for the dictionary. It cannot be an index. ")
					} else if matched := rePredicateValue.MatchString(value); matched {
						// the second predicate is a key to a dictionary - name[first]
						dictKey = value
					} else {
						// else it was an array indicator (.../name[] or .../name) - return all the values
						return fieldValue, errors.New("the second [] must have key for the dictionary. Cannot be blank. ")
					}
				}
			}
		}

		// Remove the predicate from the key, if it exists
		if pos := strings.Index(key, "["); pos >= 0 {
			key = key[:pos]
		}
	}

	records, err := c.GetSecrets([]string{uid})
	if err != nil {
		return fieldValue, err
	}
	if len(records) == 0 {
		return fieldValue, errors.New("Could not find a record with the UID " + uid)
	}

	record := records[0]

	var iValue []map[string]interface{}
	if fieldType == "field" {
		iValue = record.GetFieldsByType(key)
	} else if fieldType == "custom_field" {
		iValue = record.GetCustomFieldsByLabel(key) // by default custom[] searches are by label
	} else if fieldType == "file" {
		file := record.FindFileByTitle(key)
		fieldValue = append(fieldValue, file.GetFileData())
		return fieldValue, nil
	} else {
		return fieldValue, fmt.Errorf("field type of %s is not value. ", fieldType)
	}

	if returnSingle {
		if len(iValue) == 0 {
			return fieldValue, nil
		}
		val, ok := iValue[0]["value"].([]interface{})
		if !ok {
			return fieldValue, nil
		}
		if len(val) > index {
			iVal := val[index]
			retMap, mapOk := iVal.(map[string]interface{})
			if mapOk && strings.TrimSpace(dictKey) != "" {
				if val, ok := retMap[dictKey]; ok {
					fieldValue = append(fieldValue, val)
				} else {
					return fieldValue, fmt.Errorf("cannot find the dictionary key %s in the value ", dictKey)
				}
			} else {
				fieldValue = append(fieldValue, iVal)
			}
			if len(fieldValue) > 0 {
				if strValue, ok := fieldValue[0].(string); ok {
					fieldValue = []interface{}{strValue}
				} else if mapValue, ok := fieldValue[0].(map[string]interface{}); ok {
					if v, ok := mapValue["value"].([]interface{}); ok {
						if len(v) > 0 {
							fieldValue = []interface{}{fmt.Sprintf("%v", v[0])}
						} else {
							fieldValue = []interface{}{""}
						}
					}
				}
			}
		} else {
			return fieldValue, fmt.Errorf("the value at index %d does not exist for %s. ", index, url)
		}
	} else {
		fieldValue = append(fieldValue, iValue)
	}

	return fieldValue, nil
}
