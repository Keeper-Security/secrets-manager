package keepercommandersm

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	ksm "keepersecurity.com/keepercommandersm"
)

var (
	MockResponseQueue mockResponseQueue = mockResponseQueue{}
	context           *ksm.Context      = &ksm.Context{}
	Ctx               **ksm.Context     = &context
)

func TestMain(m *testing.M) {
	s := httptest.NewServer(http.HandlerFunc(Handler))
	u, err := url.Parse(s.URL)
	if err != nil {
		log.Fatalln("failed to parse httptest.Server URL:", err)
	}
	http.DefaultClient.Transport = RewriteTransport{URL: u}

	retCode := m.Run()

	os.Exit(retCode)
}

// MockResponse represents a response for the mock server to serve
type MockResponse struct {
	StatusCode int
	Headers    http.Header
	Content    []byte

	Records map[string]interface{}
	Folders map[string]interface{}
	Reason  string
}

func NewMockResponse(content []byte, statusCode int) *MockResponse {
	// Mock a response from Secret Management Service
	mockResponse := MockResponse{
		StatusCode: statusCode,
		Headers:    http.Header{},
		Content:    content,
		Records:    map[string]interface{}{},
		Folders:    map[string]interface{}{},
		Reason:     http.StatusText(statusCode),
	}

	mockResponse.Headers.Add("Server", "keeper")
	mockResponse.Headers.Add("Content-Type", "application/octet-stream")
	mockResponse.Headers.Add("Connection", "keep-alive")
	mockResponse.Headers.Add("X-Frame-Options", "DENY")
	mockResponse.Headers.Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	mockResponse.Headers.Add("X-Content-Type-Options", "nosniff")
	mockResponse.Headers.Add("X-XSS-Protection", "1; mode=block")
	mockResponse.Headers.Add("Expect-CT", "max-age=10, report-uri=\"https://keepersecurity.report-uri.com/r/d/ct/reportOnly\"")
	mockResponse.Headers.Add("Accept-Ranges", "bytes")

	return &mockResponse
}

func (m *MockResponse) Dump(secret []byte) map[string]interface{} {
	folders := []interface{}{}
	for _, folder := range m.Folders {
		fld := folder.(*MockFolder)
		fldDump := fld.Dump(secret)
		folders = append(folders, fldDump)
	}

	records := []interface{}{}
	for _, record := range m.Records {
		rec := record.(*MockRecord)
		recDump := rec.Dump(secret)
		records = append(records, recDump)
	}

	response := map[string]interface{}{
		"encryptedAppKey": "",
		"folders":         folders,
		"records":         records,
	}

	return response
}

func (m *MockResponse) InstanceSetup(context *ksm.Context) {
	// Setup Response instance filled in with mock response message
	// The method requires an instance of *ksm.Context since that information on how to encrypt the response message.

	m.Headers.Add("Date", time.Now().UTC().Format(time.RFC1123))
	// If canned content has not been set, the create content from records/folders.
	if len(m.Content) == 0 {
		jsonStr := ksm.DictToJson(m.Dump(context.ClientKey))
		if content, err := ksm.EncryptAesGcm([]byte(jsonStr), context.TransmissionKey.Key); err == nil {
			m.Content = content
			m.Headers.Add("Content-Length", strconv.Itoa(len(content)))
			m.StatusCode = 200
			m.Reason = "OK"
		} else {
			log.Println("error necrypting paylod " + err.Error())
		}
	}
	// Else return the canned content. This is useful to mock errors that return plain or json text.
}

func (m *MockResponse) AddRecord(title, recordType, uid string, record *MockRecord, keeperRecord *ksm.Record) *MockRecord {
	if keeperRecord != nil {
		record = ConvertKeeperRecord(keeperRecord)
	} else if record == nil {
		record = NewMockRecord(recordType, uid, title)
	}
	m.Records[record.Uid] = record
	return record
}

func (m *MockResponse) AddFolder(uid string, folder *MockFolder) *MockFolder {
	if folder == nil {
		folder = NewMockFolder(uid)
	}
	m.Folders[folder.Uid] = folder
	return folder
}

// Queue up responses
// The is a FIFO queue. The queue can be loaded with mock Response instance that
// will be shift off when a request to GetResponse called.
type mockResponseQueue struct {
	queue []*MockResponse
}

func (q *mockResponseQueue) AddMockResponse(r *MockResponse) {
	if r == nil {
		log.Panicln("attempt to add nil MockResponse")
	}
	q.queue = append(q.queue, r)
}
func (q *mockResponseQueue) GetMockResponse(context *ksm.Context) *MockResponse {
	var rs *MockResponse = nil
	if len(q.queue) > 0 {
		rs = q.queue[0]
		q.queue = q.queue[1:]
	} else {
		log.Panicln("Not enough queued responses. Cannot get response.")
	}

	return rs
}

func Handler(w http.ResponseWriter, r *http.Request) {
	rs := MockResponseQueue.GetMockResponse(*Ctx)
	rs.InstanceSetup(*Ctx)
	for key, values := range rs.Headers {
		w.Header().Set(key, values[0])
	}
	if rs.StatusCode > 0 {
		w.WriteHeader(rs.StatusCode)
	}
	w.Write(rs.Content)
}

func NewMockHtpServer(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(Handler))
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal("failed to parse httptest.Server URL:", err)
	}
	http.DefaultClient.Transport = RewriteTransport{URL: u}
	return s
}

func TestMockHtpServer(t *testing.T) {
	MockResponseQueue.AddMockResponse(NewMockResponse([]byte("TEST"), 200))
	if resp, err := http.Get("https://127.0.0.1/test"); err != nil {
		t.Fatal("failed to send first request:", err)
	} else if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "TEST" {
		t.Fatal("failed to read first request:", err)
	}
}

type RewriteTransport struct {
	Transport http.RoundTripper
	URL       *url.URL
}

func (t RewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// note that url.URL.ResolveReference doesn't work here since t.u is an absolute url
	req.URL.Scheme = t.URL.Scheme
	req.URL.Host = t.URL.Host
	req.URL.Path = path.Join(t.URL.Path, req.URL.Path)
	rt := t.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(req)
}

func GetRandomUid() (uid string, err error) {
	blk := make([]byte, 16)
	_, err = rand.Read(blk)
	uid = fmt.Sprintf("%x", blk)
	return
}

type MockFolder struct {
	Uid     string
	Records map[string]interface{}
}

func NewMockFolder(uid string) *MockFolder {
	if strings.TrimSpace(uid) == "" {
		uid, _ = GetRandomUid()
	}
	return &MockFolder{
		Uid:     uid,
		Records: map[string]interface{}{},
	}
}

func (f *MockFolder) AddRecord(title, recordType, uid string, record *MockRecord) *MockRecord {
	if record == nil {
		record = NewMockRecord(recordType, uid, title)
	}
	f.Records[record.Uid] = record
	return record
}

func (f *MockFolder) Dump(secret []byte) map[string]interface{} {
	encFolderKey, _ := ksm.EncryptAesGcm(secret, secret)
	folderKey := ksm.BytesToBase64(encFolderKey)

	records := []interface{}{}
	for _, record := range f.Records {
		rec := record.(*MockRecord)
		recDump := rec.Dump(secret)
		records = append(records, recDump)
	}

	dict := map[string]interface{}{
		"folderUid": f.Uid,
		"folderKey": folderKey,
		"records":   records,
	}

	return dict
}

type MockFile struct {
	Uid          string
	SecretUsed   []byte
	Name         string
	Title        string
	ContentType  string
	Url          string
	Content      []byte
	Size         int
	LastModified int
}

func NewMockFile(name, title, contentType, url string, content []byte, lastModified int) *MockFile {
	uid, _ := GetRandomUid()
	if title == "" {
		title = name
	}
	if contentType == "" {
		contentType = "text/plain"
	}
	if url == "" {
		url = "http://localhost/" + uid
	}
	if len(content) == 0 {
		content = []byte("ABC123")
	}
	if lastModified == 0 {
		lastModified = int(time.Now().Unix())
	}
	return &MockFile{
		Uid:          uid,
		SecretUsed:   []byte{},
		Name:         name,
		Title:        title,
		ContentType:  contentType,
		Url:          url,
		Content:      content,
		Size:         len(content),
		LastModified: lastModified,
	}
}

func (f *MockFile) DownloadableContent() []byte {
	// The dump method will generate the content that the secret manager would return. The
	// problem is we won't know the secret here. So the dump method needs to be run before
	// this method is called. The dump method will set the last/only secret used. We need to
	// encode the content with that secret.
	if len(f.SecretUsed) == 0 {
		log.Panicln("The file has not be dump'd yet, Secret is unknown.")
	}
	content, _ := ksm.EncryptAesGcm(f.Content, f.SecretUsed)
	return content
}

func (f *MockFile) Dump(secret []byte) map[string]interface{} {
	f.SecretUsed = secret

	d := map[string]interface{}{
		"name":         f.Name,
		"title":        f.Title,
		"size":         f.Size,
		"lastModified": f.LastModified,
		"type":         f.ContentType,
	}

	data := ksm.DictToJson(d)
	encData, _ := ksm.EncryptAesGcm([]byte(data), secret)
	recordData := ksm.BytesToBase64(encData)

	encFileKey, _ := ksm.EncryptAesGcm(secret, secret)
	fileKey := ksm.BytesToBase64(encFileKey)

	fileData := map[string]interface{}{
		"fileUid":      f.Uid,
		"fileKey":      fileKey,
		"data":         recordData,
		"url":          f.Url,
		"thumbnailUrl": "",
	}

	return fileData
}

type MockRecord struct {
	Uid          string
	RecordType   string
	Title        string
	IsEditable   bool
	Files        map[string]interface{}
	Fields       map[string]interface{}
	CustomFields map[string]map[string]interface{}
}

func NewMockRecord(recordType, uid, title string) *MockRecord {
	if strings.TrimSpace(uid) == "" {
		uid, _ = GetRandomUid()
	}
	if strings.TrimSpace(recordType) == "" {
		recordType = "login"
	}

	// Some default data
	fields := map[string]interface{}{
		"login":    "Login " + uid,
		"password": "******** " + uid,
		"url":      "http://localhost/" + uid,
	}

	return &MockRecord{
		Uid:          uid,
		RecordType:   recordType,
		Title:        title,
		IsEditable:   false,
		Files:        map[string]interface{}{},
		Fields:       fields,
		CustomFields: map[string]map[string]interface{}{},
	}
}

func ConvertKeeperRecord(keeperRecord *ksm.Record) *MockRecord {
	mockRecord := MockRecord{
		Uid:          keeperRecord.Uid,
		RecordType:   keeperRecord.Type(),
		Title:        keeperRecord.Title(),
		IsEditable:   false,
		Files:        map[string]interface{}{},
		Fields:       map[string]interface{}{},
		CustomFields: map[string]map[string]interface{}{},
	}

	if iFields, ok := keeperRecord.RecordDict["fields"]; ok {
		if aFields, ok := iFields.([]interface{}); ok {
			for _, fmap := range aFields {
				if fld, ok := fmap.(map[string]interface{}); ok {
					ftype, _ := fld["type"].(string)
					fval := []interface{}{}
					if fv, ok := fld["value"].([]interface{}); ok {
						fval = fv
					} else {
						fval = append(fval, fv)
					}
					mockRecord.Field(ftype, fval)
				}
			}
		}
	}

	if iFields, ok := keeperRecord.RecordDict["custom"]; ok {
		if aFields, ok := iFields.([]interface{}); ok {
			for _, fmap := range aFields {
				if fld, ok := fmap.(map[string]interface{}); ok {
					flabel, _ := fld["label"].(string)
					ftype, _ := fld["type"].(string)
					fval := []interface{}{}
					if fv, ok := fld["value"].([]interface{}); ok {
						fval = fv
					} else {
						fval = append(fval, fv)
					}
					mockRecord.CustomField(flabel, ftype, fval)
				}
			}
		}
	}

	// # TODO - Add files
	return &mockRecord
}

func (r *MockRecord) Field(fieldType string, value interface{}) {
	if _, ok := value.([]interface{}); !ok {
		value = []interface{}{value}
	}
	r.Fields[fieldType] = value
}

func (r *MockRecord) CustomField(label, fieldType string, value interface{}) {
	if fieldType == "" {
		fieldType = "text"
	}
	if _, ok := value.([]interface{}); !ok {
		value = []interface{}{value}
	}
	if _, ok := r.CustomFields[label]; !ok {
		r.CustomFields[label] = map[string]interface{}{}
	}
	r.CustomFields[label][fieldType] = value
}

func (r *MockRecord) AddFile(name, title, contentType, url string, content []byte, lastModified int) *MockFile {
	file := NewMockFile(name, title, contentType, url, content, lastModified)
	r.Files[file.Uid] = file
	return file
}

func (r *MockRecord) Dump(secret []byte) map[string]interface{} {
	fields := []interface{}{}
	custom := []interface{}{}
	files := []interface{}{}

	if len(r.Files) > 0 {
		fileUids := []string{}
		for _, file := range r.Files {
			f := file.(*MockFile)
			fileUids = append(fileUids, f.Uid)
			files = append(files, f.Dump(secret))
		}
		fields = append(fields, map[string]interface{}{
			"type":  "fileRef",
			"value": fileUids,
		})
	}

	for fieldType, field := range r.Fields {
		fields = append(fields, map[string]interface{}{
			"type":  fieldType,
			"value": field,
		})
	}

	for label := range r.CustomFields {
		for fieldType, field := range r.CustomFields[label] {
			custom = append(custom, map[string]interface{}{
				"type":  fieldType,
				"label": label,
				"value": field,
			})
		}
	}

	dataMap := map[string]interface{}{
		"title":  r.Title,
		"type":   r.RecordType,
		"fields": fields,
		"custom": custom,
	}
	jsonData := ksm.DictToJson(dataMap)
	encData, _ := ksm.EncryptAesGcm([]byte(jsonData), secret)
	recordData := ksm.BytesToBase64(encData)

	recKey, _ := ksm.EncryptAesGcm(secret, secret)
	recordKey := ksm.BytesToBase64(recKey)

	data := map[string]interface{}{
		"recordUid":  r.Uid,
		"recordKey":  recordKey,
		"data":       recordData,
		"isEditable": r.IsEditable,
		"files":      files,
	}

	return data
}
