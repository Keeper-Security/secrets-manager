package test

import (
	"os"
	"strings"
	"testing"

	ksm "keepersecurity.com/keeper-secrets-manager"
)

func TestTheWorks(t *testing.T) {
	// Perform a simple get_secrets
	// This test is mocked to return 3 record (2 records, 1 folder with a record)
	defer ResetMockResponseQueue()

	rawJson := `
	{
		"server": "fake.keepersecurity.com",
		"appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
		"clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
		"clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
		"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI"
	}
				`
	if f, err := os.CreateTemp("", ""); err == nil {
		defer os.Remove(f.Name())
		if err := os.WriteFile(f.Name(), []byte(rawJson), 0644); err == nil {
			c := ksm.NewCommanderFromConfig(ksm.NewFileKeyValueStorage(f.Name()), Ctx)

			// --------------------------
			// Add three records, 2 outside a folder, 1 inside folder
			res1 := NewMockResponse([]byte{}, 200, nil)
			one := res1.AddRecord("My Record 1", "", "", nil, nil)
			one.Field("login", "My Login 1")
			one.Field("password", "My Password 1")
			one.CustomField("My Custom 1", "text", "custom1")

			// The frontend allows for custom field to not have unique names :(. The best way we
			// can handle this is to set label and field type.
			one.CustomField("My Custom 2", "text", "custom2")
			one.CustomField("My Custom 2", "secret", "my secret")

			two := res1.AddRecord("My Record 2", "", "", nil, nil)
			two.Field("login", "My Login 2")
			two.Field("password", "My Password 2")
			two.AddFile("My File 1", "", "", "", nil, 0)
			two.AddFile("My File 2", "", "", "", nil, 0)

			folder := res1.AddFolder("", nil)
			three := folder.AddRecord("My Record 3", "", "", nil)
			three.Field("login", "My Login 3")
			three.Field("password", "My Password 3")

			// --------------------------
			res2 := NewMockResponse([]byte{}, 200, nil)

			// Use the existing first record of res1
			res2.AddRecord("", "", "", one, nil)

			// --------------------------

			// All records
			MockResponseQueue.AddMockResponse(res1)
			// Single record
			MockResponseQueue.AddMockResponse(res2)
			// Save response
			MockResponseQueue.AddMockResponse(NewMockResponse([]byte{}, 200, nil))

			// --------------------------
			// DO THE WORKS
			records, err := c.GetSecrets([]string{""})
			if err != nil || len(records) != 3 {
				t.Error("didn't get 3 records")
			}

			records, err = c.GetSecrets([]string{one.Uid})
			if err != nil || len(records) != 1 {
				t.Error("didn't get 1 records")
			}
			record := records[0]

			// Test field gets
			if login := record.GetFieldValueByType("login"); login != "My Login 1" {
				t.Error("didn't get the correct login")
			}

			if loginValues := record.GetFieldValuesByType("login"); len(loginValues) != 1 {
				t.Error("didn't find only 1 login")
			} else if loginValues[0] != "My Login 1" {
				t.Error("didn't get the correct login in array")
			}

			// Test custom field gets
			if custom := record.GetCustomFieldValueByLabel("My Custom 1"); custom != "custom1" {
				t.Error("didn't get the correct My Custom 1 value")
			}
			if custom := record.GetCustomFieldValues("My Custom 2", "text"); len(custom) != 1 || custom[0] != "custom2" {
				t.Error("didn't get the correct My Custom 2/text value")
			}
			if custom := record.GetCustomFieldValues("My Custom 2", "secret"); len(custom) != 1 || custom[0] != "my secret" {
				t.Error("didn't get the correct My Custom 2/secret value")
			}

			// Test field sets
			record.SetFieldValueSingle("login", "ABC")
			if login := record.GetFieldValueByType("login"); login != "ABC" {
				t.Error("didn't get the correct login for str")
			}

			// Test custom field sets
			record.SetCustomFieldValueSingle("My Custom 1", "NEW VALUE")
			if custom := record.GetCustomFieldValueByLabel("My Custom 1"); custom != "NEW VALUE" {
				t.Error("didn't get the correct My Custom 1 value after set")
			}

			// SAVE THE RECORD
			c.Save(record)

			// Take the save record and queue it back up as a response.
			savedRes := NewMockResponse([]byte{}, 200, nil)
			savedRes.AddRecord("", "", "", nil, record)
			MockResponseQueue.AddMockResponse(savedRes)

			records, err = c.GetSecrets([]string{record.Uid})
			if err != nil || len(records) != 1 {
				t.Error("didn't get 1 records")
			}
			record = records[0]
			if custom := record.GetCustomFieldValueByLabel("My Custom 1"); custom != "NEW VALUE" {
				t.Error("didn't get the correct My Custom 1 value after write")
			}
		} else {
			t.Error(err.Error())
		}
	} else {
		t.Error(err.Error())
	}
}

func Test403SignatureError(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if msg, ok := r.(string); ok && strings.TrimSpace(msg) == "Error: access_denied, message=Signature is invalid" {
				t.Log("Received expected error code 403 'Signature is invalid'")
			} else {
				t.Error("did not get correct error message")
			}
		}
	}()

	defer ResetMockResponseQueue()
	rawJson := `
{
	"server": "fake.keepersecurity.com",
	"appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
	"clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
	"clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
	"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI"
}`
	config := ksm.NewMemoryKeyValueStorage(rawJson)
	c := ksm.NewCommanderFromConfig(config)

	// Make the error message
	errorJson := `
{
	"path": "https://fake.keepersecurity.com/api/rest/sm/v1/get_secret, POST, python-requests/2.25.1",
	"additional_info": "",
	"location": "default exception manager - api validation exception",
	"error": "access_denied",
	"message": "Signature is invalid"
}`

	MockResponseQueue.AddMockResponse(NewMockResponse([]byte(errorJson), 403, nil))

	if _, err := c.GetSecrets(nil); err != nil && err.Error() == "Error: access_denied, message=Signature is invalid" {
		t.Log("Received expected error code 403 'Signature is invalid'")
	} else {
		t.Error("did not get correct error message")
	}
}

func TestVerifySslCerts(t *testing.T) {
	config := ksm.NewMemoryKeyValueStorage()
	config.Set(ksm.KEY_CLIENT_KEY, "ABC123")

	os.Setenv("KSM_SKIP_VERIFY", "")
	if c := ksm.NewCommanderFromConfig(config); !c.VerifySslCerts {
		t.Error(" VerifySslCerts is not true on 'no args; instance")
	}

	os.Setenv("KSM_SKIP_VERIFY", "")
	if c := ksm.NewCommanderFromFullSetup("1234", "EU", true, config); !c.VerifySslCerts {
		t.Error(" VerifySslCerts is not true on param instance")
	}

	os.Setenv("KSM_SKIP_VERIFY", "")
	if c := ksm.NewCommanderFromFullSetup("1234", "EU", false, config); c.VerifySslCerts {
		t.Error(" VerifySslCerts is not false on param instance")
	}

	os.Setenv("KSM_SKIP_VERIFY", "FALSE")
	if c := ksm.NewCommanderFromConfig(config); !c.VerifySslCerts {
		t.Error(" VerifySslCerts is not false on env set (FALSE)")
	}

	os.Setenv("KSM_SKIP_VERIFY", "NO")
	if c := ksm.NewCommanderFromConfig(config); !c.VerifySslCerts {
		t.Error(" VerifySslCerts is not false on env set (NO)")
	}

	os.Setenv("KSM_SKIP_VERIFY", "True")
	if c := ksm.NewCommanderFromConfig(config); c.VerifySslCerts {
		t.Error(" VerifySslCerts is not true on env set (True)")
	}
}
