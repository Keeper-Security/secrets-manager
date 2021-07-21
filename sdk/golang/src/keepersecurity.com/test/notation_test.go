package test

import (
	"fmt"
	"strings"
	"testing"

	ksm "keepersecurity.com/keeper-secrets-manager"
)

func generateMockresponse(uid string) *MockResponse {
	res1 := NewMockResponse([]byte{}, 200, nil)
	one := res1.AddRecord("My Record 1", "", uid, nil, nil)
	one.Field("login", "My Login 1")
	one.Field("password", "My Password 1")
	one.CustomField("My Custom 1", "text", "custom1")

	// The frontend allows for custom field to not have unique names :(. The best way we
	// can handle this is to set label and field type.
	one.CustomField("My Custom 1", "text", "custom1")
	one.CustomField("My Custom 2", "text", []interface{}{"one", "two", "three"})

	phoneData := []interface{}{
		map[string]string{"number": "555-5555555", "ext": "55"},
		map[string]string{"number": "777-7777777", "ext": "77"},
		map[string]string{"number": "888-8888888", "ext": "", "type": "Home"},
		map[string]string{"number": "999-9999999", "type": "Work"},
	}
	one.CustomField("phone", "text", phoneData)

	nameData := []interface{}{map[string]string{"first": "Jenny", "middle": "X", "last": "Smith"}}
	one.CustomField("name", "text", nameData)
	return res1
}

func TestGetNotation(t *testing.T) {
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
	config := ksm.NewMemoryKeyValueStorage(rawJson)
	c := ksm.NewCommanderFromConfig(config, Ctx)

	// --------------------------

	// Add the same response for each call
	uid, _ := GetRandomUid()
	for i := 0; i < 14; i++ {
		MockResponseQueue.AddMockResponse(generateMockresponse(uid))
	}

	prefix := c.NotationPrefix()

	// Simple call. With prefix
	success := false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/field/login", prefix, uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "My Login 1" {
			success = true
		}
	}
	if !success {
		t.Error("field login is not correct for simple call w/ prefix")
	}

	// Simple call. Without prefix
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s/field/login", uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "My Login 1" {
			success = true
		}
	}
	if !success {
		t.Error("field login is not correct for simple call w/o prefix")
	}

	// Same call, but specifically telling to return value at index 0
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/field/login[0]", prefix, uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "My Login 1" {
			success = true
		}
	}
	if !success {
		t.Error("field login is not correct for predicate of index 0")
	}

	// There is only 1 value. Asking for second item should throw an error.
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/field/login[1]", prefix, uid)); err != nil && len(value) == 0 {
		if strings.Contains(err.Error(), "value at index") {
			success = true
		}
	}
	if !success {
		t.Error("field login is not correct for predicate of index 0")
	}

	// We should get an array instead of a single value.
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/field/login[]", prefix, uid)); err == nil && len(value) == 1 {
		if vmap, ok := value[0].([]map[string]interface{}); ok && len(vmap) > 0 {
			if val, ok := vmap[0]["value"].([]interface{}); ok && len(val) > 0 {
				if v, ok := val[0].(string); ok && v == "My Login 1" {
					success = true
				}
			}
		}
	}
	if !success {
		t.Error("field login is not correct for array value")
	}

	// Custom field, simple
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/custom_field/My Custom 1", prefix, uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "custom1" {
			success = true
		}
	}
	if !success {
		t.Error("custom field My Custom 1 is not correct")
	}

	// Custom field, only the first
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/custom_field/My Custom 2", prefix, uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "one" {
			success = true
		}
	}
	if !success {
		t.Error("custom field My Custom 2, only the first, is not correct")
	}

	// Custom field, get the second value
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/custom_field/My Custom 2[1]", prefix, uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "two" {
			success = true
		}
	}
	if !success {
		t.Error("custom field My Custom 2, second value, is not correct")
	}

	// Custom field, get the second value
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/custom_field/My Custom 2[]", prefix, uid)); err == nil && len(value) == 1 {
		if vmap, ok := value[0].([]map[string]interface{}); ok && len(vmap) > 0 {
			if val, ok := vmap[0]["value"].([]interface{}); ok && len(val) == 3 && fmt.Sprintf("%v", val) == "[one two three]" {
				success = true
			}
		}
	}
	if !success {
		t.Error("custom field My Custom 2, all value, is not correct")
	}

	// Custom field, get first phone number
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/custom_field/phone[0][number]", prefix, uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "555-5555555" {
			success = true
		}
	}
	if !success {
		t.Error("custom field phone, did not get first home number")
	}

	// Custom field, get second phone number
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/custom_field/phone[1][number]", prefix, uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "777-7777777" {
			success = true
		}
	}
	if !success {
		t.Error("custom field phone, did not get second home number")
	}

	// Custom field, get all of the third phone number
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/custom_field/phone[2]", prefix, uid)); err == nil && len(value) == 1 {
		if vmap, ok := value[0].(map[string]interface{}); ok && len(vmap) > 0 {
			if len(vmap) == 3 && fmt.Sprintf("%v", vmap) == "map[ext: number:888-8888888 type:Home]" {
				success = true
			}
		}
	}
	if !success {
		t.Error("custom field phone, did not get correct dict for third")
	}

	// Custom field, get first name
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/custom_field/name[first]", prefix, uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "Jenny" {
			success = true
		}
	}
	if !success {
		t.Error("custom field name, got the first name")
	}

	// Custom field, get last name
	success = false
	if value, err := c.GetNotation(fmt.Sprintf("%s://%s/custom_field/name[last]", prefix, uid)); err == nil && len(value) == 1 {
		if val, ok := value[0].(string); ok && val == "Smith" {
			success = true
		}
	}
	if !success {
		t.Error("custom field name, got the last name")
	}
}

func TestCommanderCustomField(t *testing.T) {
	// Test how Commander stores custom fields
	defer ResetMockResponseQueue()

	// If no custom fields are added via Commander, the JSON will be missing the "custom" key.
	// Make a record that has no custom fields and see if stuff still works.
	rawJson := `
	{
		"server": "fake.keepersecurity.com",
		"appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
		"clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
		"clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
		"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI"
	}
				`
	config := ksm.NewMemoryKeyValueStorage(rawJson)
	c := ksm.NewCommanderFromConfig(config, Ctx)

	// --------------------------

	// We want to remove the 'custom' key from the JSON
	res1 := NewMockResponse([]byte{}, 200, &MockFlags{PruneCustomFields: true})
	one := res1.AddRecord("My Record 1", "", "", nil, nil)
	one.Field("login", "My Login 1")
	one.Field("password", "My Password 1")
	MockResponseQueue.AddMockResponse(res1)

	res2 := NewMockResponse([]byte{}, 200, &MockFlags{PruneCustomFields: true})
	two := res2.AddRecord("My Record 2", "", "", nil, nil)
	two.Field("login", "My Login 2")
	two.Field("password", "My Password 2")
	MockResponseQueue.AddMockResponse(res2)

	// Make sure the mock worked
	records, err := c.GetSecrets([]string{""})
	if err != nil || len(records) != 1 {
		t.Error("didn't get 1 records")
	}

	record := records[0]
	if cust, ok := record.RecordDict["custom"]; ok {
		if iCust, ok := cust.([]interface{}); !ok || len(iCust) != 0 {
			t.Error("found 'custom' in the JSON, mock failed")
		}
	}
}
