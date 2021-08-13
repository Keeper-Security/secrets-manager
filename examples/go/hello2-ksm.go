package main

import (
	"os"
	"time"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func main() {
	// One time tokens can be used only once - afterwards use the generated config.json
	hostname := "keepersecurity.com"
	token := "<ONE TIME TOKEN>"
	sm := ksm.NewSecretsManagerFromSettings(token, hostname, true)
	// sm := ksm.NewSecretsManagerFromConfig(ksm.NewFileKeyValueStorage("client-config.json"))

	allRecords, err := sm.GetSecrets([]string{})
	if err != nil {
		println("Error retrieving all records: ", err.Error())
		os.Exit(1)
	}

	// Get first record
	recToUpdate := allRecords[0]

	// Get first field in a record of type password
	passwordField := map[string]interface{}{}
	if passwordFields := recToUpdate.GetFieldsByType("password"); len(passwordFields) > 0 {
		passwordField = passwordFields[0]
	}

	if len(passwordField) > 0 {
		newPassword := "New Password from hello world - " + time.Now().Format(time.RFC850)
		recToUpdate.SetPassword(newPassword)

		updatedRawJson := ksm.DictToJson(recToUpdate.RecordDict)
		recToUpdate.RawJson = updatedRawJson

		// Perform save operation
		if err := sm.Save(recToUpdate); err != nil {
			println("Error saving record: ", err.Error())
		}
	} else {
		println("No password field found in selected record")
	}

	println("Get only one record by UID")
	if foundRecord, err := sm.GetSecrets([]string{"<RECORD UID>"}); err == nil {
		if len(foundRecord) > 0 {
			println(foundRecord[0].RawJson)
		} else {
			println("Record doesn't exist.")
		}
	} else {
		println("Error retrieveing single record: ", err.Error())
	}
}
