package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter KSM Server\nPress <Enter> to use keepersecurity.com server: ")
	hostname, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "keepersecurity.com"
	}

	fmt.Print("Enter one time token: ")
	token, _ := reader.ReadString('\n')

	hostname = strings.TrimSpace(hostname)
	token = strings.TrimSpace(token)
	fmt.Printf("%10s[%s]\n", "Hostname: ", hostname)
	fmt.Printf("%10s[%s]\n", "Token: ", token)

	// if your Keeper Account is in other region than US, update the hostname accordingly
	secretsManager := ksm.NewSecretsManagerFromFullSetup(
		token,
		hostname,
		true,
		ksm.NewFileKeyValueStorage("config2.json"))

	if allRecords, err := secretsManager.GetSecrets([]string{}); err != nil {
		fmt.Println("Error retrieving all records: ", err.Error())
	} else if len(allRecords) == 0 {
		fmt.Println("No records found!")
	} else {
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
			if err := secretsManager.Save(recToUpdate); err != nil {
				println("Error saving record: ", err.Error())
			}
		} else {
			println("No password field found in selected record")
		}
	}

	println("Get only one record by UID")
	if foundRecord, err := secretsManager.GetSecrets([]string{"<RECORD UID>"}); err == nil {
		if len(foundRecord) > 0 {
			println(foundRecord[0].RawJson)
		} else {
			println("Record doesn't exist.")
		}
	} else {
		println("Error retrieveing single record: ", err.Error())
	}
}
