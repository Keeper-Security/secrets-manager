package main

import (
	"fmt"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func main() {
	// One time tokens can be used only once - afterwards use the generated config.json
	hostname := "keepersecurity.com"
	token := "<ONE TIME TOKEN>"
	sm := ksm.NewSecretsManagerFromSettings(token, hostname, true)
	// sm := ksm.NewSecretsManagerFromConfig(ksm.NewFileKeyValueStorage("client-config.json"))

	if allRecords, err := sm.GetSecrets([]string{}); err != nil {
		println("Error retrieving all records: ", err.Error())
	} else {
		for _, r := range allRecords {
			println("\tPassword: ", r.Password())
			println("\tRecord details: ", r.RawJson)

			for i, f := range r.Files {
				fmt.Printf("\t\tfile #%d -> name: %s", i, f.Name)
				filePath := "/tmp/" + f.Name
				f.SaveFile(filePath, true)
			}
		}
	}
}
