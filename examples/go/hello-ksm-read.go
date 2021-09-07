package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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
	secretsManager := ksm.NewSecretsManagerFromFullSetup(token, hostname, true, nil)

	if allRecords, err := secretsManager.GetSecrets([]string{}); err != nil {
		fmt.Println("Error retrieving all records: ", err.Error())
	} else {
		for _, r := range allRecords {
			// view record data details
			println("\tPassword: ", r.Password())
			println("\tRecord details: ", r.RawJson)

			// view all files in record if present
			for i, f := range r.Files {
				fmt.Printf("\t\t%4d:\t%s\n", i+1, f.Name)
				filePath := "/tmp/" + f.Name
				f.SaveFile(filePath, true)
			}
		}
	}
}
