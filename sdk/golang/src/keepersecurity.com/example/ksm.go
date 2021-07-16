package main

import (
	"fmt"
	"time"

	ksm "keepersecurity.com/keepercommandersm"
	klog "keepersecurity.com/keepercommandersm/logger"
)

func main() {
	klog.SetLogLevel(klog.DebugLevel)
	klog.Info("Secrets Manager Started")

	// server := "https://dev.keepersecurity.com"
	// clientKey := "Qgdoj2QYPiILa4wLxse2wMNhjgs8Ung8ol-WXql1qU0"
	// verifySslCerts := true
	// c := ksm.NewCommanderFromSettings(clientKey, server, verifySslCerts)

	c := ksm.NewCommanderFromConfig(ksm.NewFileKeyValueStorage("client-config.json"))

	allRecords, err := c.GetSecrets([]string{})
	if err != nil {
		klog.Error("error retrieving all records: " + err.Error())
	}

	for _, r := range allRecords {
		klog.Println(r)
		klog.Println("\tPassword: " + r.Password())

		for i, f := range r.Files {
			klog.Printf("\t\tfile #%d -> name: %s", i, f.Name)
			f.SaveFile("/tmp/sm_v2_/_"+f.Name, true)
		}
	}

	recToUpdate := allRecords[0]

	passwordField := map[string]interface{}{}
	if passwordFields := recToUpdate.GetFieldsByType("password"); len(passwordFields) > 0 {
		passwordField = passwordFields[0]
	}

	if len(passwordField) > 0 {
		newPassword := fmt.Sprintf("New Password from SDK Test - " + time.Now().Format(time.RFC850))
		recToUpdate.SetPassword(newPassword)

		updatedRawJson := ksm.DictToJson(recToUpdate.RecordDict)
		recToUpdate.RawJson = updatedRawJson

		if err := c.Save(recToUpdate); err != nil {
			klog.Error("error saving record: " + err.Error())
		}
	} else {
		klog.Error("No password field found in selected record")
	}

	klog.Println("Get only one record")
	if JW_F1_R1, err := c.GetSecrets([]string{"EG6KdJaaLG7esRZbMnfbFA"}); err == nil && len(JW_F1_R1) > 0 {
		klog.Println(JW_F1_R1[0].RawJson)
	} else {
		klog.Println("error retrieveing single record: " + err.Error())
	}

	print("Press [Enter] to exit!")
}
