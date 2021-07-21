package test

import (
	"os"
	"strings"
	"testing"

	ksm "keepersecurity.com/keeper-secrets-manager"
)

func TestMissingConfig(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			expectedMsg := "Cannot find the client key in the configuration file."
			if msg, ok := r.(string); !ok || strings.TrimSpace(msg) != expectedMsg {
				t.Error("did not get correct exception message.")
			}
		}
	}()

	// Attempt to load a missing config file.

	// Attempt to get instance without config file. This should fail since the directory will not contain
	// any config file and there are no env vars to use.
	if curWD, err := os.Getwd(); err == nil {
		defer os.Chdir(curWD) // Fix for Windows cleanup error ...being used by another process
	}
	tempDirName := t.TempDir()
	if err := os.Chdir(tempDirName); err == nil {
		c := ksm.NewCommander()
		t.Errorf("Found config file, should be missing. Config is empty: %t", c.Config.IsEmpty())
	} else {
		t.Error(err.Error())
	}
}

func TestDefaultLoadFromJson(t *testing.T) {
	// Load config from default location and name.

	defaultConfigName := ksm.DEFAULT_CONFIG_PATH

	// Make instance using default config file.
	// Create a JSON config file and store under the default file name.
	// This will pass because the JSON file exists.
	if curWD, err := os.Getwd(); err == nil {
		defer os.Chdir(curWD) // Fix for Windows cleanup error ...being used by another process
	}
	tempDirName := t.TempDir()
	if err := os.Chdir(tempDirName); err == nil {
		rawJson := `
{
"server": "fake.keepersecurity.com",
"appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
"clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
"clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI"
}
		`
		if err := os.WriteFile(defaultConfigName, []byte(rawJson), 0644); err == nil {
			c := ksm.NewCommander()
			if c.Config.Get(ksm.KEY_SERVER) != "fake.keepersecurity.com" {
				t.Error("did not get correct server")
			}
			if c.Config.Get(ksm.KEY_APP_KEY) != "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw" {
				t.Error("did not get correct app key")
			}
		} else {
			t.Error(err.Error())
		}
	} else {
		t.Error(err.Error())
	}
}

func TestOverwriteViaArgs(t *testing.T) {
	// Load config from default location and name, but overwrite the client key and server

	defaultConfigName := ksm.DEFAULT_CONFIG_PATH

	// Make instance using default config file.
	// Create a JSON config file and store under the default file name.
	// This will pass because the JSON file exists.
	if curWD, err := os.Getwd(); err == nil {
		defer os.Chdir(curWD) // Fix for Windows cleanup error ...being used by another process
	}
	tempDirName := t.TempDir()
	if err := os.Chdir(tempDirName); err == nil {
		rawJson := `
{
"appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
"clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
"clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI"
}
		`
		if err := os.WriteFile(defaultConfigName, []byte(rawJson), 0644); err == nil {
			// Pass in the client key and server
			c := ksm.NewCommanderFromSettings("ABC123", "localhost", true)
			if c.Config.Get(ksm.KEY_SERVER) != "localhost" {
				t.Error("did not get correct server")
			}
			if c.Config.Get(ksm.KEY_CLIENT_KEY) != "ABC123" {
				t.Error("did not get correct client key")
			}
		} else {
			t.Error(err.Error())
		}
	} else {
		t.Error(err.Error())
	}
}

func TestPassInConfig(t *testing.T) {
	defaultConfigName := ksm.DEFAULT_CONFIG_PATH

	// Make instance using default config file.
	// Create a JSON config file and store under the default file name.
	// This will pass because the JSON file exists.
	if curWD, err := os.Getwd(); err == nil {
		defer os.Chdir(curWD) // Fix for Windows cleanup error ...being used by another process
	}
	tempDirName := t.TempDir()
	if err := os.Chdir(tempDirName); err == nil {
		config := ksm.NewFileKeyValueStorage()
		config.Set(ksm.KEY_CLIENT_KEY, "MY CLIENT KEY")
		config.Set(ksm.KEY_CLIENT_ID, "MY CLIENT ID")
		config.Set(ksm.KEY_APP_KEY, "MY APP KEY")
		config.Set(ksm.KEY_PRIVATE_KEY, "MY PRIVATE KEY")

		if ok, err := ksm.PathExists(defaultConfigName); !ok {
			t.Error("config file is missing. " + err.Error())
		}

		dictConfig := config.ReadStorage()

		if val, ok := dictConfig[string(ksm.KEY_CLIENT_KEY)]; !ok || val != "MY CLIENT KEY" {
			t.Error("did not get correct client key")
		}
		if val, ok := dictConfig[string(ksm.KEY_CLIENT_ID)]; !ok || val != "MY CLIENT ID" {
			t.Error("did not get correct client id")
		}
		if val, ok := dictConfig[string(ksm.KEY_APP_KEY)]; !ok || val != "MY APP KEY" {
			t.Error("did not get correct app key")
		}
		if val, ok := dictConfig[string(ksm.KEY_PRIVATE_KEY)]; !ok || val != "MY PRIVATE KEY" {
			t.Error("did not get correct private key")
		}

		// Pass in the config
		c := ksm.NewCommanderFromConfig(config)

		if c.Config.Get(ksm.KEY_CLIENT_KEY) != "MY CLIENT KEY" {
			t.Error("did not get correct client key")
		}

		// Is not bound, client id and private key will be generated and overwrite existing
		if c.Config.Get(ksm.KEY_CLIENT_ID) == "" {
			t.Error("did not get a client id")
		}
		if c.Config.Get(ksm.KEY_PRIVATE_KEY) == "" {
			t.Error("did not get a private key")
		}

		// App key should be removed.
		if c.Config.Get(ksm.KEY_APP_KEY) != "" {
			t.Error("found the app key")
		}
	} else {
		t.Error(err.Error())
	}
}

func TestInMemoryConfig(t *testing.T) {
	config := ksm.NewMemoryKeyValueStorage()
	config.Set(ksm.KEY_CLIENT_KEY, "MY CLIENT KEY")
	config.Set(ksm.KEY_CLIENT_ID, "MY CLIENT ID")
	config.Set(ksm.KEY_APP_KEY, "MY APP KEY")
	config.Set(ksm.KEY_PRIVATE_KEY, "MY PRIVATE KEY")

	dictConfig := config.ReadStorage()

	if val, ok := dictConfig[string(ksm.KEY_CLIENT_KEY)]; !ok || val != "MY CLIENT KEY" {
		t.Error("did not get correct client key")
	}
	if val, ok := dictConfig[string(ksm.KEY_CLIENT_ID)]; !ok || val != "MY CLIENT ID" {
		t.Error("did not get correct client id")
	}
	if val, ok := dictConfig[string(ksm.KEY_APP_KEY)]; !ok || val != "MY APP KEY" {
		t.Error("did not get correct app key")
	}
	if val, ok := dictConfig[string(ksm.KEY_PRIVATE_KEY)]; !ok || val != "MY PRIVATE KEY" {
		t.Error("did not get correct private key")
	}

	// Pass in the config
	c := ksm.NewCommanderFromConfig(config)

	if c.Config.Get(ksm.KEY_CLIENT_KEY) != "MY CLIENT KEY" {
		t.Error("did not get correct client key")
	}

	// Is not bound, client id and private key will be generated and overwrite existing
	if c.Config.Get(ksm.KEY_CLIENT_ID) == "" {
		t.Error("did not get a client id")
	}
	if c.Config.Get(ksm.KEY_PRIVATE_KEY) == "" {
		t.Error("did not get a private key")
	}

	// App key should be removed.
	if c.Config.Get(ksm.KEY_APP_KEY) != "" {
		t.Error("found the app key")
	}
}
