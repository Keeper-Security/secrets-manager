# Oracle Key Management
Keeper Secrets Manager integrates with **Oracle Key Vault Management Service (OCI KMS)** to provide protection for Keeper Secrets Manager configuration files. With this integration, you can secure connection details on your machine while leveraging Keeper's **zero-knowledge encryption** for all your secret credentials.

## Features
* Encrypt and decrypt your Keeper Secrets Manager configuration files using **OCI KMS**.
* Protect against unauthorized access to your **Secrets Manager connections**.
* Requires only minor code modifications for immediate protection. Works with all Keeper Secrets Manager **Java/Kotlin SDK** functionality.


## Prerequisites

* Supports the Java/Kotlin Secrets Manager SDK.
* Requires Oracle packages: oci-java-sdk-keymanagement, oci-java-sdk-common and oci-java-sdk-common-httpclient-jersey.
* OCI KMS Key needs `ENCRYPT` and `DECRYPT` permissions.

# Download and Installation
**Install With Gradle or Maven**
	
	
 <details>
  <summary>Gradle</summary>
  
  ```
  repositories {
    mavenCentral()
}

dependencies {
    implementation("com.keepersecurity.secrets-manager:core:17.0.0")
	implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2")
	implementation("com.fasterxml.jackson.core:jackson-core:2.18.2")
	implementation("com.google.code.gson:gson:2.12.1")
    implementation("org.slf4j:slf4j-simple:2.0.16")
	implementation("com.oracle.oci.sdk:oci-java-sdk-keymanagement:3.60.0")
	implementation("com.oracle.oci.sdk:oci-java-sdk-common-httpclient-jersey:3.60.0") // or the latest version
	implementation("com.oracle.oci.sdk:oci-java-sdk-common:3.60.0")
	implementation("org.bouncycastle:bc-fips:1.0.2.4")
}
```

  </details> 
  <details> <summary>Maven</summary>

 ```
<dependencies>
    <dependency>
        <groupId>com.keepersecurity.secrets-manager</groupId>
        <artifactId>core</artifactId>
        <version>17.0.0</version>
    </dependency>
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.18.2</version>
    </dependency>
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-core</artifactId>
        <version>2.18.2</version>
    </dependency>
    <dependency>
        <groupId>com.google.code.gson</groupId>
        <artifactId>gson</artifactId>
        <version>2.12.1</version>
    </dependency>
    <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-simple</artifactId>
        <version>2.0.16</version>
    </dependency>
    <dependency>
        <groupId>com.oracle.oci.sdk</groupId>
        <artifactId>oci-java-sdk-keymanagement</artifactId>
        <version>3.60.0</version>
    </dependency>
    <dependency>
        <groupId>com.oracle.oci.sdk</groupId>
        <artifactId>oci-java-sdk-common-httpclient-jersey</artifactId>
        <version>3.60.0</version>
    </dependency>
    <dependency>
        <groupId>com.oracle.oci.sdk</groupId>
        <artifactId>oci-java-sdk-common</artifactId>
        <version>3.60.0</version>
    </dependency>
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bc-fips</artifactId>
        <version>1.0.2.4</version>
    </dependency>
</dependencies>

```
   </details> 
  
**Configure Oracle Connection**

Initilaizes OracleKeyValueStorage configuration variables can be provided as

```
import com.keepersecurity.secretmanager.oracle.kv.OracleSessionConfig;
import com.oracle.bmc.Region;

String configPath = "</.oci/config>";
String managementEndpoint = "https://<>-management.kms.<>.oraclecloud.com";
String cryptoEndpoint = "https://<>-management.kms.<>.oraclecloud.com";
String vaultId = "ocid1.vault.<>.<>.<>.<>";
String keyId = "ocid1.vault.<>.<>.<>.<>";
String keyVersionId = "ocid1.keyversion.oc1.<>.<>.<>.<>";
String configFileLocation = "ksm_config.json";
String profile = "DEFAULT"; // Set profile name
String oneTimeToken = "US:44XzqbqierM61q-ToqjwblO8p_QwBulpQ_mvuy6KEa0";
String updatedKeyId = "ocid1.keyversion.oc1.<>.<>.<>.<>";
String updatedKeyVersion = "ocid1.keyversion.oc1.<>.<>.<>.<>";
Region region = Region.<Cloud_Region>;
```

An access key using the `OracleSessionConfig` data class and providing `configPath`, `kmsEndpoint`, `vaultId`, `keyId` and `keyVersionId` variables.

You will need an `~/.oci/config` to use the OCI KMS Integration.
Refer the [oracle official documentation](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm)
 for setup. 

**Add Oracle Key Vault Storage to Your Code**

Now that the Oracle connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use OracleKeyValueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require the name of the Secrets Manager configuration file which will be encrypted by Oracle Key Vault.

```
import com.keepersecurity.secretmanager.oracle.kv.OracleSessionConfig;
import  com.keepersecurity.secretmanager.oracle.kv.OracleKeyValueStorage;
import com.keepersecurity.secretsManager.core.SecretsManagerOptions;
		
public class Test {
	public static void main(String[] args) {
        try {
			OracleSessionConfig oracleSessionConfig = new OracleSessionConfig(configPath, cryptoEndpoint, managementEndpoint, vaultId, keyId, keyVersionId, region);
			OracleKeyValueStorage oracleKeyValueStorage = new OracleKeyValueStorage(configFileLocation, profile, oracleSessionConfig);
			initializeStorage(oracleKeyValueStorage, oneTimeToken);
			SecretsManagerOptions options = new SecretsManagerOptions(oracleKeyValueStorage);
			System.out.println("SecretsManagerOptions: "+options.toString());getSecrets(options);	
			boolean isChanged = oracleKeyValueStorage.changeKey(updatedKeyId, updatedKeyVersion);
			System.out.println("Key is Changed: "+isChanged);
			String plaintext = oracleKeyValueStorage.decryptConfig(false);
			System.out.println("Plaintext: "+plaintext);
			oracleKeyValueStorage.decryptConfig(true);
			System.out.println("Config is decrypted");
		} catch (Exception e) {
			System.out.println("Exception raised: "+e.getMessage());
		}
    }
}
```
