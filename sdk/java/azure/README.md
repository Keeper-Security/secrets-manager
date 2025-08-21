# Azure Key Vault 

Protect Secrets Manager connection details with Azure Key Vault

Keeper Secrets Manager integrates with Azure Key Vault in order to provide protection for Keeper Secrets Manager configuration files. With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

# Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with Azure Key Vault
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection.  Works with all Keeper Secrets Manager Java/Kotlin SDK functionality

# Prerequisites

* Supports the Java/Kotlin Secrets Manager SDK.
* Requires Azure packages: azure-identity and azure-keyvault-keys.
* Works with just RSA key types with `WrapKey` and `UnWrapKey` permissions.

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
    implementation("com.azure:azure-identity:1.15.0")
    implementation("com.azure:azure-security-keyvault-keys:4.9.2")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2")
	implementation("com.fasterxml.jackson.core:jackson-core:2.18.2")
	implementation("com.google.code.gson:gson:2.12.1")
    implementation("org.slf4j:slf4j-api:1.7.32"){
        exclude("org.slf4j:slf4j-log4j12")
    }
	implementation("ch.qos.logback:logback-classic:1.2.6")
	implementation("ch.qos.logback:logback-core:1.2.6")
	implementation("org.bouncycastle:bc-fips:1.0.2.4")
}
```

  </details> 
  <details> <summary>Maven</summary>

 ```
 		 <!-- KMS-core -->	
		 <dependency>
		  <groupId>com.keepersecurity.secrets-manager</groupId>
		  <artifactId>core</artifactId>
		  <version>[17.0.0,)</version>
		</dependency>
		
		 <!-- Azure-identity -->
		<dependency>
		    <groupId>com.azure</groupId>
		    <artifactId>azure-identity</artifactId>
		    <version>1.15.0</version>
		    <scope>compile</scope>
		</dependency>
		
		 <!-- Azure-keyvault -->
		<dependency>
		    <groupId>com.azure</groupId>
		    <artifactId>azure-security-keyvault-keys</artifactId>
		    <version>4.9.2</version>
		</dependency>

		<!--gson -->
		<dependency>
		    <groupId>com.google.code.gson</groupId>
		    <artifactId>gson</artifactId>
		    <version>2.12.1</version>
		</dependency>

		<!--jackson-core -->
		<dependency>
			<groupId>com.fasterxml.jackson.core</groupId>
			<artifactId>jackson-core</artifactId>
			<version>2.18.2</version>
		</dependency>
		
		<!--jackson-databind -->
		<dependency>
			<groupId>com.fasterxml.jackson.core</groupId>
			<artifactId>jackson-core</artifactId>
			<version>2.18.2</version>
		</dependency>
		
		<!-- slf4j-api -->
		<dependency>
			<groupId>org.slf4j</groupId>
			<artifactId>slf4j-api</artifactId>
			<version>1.7.32</version>
			<scope>runtime</scope>
		</dependency>

		<!-- logback-classic -->
		<dependency>
			<groupId>ch.qos.logback</groupId>
			<artifactId>logback-classic</artifactId>
			<version>1.2.6</version>
			<scope>compile</scope>
		</dependency>

		<!-- logback-core -->
		<dependency>
			<groupId>ch.qos.logback</groupId>
			<artifactId>logback-core</artifactId>
			<version>1.2.6</version>
			<scope>compile</scope>
		</dependency>
		
		<!-- bc-fips -->
		<dependency>
    		<groupId>org.bouncycastle</groupId>
    		<artifactId>bc-fips</artifactId>
    		<version>1.0.2.4</version>
		</dependency>

```
   </details> 
  
  
** Configure Azure Connection **

Initilaizes AzureKeyValueStorage

        key_id URI of the master key - if missing read from env KSM_AZ_KEY_ID
        key_id URI may also include version in case key has auto rotate enabled
        ex. key_id = "https://<vault_name>.vault.azure.net/keys/<key_name>/<key_version>"
        The master key needs WrapKey, UnwrapKey privileges

        config_file_location provides custom config file location - if missing read from env KSM_CONFIG_FILE
        az_session_config optional az session config - if missing use default env variables
        https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential
        
Configuration variables can be provided as 

```
    import com.keepersecurity.secretsManager.core.KeyValueStorage;
    import com.keepersecurity.secretmanager.azurekv.AzureSessionConfig;
    import com.keepersecurity.secretmanager.azurekv.AzureKeyValueStorage;
    
    String tenant_id="<Tenant ID>" 
    String client_id="<Client ID>"
    String client_secret="<Client Secret>"
    String azure_keyvault_url="<Azure Key Vault URL>"
    AzureSessionConfig azureSessionConfig = new AzureSessionConfig(tenant_id, client_id, client_secret, azure_keyvault_url)
```

An access key using the `AzureSessionConfig` data class and providing `tenant_id`,`client_id` ,`client_secret` and `azure_keyvault_url` variables.

You will need an Azure App directory App to use the Azure Key Vault integration.


For more information on Azure App Directory App registration and Permissions see the Azure documentation: https://learn.microsoft.com/en-us/azure/key-vault/general/authentication

**Add Azure Key Vault Storage to Your Code**

Now that the Azure connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use AzureKeyValueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an Azure Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by Azure Key Vault.

```

import java.security.Security;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import static com.keepersecurity.secretsManager.core.SecretsManager.initializeStorage;
import com.keepersecurity.secretmanager.azurekv.AzureKeyValueStorage;
import com.keepersecurity.secretmanager.azurekv.AzureSessionConfig;
import com.keepersecurity.secretsManager.core.KeeperSecrets;
import com.keepersecurity.secretsManager.core.SecretsManager;
import com.keepersecurity.secretsManager.core.SecretsManagerOptions;
public class Test {
	
	public static void main(String args[]) throws Exception {
		String oneTimeToken = "[One_Time_Token]";
		String keyId = "https://<vault-name>.vault.azure.net/keys/<keyname>/<keyversion>";
		String configFileLocation="client_config_test.json";
		String azTenantId = "<tenant-id>";
		String azClientId = "<client-id>";
		String azClientSecret = "<client-secret>";
		String keyVaultUrl = "https://<vault-name>.vault.azure.net/";
		String updatedKeyID = "https://<vault-name>.vault.azure.net/keys/<keyname>/<keyversion>";
		Security.addProvider(new BouncyCastleFipsProvider()); 
		AzureSessionConfig azConfig= new AzureSessionConfig(azTenantId, azClientId, azClientSecret, keyVaultUrl);
		AzureKeyValueStorage azkvstorage =  AzureKeyValueStorage.getInternalStorage(keyId, configFileLocation, azConfig);
		initializeStorage(azkvstorage, oneTimeToken);
        SecretsManagerOptions options = new SecretsManagerOptions(azkvstorage);
        KeeperSecrets secrets = SecretsManager.getSecrets(options);
		System.out.println("Printing storage: "+azkvstorage.toString());
		
		String plaintext = azkvstorage.decryptConfig(false);
		System.out.println("Decrypt config: "+plaintext);
		String decryptedConfig = azkvstorage.decryptConfig(true);
		System.out.println("Decrypt config: "+decryptedConfig);
		
		boolean isChanged = azkvstorage.changeKey(updatedKeyID);	
		System.out.println("Key is changed: "+isChanged);
		
//        getSecrets(options);
    }
}
```
