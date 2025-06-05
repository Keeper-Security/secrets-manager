# GCP KMS Integration

Protect Secrets Manager connection details with GCP KMS

Keeper Secrets Manager integrates with GCP KMS in order to provide protection for Keeper Secrets Manager configuration files. With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

# Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with GCP KMS (Symmetric/Asymmetric Key) 
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager Java/Kotlin SDK functionality

# Prerequisites

* Supports the Java/Kotlin Secrets Manager SDK.
* Requires GCP package: google-cloud-kms.
* Key needs `Encrypt` and `Decrypt` permissions.

# Set Up Authentication
Before using Google Cloud APIs, you must authenticate your Java application. The easiest way to do this is by setting up a service account and downloading a service account key file (JSON). This service account should have the appropriate permissions to interact with the KMS API.

* Go to the Google Cloud Console. 
* Navigate to IAM & Admin → Service Accounts. 
* Create a new service account or select an existing one. 
* Assign the necessary permissions (e.g., Cloud KMS Admin, or Cloud KMS CryptoKey Encrypter/Decrypter). 
* Download the private key JSON file.

You can also set the GOOGLE_APPLICATION_CREDENTIALS environment variable to point to the path of the downloaded key file:

`export GOOGLE_APPLICATION_CREDENTIALS="/path/to/your-service-account-file.json"`

For more detail: https://cloud.google.com/kms/docs/iam

# Permissions
Make sure that the service account you're using has appropriate permissions. Typically, you'll need:

Cloud KMS CryptoKey Encrypter/Decrypter permission for encrypting and decrypting data.
Cloud KMS Key Viewer permission to fetch key details. You can assign these roles via IAM in the Google Cloud Console or using gcloud.


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
	
	implementation ("com.google.cloud:google-cloud-kms:2.62.0")
	implementation ("com.google.auth:google-auth-library-oauth2-http:1.33.1")
	    
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

<!-- gcp-kms -->

	 <dependency>
    	<groupId>com.google.cloud</groupId>
   		 <artifactId>google-cloud-kms</artifactId>
    	<version>2.62.0</version>
	 </dependency>
	 
	<!-- gcp auth -->
	<dependency>
	    <groupId>com.google.auth</groupId>
	    <artifactId>google-auth-library-oauth2-http</artifactId>
	    <version>1.33.1</version>
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
  
  
**Configure GCP Connection**

**Initializes GcpKeyValueStorage**

Configuration variables can be provided as 

    config_file_location provides keeper secret manager config file location - if missing read from env param KSM_CONFIG_FILE
    It can be export like "export KSM_CONFIG_FILE = <Config File location>"
     

GCPSessionConfig is needed to initialize GCPKeyValueStorage. To initialize GCPSessionConfig, You will need an GCP ProjectId, location, KeyRing, keyId and keyVersion to use the GCP KMS integration.
        
```
String projectId = "<GCP project id>";
String location = "<GCP cloud Location>";
String keyRing = "<Key Ring>>";
String keyId = "<Key ID>";  //Symmetric or Asymmetric
String keyVersion ="<Key Version>";
String credentialsPaths = "<credential.json path>";
GcpSessionConfig sessionConfig = new GcpSessionConfig(projectId, location, keyRing, keyId, keyVersion, credentialsPaths);
```
For more information on GCP Configuration see the GCP documentation: https://cloud.google.com/kms/docs/reference/libraries#client-libraries-install-java
 OR
For more information on GCP KMS parameter see the documentation: https://cloud.google.com/kms/docs/resource-hierarchy

**Add GCP KMS Storage to Your Code**

Now that the GCP connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use GcpKeyValueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an GCP KeyId and KeyVersion, as well as the name of the Secrets Manager configuration file which will be encrypted by GCP KMS. Below is the sample Test class

```
import java.security.Security;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import static com.keepersecurity.secretsManager.core.SecretsManager.initializeStorage;
import com.keepersecurity.secretsmanager.gcp.GcpKeyValueStorage;
import com.keepersecurity.secretsmanager.gcp.GcpSessionConfig;
import com.keepersecurity.secretsManager.core.SecretsManagerOptions;

public class Test {
	public static void main(String args[]){
			
	    String oneTimeToken = "One_Time_Token";
	    String projectId = "projectId";
	    String location = "cloud_region";
	    String keyRing = "key_ring_name";
	    String keyId = "key_id";  //Symmetric or Asymmetric
	    String keyVersion = "key_version";
	    String configFileLocation = "client_config_test.json";
	    String credentialFileLocation = "path_of_gcp_cred_file.json";
	   // Used for change_key 
          String updatedKeyId = "updated_key_id"; 
	   Security.addProvider(new BouncyCastleFipsProvider());
		try{
				GcpSessionConfig sessionConfig = new GcpSessionConfig(projectId, location, keyRing, updatedKeyId, keyVersion, credentialFileLocation);
				GcpKeyValueStorage storage = new GcpKeyValueStorage(configFileLocation, sessionConfig);
				initializeStorage(storage, oneTimeToken);
				SecretsManagerOptions options = new SecretsManagerOptions(storage);	
				boolean isChanged = storage.changeKey(keyId);
				System.out.println("Key Changed: "+isChanged);
				
				String plaintext = storage.decryptConfig(false);
				System.out.println(plaintext);

				System.out.println("Saving the decrypt config into file");
				String plainText = storage.decryptConfig(true);
				
				//getSecrets(OPTIONS);
		}catch (Exception e) {
				  System.out.println(e.getMessage());
		}
	}
}
			
```
