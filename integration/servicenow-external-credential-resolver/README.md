# MID Server External Credential Resolver for Keeper Secrets Manager
This is the ServiceNow MID Server custom external credential resolver for the Keeper vault credential storage.

# Pre-requisites:
Keeper External Credential Resolver requires JDK 1.8 or newer  
IntelliJ IDEA or any equivalent IDE

> ⚠️ JRE 8 versions prior to u161 require strong cryptography (JCE) to be enabled.
Latest versions of JRE have strong cryptography enabled [by default](https://bugs.openjdk.java.net/browse/JDK-8170157).

# Steps to build
* Clone this repository.
* Import the project in IntelliJ IDEA or any IDE.
* Update MID Server agent path in build.gradle to point to valid MID Server location.
* Update the code in CredentialResolver.java to customize anything.
* Use the following gradle command or IDE (IntelliJ or Eclipse) gradle build option to build the jar:
  > gradle jar  
* keeper-external-credentials-0.1.0.jar will be generated under target folder.

# Steps to install and use Keeper Secrets Manager as external credential resolver

* Make sure that "External Credential Storage" plugin (com.snc.discovery.external_credentials) is installed in your ServiceNow instance.
* Import the keeper-external-credentials-0.1.0.jar file from target folder in ServiceNow instance.
    - Navigate to MID Server – JAR Files
    - Create a New Record by clicking New
    - Name it "KeeperCredentialResolver", version 0.1.0 and attach keeper-external-credentials-0.1.0.jar from target folder.
    - Click Submit
* Update the _config.xml_ in MID Server with following parameters and restart the MID Server.  
  `<parameter name="ext.cred.keeper.ksm_config" secure="true" value="<ksm-config-base64-string>"/>`  
  _To create new KSM configuration follow [this tutorial](https://docs.keeper.io/secrets-manager/secrets-manager/about/secrets-manager-configuration#creating-a-secrets-manager-configuration)_
* Create Credential in the instance with "External credential store" flag activated.
* Ensure that the "Credential ID" matches a record UID in your Keeper vault.
* Ensure that the record in the vault contains fields matching the ServiceNow credential record fields - ex. record _type=login_ or any record type with custom fields of _type=hidden_ or _type=text_ with labels matching with the column names in discovery_credential table, where each label is prefixed with  "mid_" (ex. GCP Credential requires a record with two custom fields labelled: mid_email and mid_secret_key)

# Finding records
Credential ID (credId parameter) passed from MID Server to Credential Resolver must be either a valid record UID (22 alphanumeric characters incl. "-" and "_") or in the following format type:title. The second format allows searches by type only or by title only (or both, but single ":" is invalid combination)
> ⚠️ When using `type:title` format for the credential make sure there's only one matching record, since multiple matches result in error.

> ⚠️ We recommend using record UID - first to guarantee uniqueness, second to avoid downloading all records with every single request to do a local search by type/title (due to zero knowledge nature of the keeper vault).

#### Examples:
_(zero or two or more matches result in an error)_  
Find by Record UID - `ABCDABCDABCDABCDABCDAB`  
Find by type and title - `login:MyLogin`  
Find by title - `:MyLogin`  
Find by type - `login:`

# Mapping fields
Keeper record types are dynamic and easy to customize, but there are no specific record types matching corresponding credential types in ServiceNow. Keeper External Credential Resolver uses custom field labels to match record data with MID Server's table columns (`discovery_credential` _table_) just label all required custom fields to match the table columns for a given credential type and prefix that label with "mid_" _(see below how to configure custom prefix)_  
Credential types that require username/password should use Login records, and add any custom fields required by the credential type - ex. type=hidden label="mid_pkey"  
Any other types that may not have username/password it is best to use File/Photo records which don't have any standard fields that makes it easier to navigate the custom fields.  

To change the custom field labels prefix update the _config.xml_ in MID Server with the parameters below and restart the MID Server.
  `<parameter name="ext.cred.keeper.ksm_label_prefix" value="mid_"/>`

> ️ⓘ Use custom fields with type `text`, `multiline` or `hidden` depending on the visibility you want in your Keeper Vault.

> ⚠️ When Login record type is used any custom fields for username/password are ignored _(even if properly labeled mid_user, mid_pswd)_ as these values always come from the Login record type standard fields - Login/Password.

#### Examples:  
 + Credential type `jdbc` map to Keeper record type `Login` (using standard Login/Password field)
 + Credential type `api_key` map to Keeper record type `Login` and manually add custom fields with of type `hidden` with labels `mid_ssh_private_key`, and `mid_ssh_passphrase` (_optional_)
 + Credential type `gcp` map to Keeper record type `File Attachment/Photo` and manually add the required custom fields `mid_email` - _text_, `mid_secret_key` - _hidden_.   

When used with **"External credential store"** option output values must conform to IExternalCredential interface from `snc-automation-api.jar` (values start with VAL_ prefix).
Currently supported values - should be prefixed with `mid_` in Keeper records to be extracted (Utah: _user, pswd, passphrase, pkey, authprotocol, authkey, privprotocol, privkey, secret_key, client_id, tenant_id, email_)

When used as Custom External Credential Resolver any field could be mapped **if properly prefixed** in Keeper vault and present in corresponding credential type. 
The credential map returned from the resolve method is expected to have keys matching with the column names in discovery_credential table _ex. sn_cfg_ansible, sn_disco_certmgmt_certificate_ca, cfg_chef_credentials, etc._

# Throttles and cache
The plugin will try to resolve _"throttled"_ errors by default by adding a random delays and retrying later, which works well for up to 1000-3000 requests per 10 sec interval (throttles start after 300-600 requests/10 sec) If you expect 5000+ requests in less than 10 seconds we recommend to enable caching by setting `ext.cred.keeper.use_ksm_cache` parameter to `"true"` in _config.xml_ and restarting the MID Server. Cached data is stored in an encrypted file `ksm_cache.dat` in MID Server's work folder. Cache is updated at most once every 5 minutes or with the next request.

# Troubleshooting
### Check the logs
Check the log files inside `logs/` in the agent installation folder for logs and errors. The resolver logs a line for each credential ID that it successfully queries, and also logs the fields that the credentials were extracted from.

If a particular credential ID is failing, search for that ID in the logs, and check that it is successfully queried and that the credentials were extracted from the fields you expected.

You will also find any exceptions that the resolver throws in the logs, including errors locating a record or finding fields, or if it couldn't communicate with Keeper vault.

### Use the Test credential feature
When creating or configuring a credential in the ServiceNow UI, you should be able to click "Test credential" to perform a quick targeted test. Select the MID server that should query Keeper vault, and select a target that the credential should work for to check that everything works as expected. If it doesn't, check the logs for errors and debug information as detailed above.