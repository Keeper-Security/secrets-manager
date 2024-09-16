using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace SecretsManager
{
    public class KeeperRecordData
    {
        public string title { get; set; }
        public string type { get; set; }
        public KeeperRecordField[] fields { get; set; }
        public KeeperRecordField[] custom { get; set; }
        public string notes { get; set; }
    }

    public class KeeperRecordField
    {
        public string type { get; set; }
        public string label { get; set; }
        public object[] value { get; set; }
        public bool required { get; set; }
        public bool privacyScreen { get; set; }
        public bool enforceGeneration { get; set; }
        public object complexity { get; set; }
    }

    public class KeeperFileData
    {
        public string title { get; set; }
        public string name { get; set; }
        public string type { get; set; }
        public long size { get; set; }
        public long lastModified { get; set; }
    }

    public class KeeperField
    {
        public string type { get; set; }
        public string label { get; set; }
        public static bool IsFieldClass(object field)
        {
            bool result = field switch
            {
                AccountNumber or AddressRef or Addresses or AppFillers or BankAccounts or BirthDate or
                CardRef or Checkbox or DatabaseType or Date or DirectoryType or Dropdown or
                Email or ExpirationDate or FileRef or Hosts or IsSsidHidden or KeyPairs or
                LicenseNumber or Login or Multiline or Names or OneTimeCode or Otp or PamHostname or
                Passkeys or PamRemoteBrowserSettings or PamResources or PamSettings or Password or
                PaymentCards or Phones or PinCode or RbiUrl or RecordRef or Scripts or Schedules or
                Secret or SecureNote or SecurityQuestions or Text or TrafficEncryptionSeed or Url or
                WifiEncryption => true,
                _ => false
            };
            return result;
        }
    }

    public class Login : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public Login(string fieldValue) { type = "login"; value = new List<string> { fieldValue }; }
    }

    public class PasswordComplexity
    {
        public int? length { get; set; }
        public int? caps { get; set; }
        public int? lowercase { get; set; }
        public int? digits { get; set; }
        public int? special { get; set; }
    }

    public class Password : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public bool? enforceGeneration { get; set; }
        public PasswordComplexity complexity { get; set; }
        public List<string> value { get; set; }
        public Password(string fieldValue) { type = "password"; value = new List<string> { fieldValue }; }
    }

    public class Url : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public Url(string fieldValue) { type = "url"; value = new List<string> { fieldValue }; }
    }

    // "file" - obsolete and removed legacy field - "fldt_file": { key: 'file_or_photo', default: "File or Photo" },
    public class FileRef : KeeperField
    {
        public bool? required { get; set; }
        public List<string> value { get; set; }
        public FileRef(string fieldValue) { type = "fileRef"; value = new List<string> { fieldValue }; }
    }

    public class OneTimeCode : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public OneTimeCode(string fieldValue) { type = "oneTimeCode"; value = new List<string> { fieldValue }; }
    }

    public class Otp : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        public Otp(string fieldValue) { type = "otp"; value = new List<string> { fieldValue }; }
    }

    public class Name
    {
        public string first { get; set; }
        public string middle { get; set; }
        public string last { get; set; }
    }

    public class Names : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Name> value { get; set; }
        public Names(Name fieldValue) { type = "name"; value = new List<Name> { fieldValue }; }
    }

    public class BirthDate : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Int64> value { get; set; }
        public BirthDate(Int64 fieldValue) { type = "birthDate"; value = new List<Int64> { fieldValue }; }
    }

    public class Date : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Int64> value { get; set; }
        public Date(Int64 fieldValue) { type = "date"; value = new List<Int64> { fieldValue }; }
    }

    public class ExpirationDate : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Int64> value { get; set; }
        public ExpirationDate(Int64 fieldValue) { type = "expirationDate"; value = new List<Int64> { fieldValue }; }
    }

    public class Text : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public Text(string fieldValue) { type = "text"; value = new List<string> { fieldValue }; }
    }

    public class SecurityQuestion
    {
        public string question { get; set; }
        public string answer { get; set; }
    }

    public class SecurityQuestions : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<SecurityQuestion> value { get; set; }
        public SecurityQuestions(SecurityQuestion fieldValue) { type = "securityQuestion"; value = new List<SecurityQuestion> { fieldValue }; }
    }

    public class Multiline : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public Multiline(string fieldValue) { type = "multiline"; value = new List<string> { fieldValue }; }
    }

    public class Email : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public Email(string fieldValue) { type = "email"; value = new List<string> { fieldValue }; }
    }

    public class CardRef : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public CardRef(string fieldValue) { type = "cardRef"; value = new List<string> { fieldValue }; }
    }

    public class AddressRef : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public AddressRef(string fieldValue) { type = "addressRef"; value = new List<string> { fieldValue }; }
    }

    public class PinCode : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public PinCode(string fieldValue) { type = "pinCode"; value = new List<string> { fieldValue }; }
    }

    public class Phone
    {
        public string region { get; set; }  // Region code. Ex. US
        public string number { get; set; }  // Phone number. Ex. 510-222-5555
        public string ext { get; set; }     // Extension number. Ex. 9987
        public string type { get; set; }    // Phone number type. Ex. Mobile
    }

    public class Phones : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Phone> value { get; set; }
        public Phones(Phone fieldValue) { type = "phone"; value = new List<Phone> { fieldValue }; }
    }

    public class Secret : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public Secret(string fieldValue) { type = "secret"; value = new List<string> { fieldValue }; }
    }

    public class SecureNote : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public SecureNote(string fieldValue) { type = "note"; value = new List<string> { fieldValue }; }
    }

    public class AccountNumber : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public AccountNumber(string fieldValue) { type = "accountNumber"; value = new List<string> { fieldValue }; }
    }

    public class PaymentCard
    {
        public string cardNumber { get; set; }
        public string cardExpirationDate { get; set; }
        public string cardSecurityCode { get; set; }
    }

    public class PaymentCards : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<PaymentCard> value { get; set; }
        public PaymentCards(PaymentCard fieldValue) { type = "paymentCard"; value = new List<PaymentCard> { fieldValue }; }
    }

    public class BankAccount
    {
        public string accountType { get; set; }
        public string routingNumber { get; set; }
        public string accountNumber { get; set; }
        public string otherType { get; set; }
    }

    public class BankAccounts : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<BankAccount> value { get; set; }
        public BankAccounts(BankAccount fieldValue) { type = "bankAccount"; value = new List<BankAccount> { fieldValue }; }
    }

    public class KeyPair
    {
        public string publicKey { get; set; }
        public string privateKey { get; set; }
    }

    public class KeyPairs : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<KeyPair> value { get; set; }
        public KeyPairs(KeyPair fieldValue) { type = "keyPair"; value = new List<KeyPair> { fieldValue }; }
    }

    public class Host
    {
        public string hostName { get; set; }
        public string port { get; set; }
    }

    public class Hosts : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Host> value { get; set; }
        public Hosts(Host fieldValue) { type = "host"; value = new List<Host> { fieldValue }; }
    }

    public class Address
    {
        public string street1 { get; set; }
        public string street2 { get; set; }
        public string city { get; set; }
        public string state { get; set; }
        public string country { get; set; }
        public string zip { get; set; }
    }

    public class Addresses : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Address> value { get; set; }
        public Addresses(Address fieldValue) { type = "address"; value = new List<Address> { fieldValue }; }
    }

    public class LicenseNumber : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }
        public LicenseNumber(string fieldValue) { type = "licenseNumber"; value = new List<string> { fieldValue }; }
    }

    public class RecordRef : KeeperField
    {
        public bool? required { get; set; }
        public List<string> value { get; set; }
        public RecordRef(string fieldValue) { type = "recordRef"; value = new List<string> { fieldValue }; }
    }

    public class Schedule
    {
        public string type { get; set; }
        public string cron { get; set; }
        // utcTime - replaced by time and tz
        public string time { get; set; }
        public string tz { get; set; }
        public string weekday { get; set; }
        public int intervalCount { get; set; }
    }

    public class Schedules : KeeperField
    {
        public bool? required { get; set; }
        public List<Schedule> value { get; set; }
        public Schedules(Schedule fieldValue) { type = "schedule"; value = new List<Schedule> { fieldValue }; }
    }

    public class DirectoryType : KeeperField
    {
        public bool? required { get; set; }
        public List<string> value { get; set; }
        public DirectoryType(string fieldValue) { type = "directoryType"; value = new List<string> { fieldValue }; }
    }

    public class DatabaseType : KeeperField
    {
        public bool? required { get; set; }
        public List<string> value { get; set; }
        public DatabaseType(string fieldValue) { type = "databaseType"; value = new List<string> { fieldValue }; }
    }

    public class Script
    {
        public string fileRef { get; set; }
        public string command { get; set; }
        public List<string> recordRef { get; set; }
    }

    public class PrivateKey
    {
        public string crv { get; set; }
        public string d { get; set; }
        public bool? ext { get; set; }
        public List<string> key_ops { get; set; }
        public string kty { get; set; }
        public string x { get; set; }
        public string y { get; set; }
    }

    public class Passkey
    {
        public PrivateKey privateKey { get; set; }
        public string credentialId { get; set; }
        public long? signCount { get; set; }
        public string userId { get; set; }
        public string relyingParty { get; set; }
        public string username { get; set; }
        public long? createdDate { get; set; }
    }

    public class PamHostname : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Host> value { get; set; }
        public PamHostname(Host fieldValue) { type = "pamHostname"; value = new List<Host> { fieldValue }; }
    }

    public class AllowedSettings
    {
        public bool? connections { get; set; }
        public bool? portForwards { get; set; }
        public bool? rotation { get; set; }
        public bool? sessionRecording { get; set; }
        public bool? typescriptRecording { get; set; }
    }

    public class PamResource
    {
        public string controllerUid { get; set; }
        public string folderUid { get; set; }
        public List<string> resourceRef { get; set; }
        public AllowedSettings allowedSettings { get; set; }
    }

    public class PamResources : KeeperField
    {
        public bool? required { get; set; }
        public List<PamResource> value { get; set; }
        public PamResources(PamResource fieldValue) { type = "pamResources"; value = new List<PamResource> { fieldValue }; }
    }

    public class Checkbox : KeeperField
    {
        public bool? required { get; set; }
        public List<bool> value { get; set; }
        public Checkbox(bool fieldValue) { type = "checkbox"; value = new List<bool> { fieldValue }; }
    }

    public class Scripts : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Script> value { get; set; }
        public Scripts(Script fieldValue) { type = "script"; value = new List<Script> { fieldValue }; }
    }

    public class Passkeys : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Passkey> value { get; set; }
        public Passkeys(Passkey fieldValue) { type = "passkey"; value = new List<Passkey> { fieldValue }; }
    }

    public class IsSsidHidden : KeeperField
    {
        public bool? required { get; set; }
        public List<bool> value { get; set; }
        public IsSsidHidden(bool fieldValue) { type = "isSSIDHidden"; value = new List<bool> { fieldValue }; }
    }

    public class WifiEncryption : KeeperField
    {
        public bool? required { get; set; }
        public List<string> value { get; set; }
        public WifiEncryption(string fieldValue) { type = "wifiEncryption"; value = new List<string> { fieldValue }; }
    }

    public class Dropdown : KeeperField
    {
        public bool? required { get; set; }
        public List<string> value { get; set; }
        public Dropdown(string fieldValue) { type = "dropdown"; value = new List<string> { fieldValue }; }
    }

    public class RbiUrl : KeeperField
    {
        public bool? required { get; set; }
        public List<string> value { get; set; }
        public RbiUrl(string fieldValue) { type = "rbiUrl"; value = new List<string> { fieldValue }; }
    }

    public class AppFiller
    {
        public string applicationTitle { get; set; }
        public string contentFilter { get; set; }
        public string macroSequence { get; set; }
    }

    public class AppFillers : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<AppFiller> value { get; set; }
        public AppFillers(AppFiller fieldValue) { type = "appFiller"; value = new List<AppFiller> { fieldValue }; }
    }

    public class PamRbiConnection
    {
        public string protocol { get; set; }
        public List<string> userRecords { get; set; }
        public bool? allowUrlManipulation { get; set; }
        public string allowedUrlPatterns { get; set; }
        public string allowedResourceUrlPatterns { get; set; }
        public string httpCredentialsUid { get; set; }
        public string autofillConfiguration { get; set; }
    }

    public class PamRemoteBrowserSetting
    {
        public PamRbiConnection connection { get; set; }
    }

    public class PamRemoteBrowserSettings : KeeperField
    {
        public bool? required { get; set; }
        public List<PamRemoteBrowserSetting> value { get; set; }
        public PamRemoteBrowserSettings(PamRemoteBrowserSetting fieldValue) { type = "pamRemoteBrowserSettings"; value = new List<PamRemoteBrowserSetting> { fieldValue }; }
    }

    public class PamSettingsConnection
    {
        public string protocol { get; set; }
        public List<string> userRecords { get; set; }
        public string security { get; set; }
        public bool? ignoreCert { get; set; }
        public string resizeMethod { get; set; }
        public string colorScheme { get; set; }
    }

    public class PamSettingsPortForward
    {
        public bool? reusePort { get; set; }
        public string port { get; set; }
    }

    public class PamSetting
    {
        public List<PamSettingsPortForward> portForward { get; set; }
        public List<PamSettingsConnection> connection { get; set; }
    }

    public class PamSettings : KeeperField
    {
        public bool? required { get; set; }
        public List<PamSetting> value { get; set; }
        public PamSettings(PamSetting fieldValue) { type = "pamSettings"; value = new List<PamSetting> { fieldValue }; }
    }

    public class TrafficEncryptionSeed : KeeperField
    {
        public bool? required { get; set; }
        public List<string> value { get; set; }
        public TrafficEncryptionSeed(string fieldValue) { type = "trafficEncryptionSeed"; value = new List<string> { fieldValue }; }
    }

    // List of retired field types:
    // trafficEncryptionKey - replaced by trafficEncryptionSeed
    // pamProvider - deprecated for legacy/internal use only
    // controller - deprecated for legacy/internal use only
}
