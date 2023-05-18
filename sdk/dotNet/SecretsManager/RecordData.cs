using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace SecretsManager
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class KeeperRecordData
    {
        public string title { get; set; }
        public string type { get; set; }
        public KeeperRecordField[] fields { get; set; }
        public KeeperRecordField[] custom { get; set; }
        public string notes { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
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

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class KeeperFileData
    {
        public string title { get; set; }
        public string name { get; set; }
        public string type { get; set; }
        public long size { get; set; }
        public long lastModified { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class KeeperField
    {
        public string type { get; set; }
        public string label { get; set; }
        public static bool IsFieldClass(object field)
        {
            bool result = field switch
            {
                AccountNumber or AddressRef or Addresses or BankAccounts or BirthDate or
                CardRef or Date or Email or ExpirationDate or FileRef or Hosts or KeyPairs or
                LicenseNumber or Login or Multiline or Names or OneTimeCode or Passkeys or Password or
                PaymentCards or Phones or PinCode or Scripts or Secret or SecureNote or
                SecurityQuestions or Text or Url => true,
                _ => false
            };
            return result;
        }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Login : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // Login field constructor with the single value to eliminate the complexity of the passing List as a value
        public Login(string fieldValue) { type = "login"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class PasswordComplexity
    {
        public int? length { get; set; }
        public int? caps { get; set; }
        public int? lowercase { get; set; }
        public int? digits { get; set; }
        public int? special { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Password : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public bool? enforceGeneration { get; set; }
        public PasswordComplexity complexity { get; set; }
        public List<string> value { get; set; }

        // Password field constructor with the single value to eliminate the complexity of the passing List as a value
        public Password(string fieldValue) { type = "password"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Url : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // Url field constructor with the single value to eliminate the complexity of the passing List as a value
        public Url(string fieldValue) { type = "url"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class FileRef : KeeperField
    {
        public bool? required { get; set; }
        public List<string> value { get; set; }

        // FileRef field constructor with the single value to eliminate the complexity of the passing List as a value
        public FileRef(string fieldValue) { type = "fileRef"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class OneTimeCode : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // OneTimeCode field constructor with the single value to eliminate the complexity of the passing List as a value
        public OneTimeCode(string fieldValue) { type = "oneTimeCode"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Name
    {
        public string first { get; set; }
        public string middle { get; set; }
        public string last { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Names : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Name> value { get; set; }

        // Names field constructor with the single value to eliminate the complexity of the passing List as a value
        public Names(Name fieldValue) { type = "name"; value = new List<Name> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class BirthDate : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Int64> value { get; set; }

        // BirthDate field constructor with the single value to eliminate the complexity of the passing List as a value
        public BirthDate(Int64 fieldValue) { type = "birthDate"; value = new List<Int64> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Date : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Int64> value { get; set; }

        // Date field constructor with the single value to eliminate the complexity of the passing List as a value
        public Date(Int64 fieldValue) { type = "date"; value = new List<Int64> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class ExpirationDate : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Int64> value { get; set; }

        // ExpirationDate field constructor with the single value to eliminate the complexity of the passing List as a value
        public ExpirationDate(Int64 fieldValue) { type = "expirationDate"; value = new List<Int64> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Text : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // Text field constructor with the single value to eliminate the complexity of the passing List as a value
        public Text(string fieldValue) { type = "text"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class SecurityQuestion
    {
        public string question { get; set; }
        public string answer { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class SecurityQuestions : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<SecurityQuestion> value { get; set; }

        // SecurityQuestions field constructor with the single value to eliminate the complexity of the passing List as a value
        public SecurityQuestions(SecurityQuestion fieldValue) { type = "securityQuestion"; value = new List<SecurityQuestion> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Multiline : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // Multiline field constructor with the single value to eliminate the complexity of the passing List as a value
        public Multiline(string fieldValue) { type = "multiline"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Email : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // Email field constructor with the single value to eliminate the complexity of the passing List as a value
        public Email(string fieldValue) { type = "email"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class CardRef : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // CardRef field constructor with the single value to eliminate the complexity of the passing List as a value
        public CardRef(string fieldValue) { type = "cardRef"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class AddressRef : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // AddressRef field constructor with the single value to eliminate the complexity of the passing List as a value
        public AddressRef(string fieldValue) { type = "addressRef"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class PinCode : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // PinCode field constructor with the single value to eliminate the complexity of the passing List as a value
        public PinCode(string fieldValue) { type = "pinCode"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Phone
    {
        public string region { get; set; }  // Region code. Ex. US
        public string number { get; set; }  // Phone number. Ex. 510-222-5555
        public string ext { get; set; }     // Extension number. Ex. 9987
        public string type { get; set; }    // Phone number type. Ex. Mobile
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Phones : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Phone> value { get; set; }

        // Phones field constructor with the single value to eliminate the complexity of the passing List as a value
        public Phones(Phone fieldValue) { type = "phone"; value = new List<Phone> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Secret : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // Secret field constructor with the single value to eliminate the complexity of the passing List as a value
        public Secret(string fieldValue) { type = "secret"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class SecureNote : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // SecureNote field constructor with the single value to eliminate the complexity of the passing List as a value
        public SecureNote(string fieldValue) { type = "note"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class AccountNumber : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // AccountNumber field constructor with the single value to eliminate the complexity of the passing List as a value
        public AccountNumber(string fieldValue) { type = "accountNumber"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class PaymentCard
    {
        public string cardNumber { get; set; }
        public string cardExpirationDate { get; set; }
        public string cardSecurityCode { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class PaymentCards : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<PaymentCard> value { get; set; }

        // PaymentCards field constructor with the single value to eliminate the complexity of the passing List as a value
        public PaymentCards(PaymentCard fieldValue) { type = "paymentCard"; value = new List<PaymentCard> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class BankAccount
    {
        public string accountType { get; set; }
        public string routingNumber { get; set; }
        public string accountNumber { get; set; }
        public string otherType { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class BankAccounts : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<BankAccount> value { get; set; }

        // BankAccounts field constructor with the single value to eliminate the complexity of the passing List as a value
        public BankAccounts(BankAccount fieldValue) { type = "bankAccount"; value = new List<BankAccount> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class KeyPair
    {
        public string publicKey { get; set; }
        public string privateKey { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class KeyPairs : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<KeyPair> value { get; set; }

        // KeyPairs field constructor with the single value to eliminate the complexity of the passing List as a value
        public KeyPairs(KeyPair fieldValue) { type = "keyPair"; value = new List<KeyPair> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Host
    {
        public string hostName { get; set; }
        public string port { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Hosts : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Host> value { get; set; }

        // Hosts field constructor with the single value to eliminate the complexity of the passing List as a value
        public Hosts(Host fieldValue) { type = "host"; value = new List<Host> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Address
    {
        public string street1 { get; set; }
        public string street2 { get; set; }
        public string city { get; set; }
        public string state { get; set; }
        public string country { get; set; }
        public string zip { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Addresses : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Address> value { get; set; }

        // Addresses field constructor with the single value to eliminate the complexity of the passing List as a value
        public Addresses(Address fieldValue) { type = "address"; value = new List<Address> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class LicenseNumber : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<string> value { get; set; }

        // LicenseNumber field constructor with the single value to eliminate the complexity of the passing List as a value
        public LicenseNumber(string fieldValue) { type = "licenseNumber"; value = new List<string> { fieldValue }; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Script
    {
        public string fileRef { get; set; }
        public string command { get; set; }
        public List<string> recordRef { get; set; }
    }
  
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Passkey
    {
        public string privateKey { get; set; }
        public string credentialId { get; set; }
        public long? signCount { get; set; }
        public string userId { get; set; }
        public string relyingParty { get; set; }
        public string username { get; set; }
        public long? createdDate { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Scripts : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Script> value { get; set; }

        // Scripts field constructor with the single value to eliminate the complexity of the passing List as a value
        public Scripts(Script fieldValue) { type = "script"; value = new List<Script> { fieldValue }; }
    }
    
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class Passkeys : KeeperField
    {
        public bool? required { get; set; }
        public bool? privacyScreen { get; set; }
        public List<Passkey> value { get; set; }

        // Passkeys field constructor with the single value to eliminate the complexity of the passing List as a value
        public Passkeys(Passkey fieldValue) { type = "passkey"; value = new List<Passkey> { fieldValue }; }
    }
}
