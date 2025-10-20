// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper Secrets Manager
// Copyright 2024 Keeper Security Inc.
// Contact: sm@keepersecurity.com
//

use crate::{
    config_keys::ConfigKeys,
    custom_error::KSMRError,
    storage::{FileKeyValueStorage, InMemoryKeyValueStorage, KeyValueStorage},
};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

pub enum KvStoreType {
    File(FileKeyValueStorage),
    InMemory(InMemoryKeyValueStorage),
    None,
}

pub struct KeyValueStore {
    store: KvStoreType,
}

impl KeyValueStore {
    pub fn new(store_type: KvStoreType) -> Self {
        KeyValueStore { store: store_type }
    }
}

impl KeyValueStorage for KeyValueStore {
    fn read_storage(&self) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        self.store.read_storage()
    }

    fn save_storage(
        &mut self,
        updated_config: HashMap<ConfigKeys, String>,
    ) -> Result<bool, KSMRError> {
        self.store.save_storage(updated_config)
    }

    fn get(&self, key: ConfigKeys) -> Result<Option<String>, KSMRError> {
        self.store.get(key)
    }

    fn set(
        &mut self,
        key: ConfigKeys,
        value: String,
    ) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        self.store.set(key, value)
    }

    fn delete(&mut self, key: ConfigKeys) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        self.store.delete(key)
    }

    fn delete_all(&mut self) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        self.store.delete_all()
    }

    fn contains(&self, key: ConfigKeys) -> Result<bool, KSMRError> {
        self.store.contains(key)
    }

    fn create_config_file_if_missing(&self) -> Result<(), KSMRError> {
        self.store.create_config_file_if_missing()
    }

    fn is_empty(&self) -> Result<bool, KSMRError> {
        self.store.is_empty()
    }
}

impl Clone for KvStoreType {
    fn clone(&self) -> Self {
        match self {
            KvStoreType::InMemory(inner) => KvStoreType::InMemory((*inner).clone()),
            KvStoreType::File(inner) => KvStoreType::File((*inner).clone()),
            KvStoreType::None => KvStoreType::None,
        }
    }
}

impl KeyValueStorage for KvStoreType {
    fn read_storage(&self) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        match &self {
            KvStoreType::File(file_store) => file_store.read_storage(),
            KvStoreType::InMemory(in_memory_store) => in_memory_store.read_storage(),
            KvStoreType::None => {
                let kv_store = FileKeyValueStorage::new(None);
                match kv_store {
                    Ok(file_store) => file_store.read_storage(),
                    Err(e) => Err(e),
                }
            }
        }
    }

    fn save_storage(
        &mut self,
        updated_config: HashMap<ConfigKeys, String>,
    ) -> Result<bool, KSMRError> {
        match self {
            KvStoreType::File(file_store) => file_store.save_storage(updated_config),
            KvStoreType::InMemory(in_memory_store) => in_memory_store.save_storage(updated_config),
            KvStoreType::None => Err(KSMRError::StorageError("No storage available".to_string())),
        }
    }

    fn get(&self, key: ConfigKeys) -> Result<Option<String>, KSMRError> {
        match &self {
            KvStoreType::File(file_store) => file_store.get(key),
            KvStoreType::InMemory(in_memory_store) => in_memory_store.get(key),
            KvStoreType::None => Ok(None),
        }
    }

    fn set(
        &mut self,
        key: ConfigKeys,
        value: String,
    ) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        match self {
            KvStoreType::File(file_store) => file_store.set(key, value),
            KvStoreType::InMemory(in_memory_store) => in_memory_store.set(key, value),
            KvStoreType::None => Err(KSMRError::StorageError(
                "No storage available when None is type here".to_string(),
            )),
        }
    }

    fn delete(&mut self, key: ConfigKeys) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        match self {
            KvStoreType::File(file_store) => file_store.delete(key),
            KvStoreType::InMemory(in_memory_store) => in_memory_store.delete(key),
            KvStoreType::None => Err(KSMRError::StorageError(
                "No storage available when None is type here".to_string(),
            )),
        }
    }

    fn delete_all(&mut self) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        match self {
            KvStoreType::File(file_store) => file_store.delete_all(),
            KvStoreType::InMemory(in_memory_store) => in_memory_store.delete_all(),
            KvStoreType::None => Err(KSMRError::StorageError(
                "No storage available when None is type here".to_string(),
            )),
        }
    }

    fn contains(&self, key: ConfigKeys) -> Result<bool, KSMRError> {
        match &self {
            KvStoreType::File(file_store) => file_store.contains(key),
            KvStoreType::InMemory(in_memory_store) => in_memory_store.contains(key),
            KvStoreType::None => Ok(false),
        }
    }

    fn create_config_file_if_missing(&self) -> Result<(), KSMRError> {
        match &self {
            KvStoreType::File(file_store) => file_store.create_config_file_if_missing(),
            KvStoreType::InMemory(_) => Ok(()),
            KvStoreType::None => Err(KSMRError::StorageError(
                "No storage available when None is type here".to_string(),
            )),
        }
    }

    fn is_empty(&self) -> Result<bool, KSMRError> {
        match &self {
            KvStoreType::File(file_store) => file_store.is_empty(),
            KvStoreType::InMemory(in_memory_store) => in_memory_store.is_empty(),
            KvStoreType::None => Err(KSMRError::StorageError(
                "No storage available when None is type here".to_string(),
            )),
        }
    }
}

pub enum ValueResult {
    Single(Option<Vec<Value>>),
    Multiple(Vec<Vec<Value>>),
}

pub enum StandardFieldTypeEnum {
    PASSWORD,
    LOGIN,
    URL,
    FILEREF,
    ONETIMEPASSWORD,
    NAMES,
    DATE,
    BIRTHDATE,
    EXPIRATIONDATE,
    TEXT,
    SECURITYQUESTIONS,
    MULTILINE,
    EMAIL,
    CARDREF,
    ADDRESSREF,
    ONETIMECODE,
    PINCODE,
    PHONES,
    SECRET,
    SECURENOTE,
    ACCOUNTNUMBER,
    PAYMENTCARDS,
    BANKACCOUNT,
    KEYPAIRS,
    HOSTS,
    LICENSENUMBER,
    RECORDREF,
    SCHEDULES,
    DIRECTORYTYPE,
    DATABASETYPE,
    PAMHOSTNAME,
    PAMRESOURCES,
    CHECKBOX,
    SCRIPTS,
    PASSKEYS,
    ISSSIDHIDDEN,
    WIFIENCRYPTION,
    DROPDOWN,
    RBIURL,
    APPFILLERS,
    PAMREMOTEBROWSERSETTINGS,
    PAMSETTINGS,
    TRAFFICENCRYPTIONSEED,
    ADDRESS,
    NOTE,
}

impl StandardFieldTypeEnum {
    pub fn get_type(&self) -> &str {
        match self {
            StandardFieldTypeEnum::PASSWORD => "password", // done
            StandardFieldTypeEnum::LOGIN => "login",       // done
            StandardFieldTypeEnum::URL => "url",           // done
            StandardFieldTypeEnum::FILEREF => "fileRef",   // done
            StandardFieldTypeEnum::ONETIMEPASSWORD => "otp", //done
            StandardFieldTypeEnum::NAMES => "name",        //done
            StandardFieldTypeEnum::DATE => "date",         //done
            StandardFieldTypeEnum::BIRTHDATE => "birthDate", //done
            StandardFieldTypeEnum::EXPIRATIONDATE => "expirationDate", //done
            StandardFieldTypeEnum::TEXT => "text",         // done
            StandardFieldTypeEnum::SECURITYQUESTIONS => "securityQuestion",
            StandardFieldTypeEnum::MULTILINE => "multiline", //done
            StandardFieldTypeEnum::EMAIL => "email",         //done
            StandardFieldTypeEnum::CARDREF => "cardRef",     //done
            StandardFieldTypeEnum::ADDRESSREF => "addressRef", //done
            StandardFieldTypeEnum::PINCODE => "pinCode",     // done
            StandardFieldTypeEnum::PHONES => "phone",        // done
            StandardFieldTypeEnum::SECRET => "secret",       // done
            StandardFieldTypeEnum::SECURENOTE => "note",     //done
            StandardFieldTypeEnum::ACCOUNTNUMBER => "accountNumber", //done
            StandardFieldTypeEnum::PAYMENTCARDS => "paymentCard", //done
            StandardFieldTypeEnum::BANKACCOUNT => "bankAccount", //done
            StandardFieldTypeEnum::KEYPAIRS => "keyPair",    //done
            StandardFieldTypeEnum::HOSTS => "host",
            StandardFieldTypeEnum::ADDRESS => "address", //done
            StandardFieldTypeEnum::LICENSENUMBER => "licenseNumber", //done
            StandardFieldTypeEnum::RECORDREF => "recordRef",
            StandardFieldTypeEnum::SCHEDULES => "schedule",
            StandardFieldTypeEnum::DIRECTORYTYPE => "directoryType",
            StandardFieldTypeEnum::DATABASETYPE => "databaseType",
            StandardFieldTypeEnum::PAMHOSTNAME => "pamHostname",
            StandardFieldTypeEnum::PAMRESOURCES => "pamResources",
            StandardFieldTypeEnum::CHECKBOX => "checkbox",
            StandardFieldTypeEnum::SCRIPTS => "script",
            StandardFieldTypeEnum::PASSKEYS => "passkey",
            StandardFieldTypeEnum::ISSSIDHIDDEN => "isSSIDHidden",
            StandardFieldTypeEnum::WIFIENCRYPTION => "wifiEncryption",
            StandardFieldTypeEnum::DROPDOWN => "dropdown",
            StandardFieldTypeEnum::RBIURL => "rbiUrl",
            StandardFieldTypeEnum::APPFILLERS => "appFiller", //done
            StandardFieldTypeEnum::PAMREMOTEBROWSERSETTINGS => "pamRemoteBrowserSettings",
            StandardFieldTypeEnum::PAMSETTINGS => "pamSettings",
            StandardFieldTypeEnum::TRAFFICENCRYPTIONSEED => "trafficEncryptionSeed",
            StandardFieldTypeEnum::ONETIMECODE => "oneTimeCode",
            StandardFieldTypeEnum::NOTE => "note", //KEEP-50-SecureNote
        }
    }
}

pub enum DefaultRecordType {
    Login,
    SecureNote,
    BankCard,
    BankAccounts,
    DatabaseCredentials,
    Addresses,
    BirthCertificate,
    Contact,
    DriverLicense,
    File,
    HealthInsurance,
    Membership,
    Server,
    IdentityCard,
    SoftwareLicense,
    SSHKeys,
}

impl DefaultRecordType {
    ///     Login Record recommended fields : StandardFieldTypeEnum::LOGIN, StandardFieldTypeEnum::password
    ///     SecureNote Records recommended fields : StandardFieldTypeEnum::SECURENOTE
    ///     
    pub fn get_type(&self) -> &str {
        match self {
            DefaultRecordType::Login => "login",
            DefaultRecordType::SecureNote => "encryptedNotes",
            DefaultRecordType::BankCard => "bankCard",
            DefaultRecordType::BankAccounts => "bankAccount",
            DefaultRecordType::DatabaseCredentials => "databaseCredentials",
            DefaultRecordType::Addresses => "address",
            DefaultRecordType::BirthCertificate => "birthCertificate",
            DefaultRecordType::Contact => "contact",
            DefaultRecordType::DriverLicense => "driverLicense",
            DefaultRecordType::File => "file",
            DefaultRecordType::SoftwareLicense => "softwareLicense",
            DefaultRecordType::HealthInsurance => "healthInsurance",
            DefaultRecordType::Membership => "membership",
            DefaultRecordType::Server => "serverCredentials",
            DefaultRecordType::IdentityCard => "ssnCard",
            DefaultRecordType::SSHKeys => "sshKeys",
        }
    }
}

/// Enum representing all the countries in the world.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub enum Country {
    AF, // Afghanistan
    AL, // Albania
    DZ, // Algeria
    AD, // Andorra
    AO, // Angola
    AG, // Antigua and Barbuda
    AR, // Argentina
    AM, // Armenia
    AU, // Australia
    AT, // Austria
    AZ, // Azerbaijan
    BS, // Bahamas
    BH, // Bahrain
    BD, // Bangladesh
    BB, // Barbados
    BY, // Belarus
    BE, // Belgium
    BZ, // Belize
    BJ, // Benin
    BT, // Bhutan
    BO, // Bolivia
    BA, // Bosnia and Herzegovina
    BW, // Botswana
    BR, // Brazil
    BN, // Brunei
    BG, // Bulgaria
    BF, // Burkina Faso
    BI, // Burundi
    KH, // Cambodia
    CM, // Cameroon
    CA, // Canada
    CV, // Cape Verde
    CF, // Central African Republic
    TD, // Chad
    CL, // Chile
    CN, // China
    CO, // Colombia
    KM, // Comoros
    CG, // Congo
    CR, // Costa Rica
    HR, // Croatia
    CU, // Cuba
    CY, // Cyprus
    CZ, // Czech Republic
    DK, // Denmark
    DJ, // Djibouti
    DM, // Dominica
    DO, // Dominican Republic
    TL, // East Timor
    EC, // Ecuador
    EG, // Egypt
    SV, // El Salvador
    GQ, // Equatorial Guinea
    ER, // Eritrea
    EE, // Estonia
    SZ, // Eswatini
    ET, // Ethiopia
    FJ, // Fiji
    FI, // Finland
    FR, // France
    GA, // Gabon
    GM, // Gambia
    GE, // Georgia
    DE, // Germany
    GH, // Ghana
    GR, // Greece
    GD, // Grenada
    GT, // Guatemala
    GN, // Guinea
    GW, // Guinea-Bissau
    GY, // Guyana
    HT, // Haiti
    HN, // Honduras
    HU, // Hungary
    IS, // Iceland
    IN, // India
    ID, // Indonesia
    IR, // Iran
    IQ, // Iraq
    IE, // Ireland
    IL, // Israel
    IT, // Italy
    CI, // Ivory Coast
    JM, // Jamaica
    JP, // Japan
    JO, // Jordan
    KZ, // Kazakhstan
    KE, // Kenya
    KI, // Kiribati
    KP, // Korea North
    KR, // Korea South
    XK, // Kosovo
    KW, // Kuwait
    KG, // Kyrgyzstan
    LA, // Laos
    LV, // Latvia
    LB, // Lebanon
    LS, // Lesotho
    LR, // Liberia
    LY, // Libya
    LI, // Liechtenstein
    LT, // Lithuania
    LU, // Luxembourg
    MG, // Madagascar
    MW, // Malawi
    MY, // Malaysia
    MV, // Maldives
    ML, // Mali
    MT, // Malta
    MH, // Marshall Islands
    MR, // Mauritania
    MU, // Mauritius
    MX, // Mexico
    FM, // Micronesia
    MD, // Moldova
    MC, // Monaco
    MN, // Mongolia
    ME, // Montenegro
    MA, // Morocco
    MZ, // Mozambique
    MM, // Myanmar
    NA, // Namibia
    NR, // Nauru
    NP, // Nepal
    NL, // Netherlands
    NZ, // New Zealand
    NI, // Nicaragua
    NE, // Niger
    NG, // Nigeria
    MK, // North Macedonia
    NO, // Norway
    OM, // Oman
    PK, // Pakistan
    PW, // Palau
    PS, // Palestine
    PA, // Panama
    PG, // Papua New Guinea
    PY, // Paraguay
    PE, // Peru
    PH, // Philippines
    PL, // Poland
    PT, // Portugal
    QA, // Qatar
    RO, // Romania
    RU, // Russia
    RW, // Rwanda
    KN, // Saint Kitts and Nevis
    LC, // Saint Lucia
    VC, // Saint Vincent and the Grenadines
    WS, // Samoa
    SM, // San Marino
    ST, // Sao Tome and Principe
    SA, // Saudi Arabia
    SN, // Senegal
    RS, // Serbia
    SC, // Seychelles
    SL, // Sierra Leone
    SG, // Singapore
    SK, // Slovakia
    SI, // Slovenia
    SB, // Solomon Islands
    SO, // Somalia
    ZA, // South Africa
    SS, // South Sudan
    ES, // Spain
    LK, // Sri Lanka
    SD, // Sudan
    SR, // Suriname
    SE, // Sweden
    CH, // Switzerland
    SY, // Syria
    TW, // Taiwan
    TJ, // Tajikistan
    TZ, // Tanzania
    TH, // Thailand
    TG, // Togo
    TO, // Tonga
    TT, // Trinidad and Tobago
    TN, // Tunisia
    TR, // Turkey
    TM, // Turkmenistan
    TV, // Tuvalu
    UG, // Uganda
    UA, // Ukraine
    AE, // United Arab Emirates
    GB, // United Kingdom
    US, // United States
    UY, // Uruguay
    UZ, // Uzbekistan
    VU, // Vanuatu
    VA, // Vatican
    VE, // Venezuela
    VN, // Vietnam
    YE, // Yemen
    ZM, // Zambia
    ZW, // Zimbabwe
}

impl Country {
    /// Converts a string to a `Country` enum variant.
    pub fn from_string(name: &str) -> Option<Country> {
        match name.to_lowercase().as_str() {
            "afghanistan" => Some(Country::AF),
            "albania" => Some(Country::AL),
            "algeria" => Some(Country::DZ),
            "andorra" => Some(Country::AD),
            "angola" => Some(Country::AO),
            "antigua and barbuda" => Some(Country::AG),
            "argentina" => Some(Country::AR),
            "armenia" => Some(Country::AM),
            "australia" => Some(Country::AU),
            "austria" => Some(Country::AT),
            "azerbaijan" => Some(Country::AZ),
            "bahamas" => Some(Country::BS),
            "bahrain" => Some(Country::BH),
            "bangladesh" => Some(Country::BD),
            "barbados" => Some(Country::BB),
            "belarus" => Some(Country::BY),
            "belgium" => Some(Country::BE),
            "belize" => Some(Country::BZ),
            "benin" => Some(Country::BJ),
            "bhutan" => Some(Country::BT),
            "bolivia" => Some(Country::BO),
            "bosnia and herzegovina" => Some(Country::BA),
            "botswana" => Some(Country::BW),
            "brazil" => Some(Country::BR),
            "brunei" => Some(Country::BN),
            "bulgaria" => Some(Country::BG),
            "burkina faso" => Some(Country::BF),
            "burundi" => Some(Country::BI),
            "cambodia" => Some(Country::KH),
            "cameroon" => Some(Country::CM),
            "canada" => Some(Country::CA),
            "cape verde" => Some(Country::CV),
            "central african republic" => Some(Country::CF),
            "chad" => Some(Country::TD),
            "chile" => Some(Country::CL),
            "china" => Some(Country::CN),
            "colombia" => Some(Country::CO),
            "comoros" => Some(Country::KM),
            "congo" => Some(Country::CG),
            "costa rica" => Some(Country::CR),
            "croatia" => Some(Country::HR),
            "cuba" => Some(Country::CU),
            "cyprus" => Some(Country::CY),
            "czech republic" => Some(Country::CZ),
            "denmark" => Some(Country::DK),
            "djibouti" => Some(Country::DJ),
            "dominica" => Some(Country::DM),
            "dominican republic" => Some(Country::DO),
            "east timor" => Some(Country::TL),
            "ecuador" => Some(Country::EC),
            "egypt" => Some(Country::EG),
            "el salvador" => Some(Country::SV),
            "equatorial guinea" => Some(Country::GQ),
            "eritrea" => Some(Country::ER),
            "estonia" => Some(Country::EE),
            "eswatini" => Some(Country::SZ),
            "ethiopia" => Some(Country::ET),
            "fiji" => Some(Country::FJ),
            "finland" => Some(Country::FI),
            "france" => Some(Country::FR),
            "gabon" => Some(Country::GA),
            "gambia" => Some(Country::GM),
            "georgia" => Some(Country::GE),
            "germany" => Some(Country::DE),
            "ghana" => Some(Country::GH),
            "greece" => Some(Country::GR),
            "grenada" => Some(Country::GD),
            "guatemala" => Some(Country::GT),
            "guinea" => Some(Country::GN),
            "guinea bissau" => Some(Country::GW),
            "guyana" => Some(Country::GY),
            "haiti" => Some(Country::HT),
            "honduras" => Some(Country::HN),
            "hungary" => Some(Country::HU),
            "iceland" => Some(Country::IS),
            "india" => Some(Country::IN),
            "indonesia" => Some(Country::ID),
            "iran" => Some(Country::IR),
            "iraq" => Some(Country::IQ),
            "ireland" => Some(Country::IE),
            "israel" => Some(Country::IL),
            "italy" => Some(Country::IT),
            "ivory coast" => Some(Country::CI),
            "jamaica" => Some(Country::JM),
            "japan" => Some(Country::JP),
            "jordan" => Some(Country::JO),
            "kazakhstan" => Some(Country::KZ),
            "kenya" => Some(Country::KE),
            "kiribati" => Some(Country::KI),
            "north korea" => Some(Country::KP),
            "korea north" => Some(Country::KP),
            "korea south" => Some(Country::KR),
            "south korea" => Some(Country::KR),
            "kosovo" => Some(Country::XK),
            "kuwait" => Some(Country::KW),
            "kyrgyzstan" => Some(Country::KG),
            "laos" => Some(Country::LA),
            "latvia" => Some(Country::LV),
            "lebanon" => Some(Country::LB),
            "lesotho" => Some(Country::LS),
            "liberia" => Some(Country::LR),
            "libya" => Some(Country::LY),
            "liechtenstein" => Some(Country::LI),
            "lithuania" => Some(Country::LT),
            "luxembourg" => Some(Country::LU),
            "madagascar" => Some(Country::MG),
            "malawi" => Some(Country::MW),
            "malaysia" => Some(Country::MY),
            "maldives" => Some(Country::MV),
            "mali" => Some(Country::ML),
            "malta" => Some(Country::MT),
            "marshall islands" => Some(Country::MH),
            "mauritania" => Some(Country::MR),
            "mauritius" => Some(Country::MU),
            "mexico" => Some(Country::MX),
            "micronesia" => Some(Country::FM),
            "moldova" => Some(Country::MD),
            "monaco" => Some(Country::MC),
            "mongolia" => Some(Country::MN),
            "montenegro" => Some(Country::ME),
            "morocco" => Some(Country::MA),
            "mozambique" => Some(Country::MZ),
            "myanmar" => Some(Country::MM),
            "namibia" => Some(Country::NA),
            "nauru" => Some(Country::NR),
            "nepal" => Some(Country::NP),
            "netherlands" => Some(Country::NL),
            "new zealand" => Some(Country::NZ),
            "nicaragua" => Some(Country::NI),
            "niger" => Some(Country::NE),
            "nigeria" => Some(Country::NG),
            "north macedonia" => Some(Country::MK),
            "norway" => Some(Country::NO),
            "oman" => Some(Country::OM),
            "pakistan" => Some(Country::PK),
            "palau" => Some(Country::PW),
            "palestine" => Some(Country::PS),
            "panama" => Some(Country::PA),
            "papua new guinea" => Some(Country::PG),
            "paraguay" => Some(Country::PY),
            "peru" => Some(Country::PE),
            "philippines" => Some(Country::PH),
            "poland" => Some(Country::PL),
            "portugal" => Some(Country::PT),
            "qatar" => Some(Country::QA),
            "romania" => Some(Country::RO),
            "russia" => Some(Country::RU),
            "rwanda" => Some(Country::RW),
            "saint kitts and nevis" => Some(Country::KN),
            "saint lucia" => Some(Country::LC),
            "saint vincent and the grenadines" => Some(Country::VC),
            "samoa" => Some(Country::WS),
            "san marino" => Some(Country::SM),
            "sao tome and principe" => Some(Country::ST),
            "saudi arabia" => Some(Country::SA),
            "senegal" => Some(Country::SN),
            "serbia" => Some(Country::RS),
            "seychelles" => Some(Country::SC),
            "sierra leone" => Some(Country::SL),
            "singapore" => Some(Country::SG),
            "slovakia" => Some(Country::SK),
            "slovenia" => Some(Country::SI),
            "solomon islands" => Some(Country::SB),
            "somalia" => Some(Country::SO),
            "south africa" => Some(Country::ZA),
            "south sudan" => Some(Country::SS),
            "spain" => Some(Country::ES),
            "sri lanka" => Some(Country::LK),
            "sudan" => Some(Country::SD),
            "suriname" => Some(Country::SR),
            "sweden" => Some(Country::SE),
            "switzerland" => Some(Country::CH),
            "syria" => Some(Country::SY),
            "taiwan" => Some(Country::TW),
            "tajikistan" => Some(Country::TJ),
            "tanzania" => Some(Country::TZ),
            "thailand" => Some(Country::TH),
            "togo" => Some(Country::TG),
            "tonga" => Some(Country::TO),
            "trinidad and tobago" => Some(Country::TT),
            "tunisia" => Some(Country::TN),
            "turkey" => Some(Country::TR),
            "turkmenistan" => Some(Country::TM),
            "tuvalu" => Some(Country::TV),
            "uganda" => Some(Country::UG),
            "ukraine" => Some(Country::UA),
            "united arab emirates" => Some(Country::AE),
            "united kingdom" => Some(Country::GB),
            "united states" => Some(Country::US),
            "uruguay" => Some(Country::UY),
            "uzbekistan" => Some(Country::UZ),
            "vanuatu" => Some(Country::VU),
            "vatican" => Some(Country::VA),
            "venezuela" => Some(Country::VE),
            "vietnam" => Some(Country::VN),
            "yemen" => Some(Country::YE),
            "zambia" => Some(Country::ZM),
            "zimbabwe" => Some(Country::ZW),
            _ => None,
        }
    }
}

impl fmt::Display for Country {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let country_name = match *self {
            Country::AF => "Afghanistan",
            Country::AL => "Albania",
            Country::DZ => "Algeria",
            Country::AD => "Andorra",
            Country::AO => "Angola",
            Country::AG => "Antigua and Barbuda",
            Country::AR => "Argentina",
            Country::AM => "Armenia",
            Country::AU => "Australia",
            Country::AT => "Austria",
            Country::AZ => "Azerbaijan",
            Country::BS => "Bahamas",
            Country::BH => "Bahrain",
            Country::BD => "Bangladesh",
            Country::BB => "Barbados",
            Country::BY => "Belarus",
            Country::BE => "Belgium",
            Country::BZ => "Belize",
            Country::BJ => "Benin",
            Country::BT => "Bhutan",
            Country::BO => "Bolivia",
            Country::BA => "Bosnia and Herzegovina",
            Country::BW => "Botswana",
            Country::BR => "Brazil",
            Country::BN => "Brunei",
            Country::BG => "Bulgaria",
            Country::BF => "Burkina Faso",
            Country::BI => "Burundi",
            Country::KH => "Cambodia",
            Country::CM => "Cameroon",
            Country::CA => "Canada",
            Country::CV => "Cape Verde",
            Country::CF => "Central African Republic",
            Country::TD => "Chad",
            Country::CL => "Chile",
            Country::CN => "China",
            Country::CO => "Colombia",
            Country::KM => "Comoros",
            Country::CG => "Congo",
            Country::CR => "Costa Rica",
            Country::HR => "Croatia",
            Country::CU => "Cuba",
            Country::CY => "Cyprus",
            Country::CZ => "Czech Republic",
            Country::DK => "Denmark",
            Country::DJ => "Djibouti",
            Country::DM => "Dominica",
            Country::DO => "Dominican Republic",
            Country::TL => "East Timor",
            Country::EC => "Ecuador",
            Country::EG => "Egypt",
            Country::SV => "El Salvador",
            Country::GQ => "Equatorial Guinea",
            Country::ER => "Eritrea",
            Country::EE => "Estonia",
            Country::SZ => "Eswatini",
            Country::ET => "Ethiopia",
            Country::FJ => "Fiji",
            Country::FI => "Finland",
            Country::FR => "France",
            Country::GA => "Gabon",
            Country::GM => "Gambia",
            Country::GE => "Georgia",
            Country::DE => "Germany",
            Country::GH => "Ghana",
            Country::GR => "Greece",
            Country::GD => "Grenada",
            Country::GT => "Guatemala",
            Country::GN => "Guinea",
            Country::GW => "Guinea Bissau",
            Country::GY => "Guyana",
            Country::HT => "Haiti",
            Country::HN => "Honduras",
            Country::HU => "Hungary",
            Country::IS => "Iceland",
            Country::IN => "India",
            Country::ID => "Indonesia",
            Country::IR => "Iran",
            Country::IQ => "Iraq",
            Country::IE => "Ireland",
            Country::IL => "Israel",
            Country::IT => "Italy",
            Country::CI => "Ivory Coast",
            Country::JM => "Jamaica",
            Country::JP => "Japan",
            Country::JO => "Jordan",
            Country::KZ => "Kazakhstan",
            Country::KE => "Kenya",
            Country::KI => "Kiribati",
            Country::KP => "North Korea",
            Country::KR => "South Korea",
            Country::XK => "Kosovo",
            Country::KW => "Kuwait",
            Country::KG => "Kyrgyzstan",
            Country::LA => "Laos",
            Country::LV => "Latvia",
            Country::LB => "Lebanon",
            Country::LS => "Lesotho",
            Country::LR => "Liberia",
            Country::LY => "Libya",
            Country::LI => "Liechtenstein",
            Country::LT => "Lithuania",
            Country::LU => "Luxembourg",
            Country::MG => "Madagascar",
            Country::MW => "Malawi",
            Country::MY => "Malaysia",
            Country::MV => "Maldives",
            Country::ML => "Mali",
            Country::MT => "Malta",
            Country::MH => "Marshall Islands",
            Country::MR => "Mauritania",
            Country::MU => "Mauritius",
            Country::MX => "Mexico",
            Country::FM => "Micronesia",
            Country::MD => "Moldova",
            Country::MC => "Monaco",
            Country::MN => "Mongolia",
            Country::ME => "Montenegro",
            Country::MA => "Morocco",
            Country::MZ => "Mozambique",
            Country::MM => "Myanmar",
            Country::NA => "Namibia",
            Country::NR => "Nauru",
            Country::NP => "Nepal",
            Country::NL => "Netherlands",
            Country::NZ => "New Zealand",
            Country::NI => "Nicaragua",
            Country::NE => "Niger",
            Country::NG => "Nigeria",
            Country::MK => "North Macedonia",
            Country::NO => "Norway",
            Country::OM => "Oman",
            Country::PK => "Pakistan",
            Country::PW => "Palau",
            Country::PS => "Palestine",
            Country::PA => "Panama",
            Country::PG => "Papua New Guinea",
            Country::PY => "Paraguay",
            Country::PE => "Peru",
            Country::PH => "Philippines",
            Country::PL => "Poland",
            Country::PT => "Portugal",
            Country::QA => "Qatar",
            Country::RO => "Romania",
            Country::RU => "Russia",
            Country::RW => "Rwanda",
            Country::KN => "Saint Kitts and Nevis",
            Country::LC => "Saint Lucia",
            Country::VC => "Saint Vincent and the Grenadines",
            Country::WS => "Samoa",
            Country::SM => "San Marino",
            Country::ST => "Sao Tome and Principe",
            Country::SA => "Saudi Arabia",
            Country::SN => "Senegal",
            Country::RS => "Serbia",
            Country::SC => "Seychelles",
            Country::SL => "Sierra Leone",
            Country::SG => "Singapore",
            Country::SK => "Slovakia",
            Country::SI => "Slovenia",
            Country::SB => "Solomon Islands",
            Country::SO => "Somalia",
            Country::ZA => "South Africa",
            Country::SS => "South Sudan",
            Country::ES => "Spain",
            Country::LK => "Sri Lanka",
            Country::SD => "Sudan",
            Country::SR => "Suriname",
            Country::SE => "Sweden",
            Country::CH => "Switzerland",
            Country::SY => "Syria",
            Country::TW => "Taiwan",
            Country::TJ => "Tajikistan",
            Country::TZ => "Tanzania",
            Country::TH => "Thailand",
            Country::TG => "Togo",
            Country::TO => "Tonga",
            Country::TT => "Trinidad and Tobago",
            Country::TN => "Tunisia",
            Country::TR => "Turkey",
            Country::TM => "Turkmenistan",
            Country::TV => "Tuvalu",
            Country::UG => "Uganda",
            Country::UA => "Ukraine",
            Country::AE => "United Arab Emirates",
            Country::GB => "United Kingdom",
            Country::US => "United States",
            Country::UY => "Uruguay",
            Country::UZ => "Uzbekistan",
            Country::VU => "Vanuatu",
            Country::VA => "Vatican",
            Country::VE => "Venezuela",
            Country::VN => "Vietnam",
            Country::YE => "Yemen",
            Country::ZM => "Zambia",
            Country::ZW => "Zimbabwe",
        };
        write!(f, "{}", country_name)
    }
}
