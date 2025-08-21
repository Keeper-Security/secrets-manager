export const DEBUG = process.env['NODE_ENV'] === 'development';

export const EXTENSION_NAME = 'Keeper Security';
export const EXTENSION_ID = 'ks-vscode';
export const CONFIG_NAMESPACE = 'keeper-security';

const makeCommand = (command: string): string => `${EXTENSION_ID}.${command}`;

export const COMMANDS = {
  AUTHENTICATE: makeCommand('authenticate'),
  SAVE_VALUE_TO_VAULT: makeCommand('saveValueToVault'),
  GET_VALUE_FROM_VAULT: makeCommand('getValueFromVault'),
  GENERATE_PASSWORD: makeCommand('generatePassword'),
  RUN_SECURELY: makeCommand('runSecurely'),
  CHOOSE_FOLDER: makeCommand('chooseFolder'),
  OPEN_LOGS: makeCommand('openLogs'),
};

export const KEEPER_NOTATION_PATTERNS = {
  BASIC: /^keeper:\/\/([^\/]+)\/(type|title|notes)$/,
  FILE: /^keeper:\/\/([^\/]+)\/file\/([^\/\[\]]+)$/,
  FIELD:
    /^keeper:\/\/([^\/]+)\/(field|custom_field)\/([^\/\[\]]+)(?:\[([^\]]*)\])?(?:\[([^\]]*)\])?$/,
};

export const KEEPER_COMMANDER_DOCS_URLS = {
  INSTALLATION:
    'https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup',
  AUTHENTICATION:
    'https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup/logging-in',
} as const;

export const HELPER_MESSAGES = {
  OPEN_INSTALLATION_DOCS: 'Open Installation Documentation',
  OPEN_AUTHENTICATION_DOCS: 'Open Authentication Documentation',
  CLI_NOT_INSTALLED:
    'Keeper Commander CLI is not installed. Please install it first.',
  CLI_NOT_AUTHENTICATED:
    'Keeper Commander CLI is not authenticated with persistent login or biometric authentication or Please try again.',
  CLI_READY: 'Keeper Security Extension is ready to use!',
} as const;

export enum KEEPER_NOTATION_FIELD_TYPES {
  CUSTOM_FIELD = 'custom_field',
  FIELD = 'field',
}

// Keeper Record Types (from Commander CLI)
export enum KEEPER_RECORD_TYPES {
  LOGIN = 'login',
  PASSWORD = 'password',
  NOTE = 'note',
  BANK_ACCOUNT = 'bankAccount',
  ADDRESS = 'address',
  PAYMENT_CARD = 'paymentCard',
  DRIVERS_LICENSE = 'driversLicense',
  BIRTH_CERTIFICATE = 'birthCertificate',
  PASSPORT = 'passport',
  SOCIAL_SECURITY = 'socialSecurity',
  WIRELESS_ROUTER = 'wirelessRouter',
  SERVER = 'server',
  DATABASE = 'database',
  API_KEY = 'apiKey',
  SSH_KEY = 'sshKey',
  ENCRYPTION_KEY = 'encryptionKey',
  SOFTWARE_LICENSE = 'softwareLicense',
  MEMBERSHIP = 'membership',
  PASSPORT_RECORD = 'passportRecord',
  SECURE_NOTE = 'secureNote',
  FILE = 'file',
  PAM_MACHINE = 'pamMachine',
  PAM_USER = 'pamUser',
  PAM_CONFIG = 'pamConfig',
  PAM_GATEWAY = 'pamGateway',
  PAM_APP = 'pamApp',
  PAM_ROTATION = 'pamRotation',
  PAM_CONNECTION = 'pamConnection',
  PAM_TUNNEL = 'pamTunnel',
  PAM_SHARE = 'pamShare',
  PAM_APP_SHARE = 'pamAppShare',
  PAM_APP_ROTATION = 'pamAppRotation',
  PAM_APP_CONNECTION = 'pamAppConnection',
  PAM_APP_TUNNEL = 'pamAppTunnel',
  PAM_APP_SHARE_ROTATION = 'pamAppShareRotation',
  PAM_APP_SHARE_CONNECTION = 'pamAppShareConnection',
  PAM_APP_SHARE_TUNNEL = 'pamAppShareTunnel',
  PAM_APP_ROTATION_CONNECTION = 'pamAppRotationConnection',
  PAM_APP_ROTATION_TUNNEL = 'pamAppRotationTunnel',
  PAM_APP_CONNECTION_TUNNEL = 'pamAppConnectionTunnel',
  PAM_APP_SHARE_ROTATION_CONNECTION = 'pamAppShareRotationConnection',
  PAM_APP_SHARE_ROTATION_TUNNEL = 'pamAppShareRotationTunnel',
  PAM_APP_SHARE_CONNECTION_TUNNEL = 'pamAppShareConnectionTunnel',
  PAM_APP_ROTATION_CONNECTION_TUNNEL = 'pamAppRotationConnectionTunnel',
  PAM_APP_SHARE_ROTATION_CONNECTION_TUNNEL = 'pamAppShareRotationConnectionTunnel',
}

// Keeper Field Types (from Commander CLI)
export enum KEEPER_FIELD_TYPES {
  // Basic Types
  TEXT = 'text',
  PASSWORD = 'password',
  URL = 'url',
  EMAIL = 'email',
  LOGIN = 'login',
  NOTE = 'note',
  MULTILINE = 'multiline',
  SECRET = 'secret',
  ONETIME_CODE = 'oneTimeCode',

  // Complex Types
  HOST = 'host',
  ADDRESS = 'address',
  PHONE = 'phone',
  NAME = 'name',
  SECURITY_QUESTION = 'securityQuestion',
  PAYMENT_CARD = 'paymentCard',
  BANK_ACCOUNT = 'bankAccount',
  KEY_PAIR = 'keyPair',

  // Special Types
  FILE = 'file',
  DATE = 'date',

  // PAM Specific
  PAM_HOSTNAME = 'pamHostname',
  PAM_USERNAME = 'pamUsername',
  PAM_PASSWORD = 'pamPassword',
  PAM_CONFIG = 'pamConfig',
  PAM_GATEWAY = 'pamGateway',
  PAM_APP = 'pamApp',
  PAM_ROTATION = 'pamRotation',
  PAM_CONNECTION = 'pamConnection',
  PAM_TUNNEL = 'pamTunnel',
  PAM_SHARE = 'pamShare',
  PAM_APP_SHARE = 'pamAppShare',
  PAM_APP_ROTATION = 'pamAppRotation',
  PAM_APP_CONNECTION = 'pamAppConnection',
  PAM_APP_TUNNEL = 'pamAppTunnel',
  PAM_APP_SHARE_ROTATION = 'pamAppShareRotation',
  PAM_APP_SHARE_CONNECTION = 'pamAppShareConnection',
  PAM_APP_SHARE_TUNNEL = 'pamAppShareTunnel',
  PAM_APP_ROTATION_CONNECTION = 'pamAppRotationConnection',
  PAM_APP_ROTATION_TUNNEL = 'pamAppRotationTunnel',
  PAM_APP_CONNECTION_TUNNEL = 'pamAppConnectionTunnel',
  PAM_APP_SHARE_ROTATION_CONNECTION = 'pamAppShareRotationConnection',
  PAM_APP_SHARE_ROTATION_TUNNEL = 'pamAppShareRotationTunnel',
  PAM_APP_SHARE_CONNECTION_TUNNEL = 'pamAppShareConnectionTunnel',
  PAM_APP_ROTATION_CONNECTION_TUNNEL = 'pamAppRotationConnectionTunnel',
  PAM_APP_SHARE_ROTATION_CONNECTION_TUNNEL = 'pamAppShareRotationConnectionTunnel',
}

// Field Sets (for Commander CLI syntax)
export enum KEEPER_FIELD_SETS {
  FIELD = 'f',
  CUSTOM = 'c',
}

// Common field patterns for detection
export const FIELD_PATTERNS = {
  PASSWORD: /password|passwd|pwd|secret|key/i,
  URL: /url|uri|link|endpoint|api_url|webhook/i,
  EMAIL: /email|mail|e-mail/i,
  LOGIN: /login|username|user|account/i,
  API_KEY: /api_key|apikey|token|access_key|secret_key/i,
  DATABASE: /database|db|connection_string|dsn/i,
  HOST: /host|hostname|server|domain/i,
  PHONE: /phone|mobile|tel|telephone/i,
  ADDRESS: /address|street|city|state|zip/i,
  NAME: /name|first|last|middle|full_name/i,
} as const;

export const DOTENV_LINE =
  /^\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^\n\r#]+)?\s*(?:#.*)?$/;
