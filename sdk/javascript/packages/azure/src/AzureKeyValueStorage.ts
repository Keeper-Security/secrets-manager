import { DefaultAzureCredential, ClientSecretCredential } from "@azure/identity";
import { CryptographyClient } from "@azure/keyvault-keys";

// import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { promises as fs } from 'fs';
import { dirname } from 'path';
import { createHash } from 'crypto';
import { KeyValueStorage, platform } from "@keeper-security/secrets-manager-core";
import { AzureSessionConfig } from "./AzureSessionConfig";
import { decryptBuffer, encryptBuffer } from "./utils";
import { getLogger } from "./Logger";
import { DEFAULT_AZURE_CREDENTIAL_ENVIRONMENTAL_VARIABLE, DEFAULT_JSON_INDENT, DEFAULT_LOG_LEVEL, HEX_DIGEST, MD5_HASH } from "./constants";
import { Logger } from "pino";
import { LoggerLogLevelOptions } from "./enum";


export class AzureKeyValueStorage implements KeyValueStorage {

    private defaultConfigFileLocation: string = "client-config.json";
    private keyId!: string;
    private azureCredentials!: ClientSecretCredential | DefaultAzureCredential;
    private cryptoClient!: CryptographyClient;
    private config!: Record<string, string>;
    private lastSavedConfigHash!: string;
    private logger: Logger;
    private configFileLocation: string;

    getString(key: string): Promise<string | undefined> {
        return this.get(key);
    }
    saveString(key: string, value: string): Promise<void> {
        return this.set(key, value);
    }
    async getBytes(key: string): Promise<Uint8Array | undefined> {
        const bytesString = await this.get(key);
        if (bytesString) {
            return Promise.resolve(platform.base64ToBytes(bytesString));
        }
        return Promise.resolve(undefined);
    }
    saveBytes(key: string, value: Uint8Array): Promise<void> {
        const bytesString = platform.bytesToBase64(value);
        return this.set(key, bytesString);
    }

    getObject?<T>(key: string): Promise<T | undefined> {
        return this.getString(key).then((value) => value ? JSON.parse(value) as T : undefined);
    }
    saveObject?<T>(key: string, value: T): Promise<void> {
        const json = JSON.stringify(value);
        return this.saveString(key, json);
    }

    constructor(keyId: string, configFileLocation: string | null, azSessionConfig: AzureSessionConfig | null, logLevel: LoggerLogLevelOptions | null) {
        /** 
        Initilaizes AzureKeyValueStorage

        key_id URI of the master key - if missing read from env variable which resolves to constant 
                            whose value is given by DEFAULT_AZURE_CREDENTIAL_ENVIRONMENTAL_VARIABLE
        key_id URI may also include version in case key has auto rotate enabled
        ex. key_id = "https://<your vault>.vault.azure.net/keys/<key name>/fe4fdcab688c479a9aa80f01ffeac26"
        The master key needs WrapKey, UnwrapKey privileges

        config_file_location provides custom config file location - if missing read from env KSM_CONFIG_FILE
        az_session_config optional az session config - if missing use default env variables
        https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential
        **/
        this.configFileLocation = configFileLocation ?? process.env.KSM_CONFIG_FILE ?? this.defaultConfigFileLocation;
        this.keyId = keyId ?? process.env[DEFAULT_AZURE_CREDENTIAL_ENVIRONMENTAL_VARIABLE];
        this.logger = logLevel == null ? getLogger(DEFAULT_LOG_LEVEL) : getLogger(logLevel);

        if (azSessionConfig) {
            this.logger.debug("validating azure credentials provided and selecting client based on provided credentials");
            const hasAzureSessionConfig = azSessionConfig.tenantId && azSessionConfig.clientId && azSessionConfig.clientSecret;
            if (hasAzureSessionConfig) {
                this.logger.debug("azure credentials provided, selecting ClientSecretCredential");
                this.azureCredentials = new ClientSecretCredential(azSessionConfig.tenantId, azSessionConfig.clientId, azSessionConfig.clientSecret);
            } else {
                this.logger.debug("azure credentials not provided, selecting DefaultAzureCredential");
                this.azureCredentials = new DefaultAzureCredential();
            }
        }
        this.logger.debug("initializing crypto client with key id", this.keyId);
        this.cryptoClient = new CryptographyClient(this.keyId, this.azureCredentials);

        this.lastSavedConfigHash = "";
    }

    async init() {
        await this.loadConfig();
        return this; // Return the instance to allow chaining
    }

    private async loadConfig(): Promise<void> {
        await this.createConfigFileIfMissing();

        try {
            // Read the config file
            let contents: Buffer;
            try {
                contents = await fs.readFile(this.configFileLocation);
                this.logger.info(`Loaded config file ${this.configFileLocation}`);
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
            } catch (err: any) {
                this.logger.error(`Failed to load config file ${this.configFileLocation}: ${err.message}`);
                throw new Error(`Failed to load config file ${this.configFileLocation}`);
            }

            if (contents.length === 0) {
                this.logger.warn(`Empty config file ${this.configFileLocation}, selecting configuration as empty object`);
                contents = Buffer.from("{}");
            }

            // Check if the content is plain JSON
            let config: Record<string, string> | null = null;
            let jsonError;
            let decryptionError = false;
            try {
                const configData = contents.toString();
                config = JSON.parse(configData);
                // Encrypt and save the config if it's plain JSON
                if (config) {
                    this.config = config;
                    await this.saveConfig(config);
                    this.lastSavedConfigHash = createHash(MD5_HASH).update(JSON.stringify(config, Object.keys(config).sort(), DEFAULT_JSON_INDENT)).digest(HEX_DIGEST);
                }
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
            } catch (err: any) {
                jsonError = err;
            }

            if (jsonError) {
                const configJson = await decryptBuffer(this.cryptoClient, contents, this.logger);
                try {
                    config = JSON.parse(configJson);
                    this.config = config ?? {};
                    this.lastSavedConfigHash = createHash(MD5_HASH).update(JSON.stringify(config, Object.keys(this.config).sort(), DEFAULT_JSON_INDENT)).digest(HEX_DIGEST);
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                } catch (err: any) {
                    decryptionError = true;
                    this.logger.error(`Failed to parse decrypted config file: ${err.message}`);
                    throw new Error(`Failed to parse decrypted config file ${this.configFileLocation}`);
                }
            }
            if (jsonError && decryptionError) {
                this.logger.info(`Config file is not a valid JSON file: ${jsonError.message}`);
                throw new Error(`${this.configFileLocation} may contain JSON format problems`);
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            this.logger.error(`Error loading config: ${err.message}`);
            throw err;
        }
    }

    private async saveConfig(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        updatedConfig: Record<string, any> = {},
        force = false
    ): Promise<void> {
        try {
            // Retrieve current config
            const config = this.config || {};
            const configJson = JSON.stringify(config, Object.keys(config).sort(), DEFAULT_JSON_INDENT);
            let configHash = createHash(MD5_HASH).update(configJson).digest(HEX_DIGEST);

            // Compare updatedConfig hash with current config hash
            if (Object.keys(updatedConfig).length > 0) {
                const updatedConfigJson = JSON.stringify(updatedConfig, Object.keys(updatedConfig).sort(), DEFAULT_JSON_INDENT);
                const updatedConfigHash = createHash(MD5_HASH)
                    .update(updatedConfigJson)
                    .digest(HEX_DIGEST);

                if (updatedConfigHash !== configHash) {
                    configHash = updatedConfigHash;
                    this.config = { ...updatedConfig }; // Update the current config
                }
            }

            // Check if saving is necessary
            if (!force && configHash === this.lastSavedConfigHash) {
                this.logger.warn("Skipped config JSON save. No changes detected.");
                return;
            }

            // Ensure the config file exists
            await this.createConfigFileIfMissing();

            // Encrypt the config JSON and write to the file
            const stringifiedConfig = JSON.stringify(this.config, Object.keys(this.config).sort(), DEFAULT_JSON_INDENT);
            const blob = await encryptBuffer(this.cryptoClient, stringifiedConfig, this.logger);
            await fs.writeFile(this.configFileLocation, blob);

            // Update the last saved config hash
            this.lastSavedConfigHash = configHash;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            this.logger.error("Error saving config:", err.message);
        }
    }

    public async decryptConfig(autosave: boolean): Promise<string> {
        let ciphertext: Buffer;
        let plaintext: string = "";

        try {
            // Read the config file
            ciphertext = await fs.readFile(this.configFileLocation);
            if (ciphertext.length === 0) {
                this.logger.warn(`Empty config file ${this.configFileLocation}`);
                return "";
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            this.logger.error(`Failed to load config file ${this.configFileLocation}: ${err.message}`);
            throw new Error(`Failed to load config file ${this.configFileLocation}`);
        }

        try {
            // Decrypt the file contents
            plaintext = await decryptBuffer(this.cryptoClient, ciphertext, this.logger);
            if (plaintext.length === 0) {
                this.logger.error(`Failed to decrypt config file ${this.configFileLocation}`);
            } else if (autosave) {
                // Optionally autosave the decrypted content
                await fs.writeFile(this.configFileLocation, plaintext);
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            this.logger.error(`Failed to write decrypted config file ${this.configFileLocation}: ${err.message}`);
            throw new Error(`Failed to write decrypted config file ${this.configFileLocation}`);
        }

        return plaintext;
    }

    public async changeKey(newKeyId: string): Promise<boolean> {
        const oldKeyId = this.keyId;
        const oldCryptoClient = this.cryptoClient;

        try {
            // Update the key and reinitialize the CryptographyClient
            this.keyId = newKeyId;
            this.cryptoClient = new CryptographyClient(this.keyId, this.azureCredentials);

            await this.saveConfig({}, true);
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (error: any) {
            // Restore the previous key and crypto client if the operation fails
            this.keyId = oldKeyId;
            this.cryptoClient = oldCryptoClient;

            this.logger.error(`Failed to change the key to '${newKeyId}' for config '${this.configFileLocation}': ${error.message}`);
            throw new Error(`Failed to change the key for ${this.configFileLocation}`);
        }
        return true;
    }

    private async createConfigFileIfMissing(): Promise<void> {
        try {
            await fs.access(this.configFileLocation);
            this.logger.info(`Config file already exists at: ${this.configFileLocation.toString()}`);
        } catch {
            this.logger.info(`Config file already exists at: ${this.configFileLocation.toString()}`);
            const dir = dirname(this.configFileLocation);
            try {
                await fs.access(dir);
            } catch {
                await fs.mkdir(dir, { recursive: true });
            }
            // Encrypt an empty configuration and write to the file
            const blob = await encryptBuffer(this.cryptoClient, "{}", this.logger);
            await fs.writeFile(this.configFileLocation, blob);
            this.logger.info(`Config file created at: ${this.configFileLocation.toString()}`);
        }
    }

    public async readStorage(): Promise<Record<string, string>> {
        if (!this.config) {
            await this.loadConfig();
        }
        return Promise.resolve(this.config);
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    public saveStorage(updatedConfig: Record<string, any>): Promise<void> {
        return this.saveConfig(updatedConfig);
    }

    public async get(key: string): Promise<string> {
        const config = await this.readStorage();
        return Promise.resolve(config[key]);
    }

    public async set(key: string, value: string): Promise<void> {
        const config = await this.readStorage();
        config[key] = value;
        await this.saveStorage(config);
    }

    public async delete(key: string): Promise<void> {
        const config = await this.readStorage();

        if (key in Object.keys(config)) {
            this.logger.debug(`Deleting key ${key} from ${this.configFileLocation}`);
            delete config[key];
        } else {
            this.logger.debug(`Key ${key} not found in ${this.configFileLocation}`);
        }
        await this.saveStorage(config);
    }

    public async deleteAll(): Promise<void> {
        await this.readStorage();
        Object.keys(this.config).forEach(key => delete this.config[key]);
        await this.saveStorage({});
    }

    public async contains(key: string): Promise<boolean> {
        const config = await this.readStorage();
        return Promise.resolve(key in Object.keys(config));
    }

    public async isEmpty(): Promise<boolean> {
        const config = await this.readStorage();
        return Promise.resolve(Object.keys(config).length === 0);
    }
}