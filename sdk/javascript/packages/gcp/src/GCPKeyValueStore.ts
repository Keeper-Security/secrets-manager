import { promises as fs } from "fs";
import { dirname, resolve } from "path";
import { createHash } from "crypto";

import {
  KeyValueStorage,
  platform,
} from "@keeper-security/secrets-manager-core";

import { GCPKeyConfig } from "./GcpKeyConfig";
import { GCPKeyValueStorageError } from "./error";
import { GCPKSMClient } from "./GcpKmsClient";
import { KeyPurpose, LoggerLogLevelOptions } from "./enum";
import {
  DEFAULT_JSON_INDENT,
  DEFAULT_LOG_LEVEL,
  HEX_DIGEST,
  MD5_HASH,
  supportedKeyPurpose,
} from "./constants";
import { decryptBuffer, encryptBuffer } from "./utils";
import { getLogger } from "./Logger";
import { KMSClient } from "./interface/UtilOptions";
import { Logger } from "pino";

export class GCPKeyValueStorage implements KeyValueStorage {
  private defaultConfigFileLocation: string = "client-config.json";
  private cryptoClient!: KMSClient;
  private config: Record<string, string> = {};
  private lastSavedConfigHash!: string;
  private logger: Logger;
  private gcpKeyConfig!: GCPKeyConfig;
  private keyType!: string;
  private configFileLocation!: string;
  private gcpSessionConfig: GCPKSMClient;
  private isAsymmetric: boolean = false;
  private encryptionAlgorithm!: string;

  public getString(key: string): Promise<string | undefined> {
    return this.get(key);
  }

  public saveString(key: string, value: string): Promise<void> {
    return this.set(key, value);
  }

  public async getBytes(key: string): Promise<Uint8Array | undefined> {
    const bytesString = await this.get(key);
    if (bytesString) {
      return platform.base64ToBytes(bytesString);
    }
    return undefined;
  }

  public saveBytes(key: string, value: Uint8Array): Promise<void> {
    const bytesString = platform.bytesToBase64(value);
    return this.set(key, bytesString);
  }

  public async delete(key: string): Promise<void> {
    const config = await this.readStorage();

    if (config[key]) {
      this.logger.debug(`Deleting key ${key} from ${this.configFileLocation}`);
      delete config[key];
    } else {
      this.logger.debug(`Key ${key} not found in ${this.configFileLocation}`);
    }
    await this.saveStorage(config);
  }

  public getObject?<T>(key: string): Promise<T | undefined> {
    return this.getString(key).then((value) =>
      value ? (JSON.parse(value) as T) : undefined
    );
  }

  public saveObject?<T>(key: string, value: T): Promise<void> {
    const json = JSON.stringify(value);
    return this.saveString(key, json);
  }

  /**
   * Initializes GCPKeyValueStorage
   *
   * @param {string | null} keyVaultConfigFileLocation Custom config file location.
   *    If null or undefined, reads from env KSM_CONFIG_FILE.
   *    If env KSM_CONFIG_FILE is not set, uses default location.
   * @param {GCPKeyConfig} gcpKeyConfig The configuration for the GCP KMS key.
   * @param {GCPKSMClient} gcpSessionConfig The GCP KMS client session configuration.
   * @param {LoggerLogLevelOptions } logLevel The log level to use for the logger.
   */
  constructor(
    keyVaultConfigFileLocation: string | null,
    gcpKeyConfig: GCPKeyConfig,
    gcpSessionConfig: GCPKSMClient,
    logLevel?: LoggerLogLevelOptions
  ) {
    this.configFileLocation =
      keyVaultConfigFileLocation ??
      process.env.KSM_CONFIG_FILE ??
      this.defaultConfigFileLocation;

    this.logger = logLevel == null ? getLogger(DEFAULT_LOG_LEVEL) : getLogger(logLevel);

    this.gcpSessionConfig = gcpSessionConfig;
    this.gcpKeyConfig = gcpKeyConfig;
    this.cryptoClient = this.gcpSessionConfig.getCryptoClient();

    this.lastSavedConfigHash = "";
  }

  public async init() {
    await this.getKeyDetails();
    await this.loadConfig();
    this.logger.info(`Loaded config file from ${this.configFileLocation}`);
    return this; // Return the instance to allow chaining
  }

  private async getKeyDetails() {
    try {
      const input = {
        name: this.gcpKeyConfig.toKeyName(),
      };
      const [key] = await this.cryptoClient.getCryptoKey(input);
      this.encryptionAlgorithm = key?.versionTemplate?.algorithm?.toString() || "";
      const keyPurposeDetails = key?.purpose?.toString() || "";

      if (!supportedKeyPurpose.includes(keyPurposeDetails)) {
        this.logger.error("Unsupported Key Spec for GCP KMS Storage");
        throw new GCPKeyValueStorageError(
          "Unsupported Key Spec for GCP KMS Storage"
        );
      }

      this.logger.debug(`Key purpose for key provided: ${keyPurposeDetails}`);
      if (keyPurposeDetails === KeyPurpose.ASYMMETRIC_DECRYPT) {
        this.isAsymmetric = true;
      } else {
        this.isAsymmetric = false;
      }
      this.logger.debug(`key is ${this.isAsymmetric ? "asymmetric" : "symmetric"}`);

      this.keyType = keyPurposeDetails;
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error("Failed to get key details:", err.message);
    }
  }

  private async loadConfig(): Promise<void> {
    await this.createConfigFileIfMissing();

    try {
      // Read the config file
      let contents: Buffer;
      try {
        contents = await fs.readFile(this.configFileLocation);
        this.logger.info(`Loaded config file ${this.configFileLocation.toString()}`);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (err: any) {
        this.logger.error(
          `Failed to load config file ${this.configFileLocation.toString()}: ${err.message.toString()}`
        );
        throw new Error(
          `Failed to load config file ${this.configFileLocation.toString()}`
        );
      }

      if (contents.length === 0) {
        this.logger.warn(`Empty config file ${this.configFileLocation.toString()}`);
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
        this.logger.info("given config file is not encrypted, starting encryption");
        if (config) {
          this.config = config;
          await this.saveConfig(config);
          this.lastSavedConfigHash = createHash(MD5_HASH)
            .update(
              JSON.stringify(
                config,
                Object.keys(config).sort(),
                DEFAULT_JSON_INDENT
              )
            )
            .digest(HEX_DIGEST);
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (err: any) {
        this.logger.debug("given file is encrypted file. trying to decrypt the configuration into a json from it");
        jsonError = err;
      }

      if (jsonError) {
        const configJson = await decryptBuffer({
          isAsymmetric: this.isAsymmetric,
          ciphertext: contents,
          cryptoClient: this.cryptoClient,
          keyType: this.keyType,
          encryptionAlgorithm: this.encryptionAlgorithm,
          keyProperties: this.gcpKeyConfig
        }, this.logger);
        this.logger.debug("decrypted configuration, trying to parse decrypted configuration into a json");
        try {
          config = JSON.parse(configJson);
          this.config = config ?? {};
          this.lastSavedConfigHash = createHash(MD5_HASH)
            .update(
              JSON.stringify(
                config,
                Object.keys(this.config).sort(),
                DEFAULT_JSON_INDENT
              )
            )
            .digest(HEX_DIGEST);
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
          decryptionError = true;
          this.logger.error(
            `Failed to parse decrypted config file: ${err.message.toString()}`
          );
          throw new Error(
            `Failed to parse decrypted config file ${this.configFileLocation.toString()}`
          );
        }
      }
      if (jsonError && decryptionError) {
        this.logger.info(
          `Config file is not a valid JSON file: ${jsonError.message.toString()}`
        );
        throw new Error(
          `${this.configFileLocation} may contain JSON format problems`
        );
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error(`Error loading config: ${err.message.toString()}`);
      throw err;
    }
  }

  private async saveConfig(
    updatedConfig: Record<string, string> = {},
    force = false
  ): Promise<void> {
    try {
      // Retrieve current config
      const config = this.config || {};
      const configJson = JSON.stringify(
        config,
        Object.keys(config).sort(),
        DEFAULT_JSON_INDENT
      );
      let configHash = createHash(MD5_HASH)
        .update(configJson)
        .digest(HEX_DIGEST);

      // Compare updatedConfig hash with current config hash
      if (Object.keys(updatedConfig).length > 0) {
        const updatedConfigJson = JSON.stringify(
          updatedConfig,
          Object.keys(updatedConfig).sort(),
          DEFAULT_JSON_INDENT
        );
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
        console.warn("Skipped config JSON save. No changes detected.");
        return;
      }

      // Ensure the config file exists
      await this.createConfigFileIfMissing();

      // Encrypt the config JSON and write to the file
      const stringifiedValue = JSON.stringify(
        this.config,
        Object.keys(this.config),
        DEFAULT_JSON_INDENT
      );
      this.logger.debug("encrypting the config before writing to file.");
      const blob = await encryptBuffer({
        isAsymmetric: this.isAsymmetric,
        message: stringifiedValue,
        cryptoClient: this.cryptoClient,
        keyType: this.keyType,
        encryptionAlgorithm: this.encryptionAlgorithm,
        keyProperties: this.gcpKeyConfig
      }, this.logger);
      await fs.writeFile(this.configFileLocation, blob);
      this.logger.debug("writing to the file completed successfully.");
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
        this.logger.warn(`Empty config file ${this.configFileLocation.toString()}`);
        return "";
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error(
        `Failed to load config file ${this.configFileLocation.toString()}: ${err.message.toString()}`
      );
      throw new GCPKeyValueStorageError(`Failed to load config file ${this.configFileLocation.toString()}`);
    }

    try {
      // Decrypt the file contents
      plaintext = await decryptBuffer({
        isAsymmetric: this.isAsymmetric,
        cryptoClient: this.cryptoClient,
        keyType: this.keyType,
        encryptionAlgorithm: this.encryptionAlgorithm,
        keyProperties: this.gcpKeyConfig,
        ciphertext,
      }, this.logger);
      if (plaintext.length === 0) {
        this.logger.error(
          `Failed to decrypt config file ${this.configFileLocation}`
        );
      } else if (autosave) {
        // Optionally autosave the decrypted content
        this.logger.debug("Autosave is true here. hence saving to file the decrypted configuration.");
        this.logger.warn("Saving the credentials file as plaintext file, please consider encrypting.");
        await fs.writeFile(this.configFileLocation, plaintext);
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error(
        `Failed to write decrypted config file ${this.configFileLocation.toString()}: ${err.message.toString()}`
      );
      throw new Error(
        `Failed to write decrypted config file ${this.configFileLocation.toString()}`
      );
    }
    return plaintext;
  }

  public async changeKey(newGcpKeyConfig: GCPKeyConfig): Promise<boolean> {
    const oldKeyConfiguration = this.gcpKeyConfig;
    const oldCryptoClient = this.cryptoClient;

    try {
      // Update the key and reinitialize the CryptographyClient
      this.logger.debug("Changing key");
      const config = this.config;
      if (Object.keys(config).length == 0) {
        await this.init();
      }
      this.logger.debug("getting new key details");
      this.gcpKeyConfig = newGcpKeyConfig;
      await this.getKeyDetails();
      this.logger.debug("saving config with new key");
      await this.saveConfig({}, true);
      this.logger.info("saving configuration with new key successful");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
      // Restore the previous key and crypto client if the operation fails
      this.gcpKeyConfig = oldKeyConfiguration;
      this.cryptoClient = oldCryptoClient;
      this.logger.error(
        `Failed to change the key to '${newGcpKeyConfig.toString()}' for config '${this.configFileLocation.toString()}': ${error.message.toString()}`
      );
      throw new Error(
        `Failed to change the key for ${this.configFileLocation.toString()}`
      );
    }
    return true;
  }

  private async createConfigFileIfMissing(): Promise<void> {
    try {
      // Ensure the config file path is absolute
      const configPath = resolve(this.configFileLocation);

      // Check if the config file exists
      await fs.access(configPath);
      this.logger.info(`Config file already exists at: ${configPath}`);
    } catch {
      // If file does not exist, proceed to create it

      try {
        const dir = dirname(resolve(this.configFileLocation)); // Ensure absolute directory path

        try {
          await fs.access(dir); // Check if directory exists
        } catch {
          await fs.mkdir(dir, { recursive: true }); // Create directory if missing
        }
      } catch {
        await fs.mkdir(process.cwd(), { recursive: true }); // Use the working directory as fallback
      }

      // Encrypt an empty configuration and write to the file
      const blob = await encryptBuffer({
        isAsymmetric: this.isAsymmetric,
        message: "{}",
        keyType: this.keyType,
        cryptoClient: this.cryptoClient,
        encryptionAlgorithm: this.encryptionAlgorithm,
        keyProperties: this.gcpKeyConfig
      }, this.logger);
      const configPath = resolve(this.configFileLocation);
      await fs.writeFile(configPath, blob);
      this.logger.info(`Config file created at: ${configPath}`);
    }
  }

  private async readStorage(): Promise<Record<string, string>> {
    if (!this.config) {
      this.logger.debug("config is empty, loading configuration");
      await this.loadConfig();
    }
    return Promise.resolve(this.config);
  }

  private saveStorage(updatedConfig: Record<string, string>): Promise<void> {
    return this.saveConfig(updatedConfig);
  }

  private async get(key: string): Promise<string> {
    const config = await this.readStorage();
    return Promise.resolve(config[key]);
  }

  private async set(key: string, value: string): Promise<void> {
    const config = await this.readStorage();
    config[key] = value;
    await this.saveStorage(config);
  }

  private async deleteAll(): Promise<void> {
    await this.readStorage();
    Object.keys(this.config).forEach((key) => delete this.config[key]);
    await this.saveStorage({});
  }

  private async contains(key: string): Promise<boolean> {
    const config = await this.readStorage();
    return Promise.resolve(key in Object.keys(config));
  }

  private async isEmpty(): Promise<boolean> {
    const config = await this.readStorage();
    return Promise.resolve(Object.keys(config).length === 0);
  }
}
