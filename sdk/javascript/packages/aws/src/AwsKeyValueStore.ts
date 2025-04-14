import { promises as fs } from "fs";
import { dirname, resolve } from "path";
import { createHash } from "crypto";

import {
  KeyValueStorage,
  platform,
} from "@keeper-security/secrets-manager-core";
import {
  KMSClient,
  EncryptionAlgorithmSpec,
  DescribeKeyCommand,
  DescribeKeyCommandOutput,
} from "@aws-sdk/client-kms";
import pino from "pino";

import { AWSSessionConfig } from "./AwsSessionConfig";
import { AWSKeyValueStorageError } from "./error";
import { AwsKmsClient } from "./AwsKmsClient";
import { EncryptionAlgorithmEnum, LoggerLogLevelOptions } from "./enum";
import {
  DEFAULT_JSON_INDENT,
  DEFAULT_LOG_LEVEL,
  HEX_DIGEST,
  MD5_HASH,
  supportedKeySpecs,
} from "./constants";
import { decryptBuffer, encryptBuffer } from "./utils";
import { getLogger } from "./Logger";

export class AWSKeyValueStorage implements KeyValueStorage {
  defaultConfigFileLocation: string = "client-config.json";
  keyId!: string;
  cryptoClient!: KMSClient;
  config: Record<string, string> = {};
  lastSavedConfigHash!: string;
  logger: pino.Logger;
  encryptionAlgorithm: EncryptionAlgorithmSpec = EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT;
  awsCredentials!: AWSSessionConfig;
  keyType!: string;
  configFileLocation!: string;

  getString(key: string): Promise<string | undefined> {
    return this.get(key);
  }

  saveString(key: string, value: string): Promise<void> {
    return this.set(key, value);
  }

  async getBytes(key: string): Promise<Uint8Array | undefined> {
    const bytesString = await this.get(key);
    if (bytesString) {
      return platform.base64ToBytes(bytesString);
    }
    return undefined;
  }

  saveBytes(key: string, value: Uint8Array): Promise<void> {
    const bytesString = platform.bytesToBase64(value);
    return this.set(key, bytesString);
  }

  getObject?<T>(key: string): Promise<T | undefined> {
    return this.getString(key).then((value) =>
      value ? (JSON.parse(value) as T) : undefined
    );
  }

  saveObject?<T>(key: string, value: T): Promise<void> {
    const json = JSON.stringify(value);
    return this.saveString(key, json);
  }

  constructor(
    keyId: string,
    configFileLocation: string | null,
    awsSessionConfig: AWSSessionConfig | null,
    logLevel: LoggerLogLevelOptions,
  ) {
    /** 
        Initializes AWSKeyValueStorage

        keyId URI of the master key
        ex. keyId = "arn:aws:kms:ap-south-1:<account>:key/<keyIdValue>"
        The master key needs EncryptCommand, DecryptCommand privileges
        key types supported are all RSA keys and Symmetric Default keys

        configFileLocation provides custom config file location - if missing read from env KSM_CONFIG_FILE
        awsSessionConfig is AWS session config
        Logger is a logger instance which is pino and will be chosen by default, log level can be passed
        **/
    this.configFileLocation =
      configFileLocation ??
      process.env.KSM_CONFIG_FILE ??
      this.defaultConfigFileLocation;
    this.keyId = keyId ?? process.env.KSM_AWS_KEY_ID;
    this.logger = getLogger(logLevel ?? DEFAULT_LOG_LEVEL);

    if (awsSessionConfig) {
      const hasAWSSessionConfig =
        awsSessionConfig.awsAccessKeyId &&
        awsSessionConfig.awsSecretAccessKey &&
        awsSessionConfig.regionName;
      if (hasAWSSessionConfig) {
        this.awsCredentials = awsSessionConfig;
      }
    }
    this.cryptoClient = new AwsKmsClient(this.awsCredentials).getCryptoClient();

    this.lastSavedConfigHash = "";
  }

  async init() {
    await this.getKeyDetails();
    await this.loadConfig();
    this.logger.info(`Loaded config file from ${this.configFileLocation.toString()}`);
    return this; // Return the instance to allow chaining
  }

  async getKeyDetails() {
    try {
      const input = {
        KeyId: this.keyId,
      };
      const command: DescribeKeyCommand = new DescribeKeyCommand(input);
      const keyDetails: DescribeKeyCommandOutput =
        await this.cryptoClient.send(command);
      const keySpecDetails = keyDetails.KeyMetadata?.KeySpec?.toString() ?? "";

      if (!supportedKeySpecs.includes(keySpecDetails)) {
        this.logger.error("Unsupported Key Spec for AWS KMS Storage");
        throw new AWSKeyValueStorageError(
          "Unsupported Key Spec for AWS KMS Storage"
        );
      }

      if (keySpecDetails === EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT) {
        this.encryptionAlgorithm = EncryptionAlgorithmEnum.SYMMETRIC_DEFAULT;
      } else {
        this.encryptionAlgorithm = EncryptionAlgorithmEnum.RSAES_OAEP_SHA_256;
      }

      this.keyType = keySpecDetails;
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error(`Failed to get key details: ${err.message.toString()}`);
    }
  }

  private async loadConfig(): Promise<void> {
    await this.createConfigFileIfMissing();

    try {
      // Read the config file
      let contents: Buffer = Buffer.alloc(0);
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
      let config: Record<string, string> | null = null;

      if (contents.length === 0) {
        this.logger.warn(`Empty config file ${this.configFileLocation.toString()}`);
        contents = Buffer.from("{}");
      }

      // Check if the content is plain JSON
      let jsonError;
      let decryptionError = false;
      try {
        const configData = contents.toString();
        config = JSON.parse(configData);
        // Encrypt and save the config if it's plain JSON
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
        jsonError = err;
      }

      if (jsonError) {
        const configJson = await decryptBuffer({
          keyId: this.keyId,
          encryptionAlgorithm: this.encryptionAlgorithm,
          ciphertext: contents,
          cryptoClient: this.cryptoClient,
          keyType: this.keyType,
        }, this.logger);
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
          `${this.configFileLocation.toString()} may contain JSON format problems`
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
        this.logger.warn("Skipped config JSON save. No changes detected.");
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
      const configPath = resolve(this.configFileLocation);
      const blob = await encryptBuffer({
        keyId: this.keyId,
        encryptionAlgorithm: this.encryptionAlgorithm,
        message: stringifiedValue,
        cryptoClient: this.cryptoClient,
        keyType: this.keyType,
      }, this.logger);

      if (blob.length > 0) {
        await fs.writeFile(configPath, blob);
      }
      // Update the last saved config hash
      this.lastSavedConfigHash = configHash;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error("Error saving config:", err.message);
    }
  }

  public async decryptConfig(autosave: boolean): Promise<string> {
    let ciphertext: Buffer;
    let plaintext: string;

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
      throw new Error(`Failed to load config file ${this.configFileLocation.toString()}`);
    }

    try {
      // Decrypt the file contents
      plaintext = await decryptBuffer({
        keyId: this.keyId,
        encryptionAlgorithm: this.encryptionAlgorithm,
        cryptoClient: this.cryptoClient,
        keyType: this.keyType,
        ciphertext,
      }, this.logger);
      if (plaintext.length === 0) {
        this.logger.error(
          `Failed to decrypt config file ${this.configFileLocation.toString()}`
        );
      } else if (autosave) {
        // Optionally autosave the decrypted content
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

  public async changeKey(newKeyId: string, newAwsConfig?: AWSSessionConfig): Promise<boolean> {
    const oldKeyId = this.keyId;
    const oldCryptoClient = this.cryptoClient;
    const oldAwsCredentials = this.awsCredentials;

    try {
      // Update the key and reinitialize the CryptographyClient
      if (newAwsConfig) {
        this.logger.info(`Changing key to ${newKeyId} for config '${this.configFileLocation.toString()}'`);
        this.awsCredentials = newAwsConfig;
      }
      const config = this.config;
      if (Object.keys(config).length == 0) {
        await this.init();
      }
      this.keyId = newKeyId;
      await this.getKeyDetails();
      await this.saveConfig({}, true);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
      // Restore the previous key and crypto client if the operation fails
      this.awsCredentials = oldAwsCredentials;
      this.keyId = oldKeyId;
      this.cryptoClient = oldCryptoClient;
      this.logger.error(
        `Failed to change the key to '${newKeyId}' for config '${this.configFileLocation.toString()}': ${error.message.toString()}`
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
      const configPath = resolve(this.configFileLocation);
      await fs.writeFile(configPath, Buffer.from("{}"));

      // Encrypt an empty configuration and write to the file
      const blob = await encryptBuffer({
        keyId: this.keyId,
        encryptionAlgorithm: this.encryptionAlgorithm,
        message: "{}",
        keyType: this.keyType,
        cryptoClient: this.cryptoClient,
      }, this.logger);

      if (blob.length > 0) {
        await fs.writeFile(configPath, blob);
      }
      this.logger.info(`Config file created at: ${configPath}`);
    }
  }

  public async readStorage(): Promise<Record<string, string>> {
    if (!this.config) {
      await this.loadConfig();
    }
    return Promise.resolve(this.config);
  }

  public saveStorage(updatedConfig: Record<string, string>): Promise<void> {
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

    if (config[key]) {
      this.logger.debug(`Deleting key ${key} from ${this.configFileLocation.toString()}`);
      delete config[key];
    } else {
      this.logger.debug(`Key ${key} not found in ${this.configFileLocation.toString()}`);
    }
    await this.saveStorage(config);
  }

  public async deleteAll(): Promise<void> {
    await this.readStorage();
    Object.keys(this.config).forEach((key) => delete this.config[key]);
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