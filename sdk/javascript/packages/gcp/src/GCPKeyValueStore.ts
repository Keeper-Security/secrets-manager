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
import { writeFileAtomicSync } from "./atomicWrite";
import { getLogger } from "./Logger";
import { KMSClient } from "./interface/UtilOptions";
import { Logger } from "pino";

// `??` falls back only on null and undefined, so a blank value would otherwise be taken as a
// real path (a common result of a Docker --env-file or a Kubernetes ConfigMap entry with no
// value), and resolve("") is the current working directory, which fs.access reports as existing.
const nonBlank = (value: string | null | undefined): string | undefined =>
  value == null || value.trim() === "" ? undefined : value;

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
    if (bytesString !== undefined) {
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

    if (key in config) {
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
   *    If null, undefined, or blank, reads from env KSM_CONFIG_FILE.
   *    If env KSM_CONFIG_FILE is not set or is blank, uses default location.
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
      nonBlank(keyVaultConfigFileLocation) ??
      nonBlank(process.env.KSM_CONFIG_FILE) ??
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
      const algorithm = key?.versionTemplate?.algorithm?.toString() || "";
      const keyPurposeDetails = key?.purpose?.toString() || "";

      if (!supportedKeyPurpose.includes(keyPurposeDetails)) {
        this.logger.error("Unsupported Key Spec for GCP KMS Storage");
        throw new GCPKeyValueStorageError(
          "Unsupported Key Spec for GCP KMS Storage"
        );
      }

      this.logger.debug(`Key purpose for key provided: ${keyPurposeDetails}`);
      const isAsymmetric = keyPurposeDetails === KeyPurpose.ASYMMETRIC_DECRYPT;
      this.logger.debug(`key is ${isAsymmetric ? "asymmetric" : "symmetric"}`);

      // Assigned only once the key is known to be usable, so a rejected key leaves the
      // previous key's metadata intact instead of half-replacing it.
      this.encryptionAlgorithm = algorithm;
      this.isAsymmetric = isAsymmetric;
      this.keyType = keyPurposeDetails;
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error("Failed to get key details:", err.message);
      throw err;
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
        this.logger.error(
          `Config file ${this.configFileLocation.toString()} is empty, which indicates an interrupted write or a corrupted file`
        );
        throw new Error(
          `Config file ${this.configFileLocation.toString()} is empty and may be corrupted. Restore it from a backup, or delete it to create a new configuration.`
        );
      }

      // Check if the content is plain JSON
      let config: Record<string, string> | null = null;
      let jsonError;
      let decryptionError = false;
      try {
        const configData = contents.toString();
        config = JSON.parse(configData);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (err: any) {
        this.logger.debug("given file is encrypted file. trying to decrypt the configuration into a json from it");
        jsonError = err;
      }

      // A successful parse already proves the file is plaintext, so encrypting it is a
      // side effect of that result and must not be mistaken for a failed parse.
      if (!jsonError) {
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
      }


      if (jsonError) {
        let token: string | null | undefined = null;
        if (this.keyType === "RAW_ENCRYPT_DECRYPT") {
          this.logger.debug("using raw symmetric key to decrypt the config.");
          token = await this.gcpSessionConfig.getToken();
        }

        const configJson = await decryptBuffer({
          isAsymmetric: this.isAsymmetric,
          ciphertext: contents,
          cryptoClient: this.cryptoClient,
          keyType: this.keyType,
          encryptionAlgorithm: this.encryptionAlgorithm,
          keyProperties: this.gcpKeyConfig,
          token
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

  private async writeSecureConfigFile(path: string, data: Buffer | string): Promise<void> {
    writeFileAtomicSync(path, data);
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

      // A matching hash only proves the in-memory config is unchanged, not that the file on disk
      // still holds it. A file deleted underneath a running process must fall through to a real
      // save of this.config; skipping here would leave the file missing indefinitely.
      let fileConfirmedMissing = false;
      if (!force && configHash === this.lastSavedConfigHash) {
        if (await this.configFileExists()) {
          this.logger.warn("Skipped config JSON save. No changes detected.");
          return;
        }
        fileConfirmedMissing = true;
      }

      // A file already confirmed missing above needs only its directory, since the write below
      // creates it. Routing it through createConfigFileIfMissing() as well would encrypt and
      // write a "{}" placeholder that this same call immediately overwrites with the real config.
      if (fileConfirmedMissing) {
        await this.ensureConfigDirectoryExists(resolve(this.configFileLocation));
      } else {
        await this.createConfigFileIfMissing();
      }

      // Encrypt the config JSON and write to the file
      const stringifiedValue = JSON.stringify(
        this.config,
        Object.keys(this.config),
        DEFAULT_JSON_INDENT
      );
      this.logger.debug("encrypting the config before writing to file.");

      let token: string | null | undefined = null;
      if (this.keyType === "RAW_ENCRYPT_DECRYPT") {
        this.logger.debug("using raw symmetric key to encrypt the config.");
        token = await this.gcpSessionConfig.getToken();
      }

      const blob = await encryptBuffer({
        isAsymmetric: this.isAsymmetric,
        message: stringifiedValue,
        cryptoClient: this.cryptoClient,
        keyType: this.keyType,
        encryptionAlgorithm: this.encryptionAlgorithm,
        keyProperties: this.gcpKeyConfig,
        token: token
      }, this.logger);
      await this.writeSecureConfigFile(this.configFileLocation, blob);
      this.logger.debug("writing to the file completed successfully.");
      // Update the last saved config hash
      this.lastSavedConfigHash = configHash;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error("Error saving config:", err.message);
      throw err;
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
      let token: string | null | undefined = null;
      if (this.keyType === "RAW_ENCRYPT_DECRYPT") {
        this.logger.debug("using raw symmetric key to decrypt the config.");
        token = await this.gcpSessionConfig.getToken();
      }
      // Decrypt the file contents
      plaintext = await decryptBuffer({
        isAsymmetric: this.isAsymmetric,
        cryptoClient: this.cryptoClient,
        keyType: this.keyType,
        encryptionAlgorithm: this.encryptionAlgorithm,
        keyProperties: this.gcpKeyConfig,
        token: token,
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
        await this.writeSecureConfigFile(this.configFileLocation, plaintext);
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
    const oldKeyType = this.keyType;
    const oldIsAsymmetric = this.isAsymmetric;
    const oldEncryptionAlgorithm = this.encryptionAlgorithm;

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
      // Restore the previous key and crypto client if the operation fails.
      // The key metadata below has to be restored with them: getKeyDetails() has already
      // switched it to the new key, and pairing the old key with the new key's algorithm
      // encrypts the config into a blob that neither key can decrypt.
      this.gcpKeyConfig = oldKeyConfiguration;
      this.cryptoClient = oldCryptoClient;
      this.keyType = oldKeyType;
      this.isAsymmetric = oldIsAsymmetric;
      this.encryptionAlgorithm = oldEncryptionAlgorithm;
      this.logger.error(
        `Failed to change the key to '${newGcpKeyConfig.toString()}' for config '${this.configFileLocation.toString()}': ${error.message.toString()}`
      );
      throw new Error(
        `Failed to change the key for ${this.configFileLocation.toString()}`
      );
    }
    return true;
  }

  // Matches fs.existsSync semantics: any access failure, not just ENOENT, reports false. The
  // caller only uses this to decide whether a save can be skipped, and a save that cannot be
  // skipped goes on to createConfigFileIfMissing(), which is where the ENOENT-only policy for
  // acting on an access failure lives.
  private async configFileExists(): Promise<boolean> {
    try {
      await fs.access(resolve(this.configFileLocation));
      return true;
    } catch {
      return false;
    }
  }

  private async ensureConfigDirectoryExists(configPath: string): Promise<void> {
    try {
      const dir = dirname(configPath); // configPath is already absolute (resolved above)

      try {
        await fs.access(dir); // Check if directory exists
      } catch {
        await fs.mkdir(dir, { recursive: true }); // Create directory if missing
      }
    } catch {
      await fs.mkdir(process.cwd(), { recursive: true }); // Use the working directory as fallback
    }
  }

  private async createConfigFileIfMissing(): Promise<void> {
    // Ensure the config file path is absolute
    const configPath = resolve(this.configFileLocation);
    try {
      // Check if the config file exists
      await fs.access(configPath);
      this.logger.info(`Config file already exists at: ${configPath}`);
    } catch (error: unknown) {
      const code = (error as NodeJS.ErrnoException | undefined)?.code;
      if (code !== "ENOENT") {
        this.logger.error(
          `Failed to check config file at ${configPath}: ${error instanceof Error ? error.message : String(error)}`
        );
        throw error;
      }
      // File genuinely does not exist, proceed to create it
      await this.ensureConfigDirectoryExists(configPath);
      await this.writeSecureConfigFile(configPath, Buffer.from("{}"));

      let token: string | null | undefined = null;
      if (this.keyType === "RAW_ENCRYPT_DECRYPT") {
        this.logger.debug("using raw symmetric key to encrypt the config.");
        token = await this.gcpSessionConfig.getToken();
      }
      // Encrypt an empty configuration and write to the file
      const blob = await encryptBuffer({
        isAsymmetric: this.isAsymmetric,
        message: "{}",
        keyType: this.keyType,
        cryptoClient: this.cryptoClient,
        encryptionAlgorithm: this.encryptionAlgorithm,
        keyProperties: this.gcpKeyConfig,
        token: token
      }, this.logger);
      await this.writeSecureConfigFile(configPath, blob);
      this.logger.info(`Config file created at: ${configPath}`);
    }
  }

  public async readStorage(): Promise<Record<string, string>> {
    return this.config;
  }

  public saveStorage(updatedConfig: Record<string, string>): Promise<void> {
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

  public async deleteAll(): Promise<void> {
    await this.readStorage();
    Object.keys(this.config).forEach((key) => delete this.config[key]);
    await this.saveStorage({});
  }

  public async contains(key: string): Promise<boolean> {
    const config = await this.readStorage();
    return Promise.resolve(key in config);
  }

  public async isEmpty(): Promise<boolean> {
    const config = await this.readStorage();
    return Promise.resolve(Object.keys(config).length === 0);
  }
}
