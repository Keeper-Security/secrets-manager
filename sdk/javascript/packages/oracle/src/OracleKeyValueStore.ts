import { promises as fs } from "fs";
import { dirname, resolve } from "path";
import { createHash, randomUUID } from "crypto";

import {
	KeyValueStorage,
	platform,
} from "@keeper-security/secrets-manager-core";

import { OciKmsClient } from "./OciKmsClient";
import {
	DEFAULT_JSON_INDENT,
	DEFAULT_LOG_LEVEL,
	HEX_DIGEST,
	MD5_HASH,
} from "./constants";
import { decryptBuffer, encryptBuffer } from "./utils";
import { getLogger } from "./Logger";
import { OCISessionConfig } from "./OciSessionConfig";
import { KmsCryptoClient, KmsManagementClient } from "oci-keymanagement";
import { GetKeyResponse } from "oci-keymanagement/lib/response";
import { GetKeyRequest } from "oci-keymanagement/lib/request";
import { KeyShape } from "oci-keymanagement/lib/model";
import { OracleKeyValueStorageError } from "./error";
import { LoggerLogLevelOptions } from "./enum";
import { Logger } from "pino";

export class OciKeyValueStorage implements KeyValueStorage {
	defaultConfigFileLocation: string = "client-config.json";
	keyId!: string;
	cryptoClient!: KmsCryptoClient;
	managementClient!: KmsManagementClient;
	config!: Record<string, string>;
	lastSavedConfigHash!: string;
	logger: Logger;
	configFileLocation!: string;
	keyVersion: string;
	isAsymmetric: boolean = false;

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

	public getObject?<T>(key: string): Promise<T | undefined> {
		return this.getString(key).then((value) =>
			value ? (JSON.parse(value) as T) : undefined
		);
	}

	public saveObject?<T>(key: string, value: T): Promise<void> {
		const json = JSON.stringify(value);
		return this.saveString(key, json);
	}

	constructor(
		keyId: string,
		keyVersion: string | null,
		configFileLocation: string | null,
		OciSessionConfig: OCISessionConfig,
		logLevel: LoggerLogLevelOptions | null
	) {
		this.configFileLocation =
			configFileLocation ??
			process.env.KSM_CONFIG_FILE ??
			this.defaultConfigFileLocation;
		this.keyId = keyId;
		this.keyVersion = keyVersion ?? "";
		this.logger = logLevel == null ? getLogger(DEFAULT_LOG_LEVEL) : getLogger(logLevel);
		const ociKmsClient = new OciKmsClient(OciSessionConfig);
		this.cryptoClient = ociKmsClient.getCryptoClient();
		this.managementClient = ociKmsClient.getManagementClient();
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
			const opcRequestId = randomUUID();
			this.logger.info(`Making a getKey request with request Id ${opcRequestId}`);
			const keyDetailsRequest: GetKeyRequest = {
				keyId: this.keyId,
				opcRequestId: opcRequestId
			};

			const keyDetails: GetKeyResponse = await this.managementClient.getKey(keyDetailsRequest);
			const algorithm: KeyShape.Algorithm = keyDetails.key.keyShape.algorithm;

			if (algorithm == KeyShape.Algorithm.Aes) {
				this.isAsymmetric = false;
			} else if (algorithm == KeyShape.Algorithm.Rsa) {
				this.isAsymmetric = true;
			} else {
				throw new OracleKeyValueStorageError(` given key has unsupported algorithm: ${algorithm}`);
			}
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} catch (error: any) {
			this.logger.error(`Error occurred while trying to get key details. Are permissions for getting key details assigned to the service principal? . Exact error message ${error.message}`);
			throw new OracleKeyValueStorageError(`Failed to get key details: ${error.message}`);
		}
	}

	private async loadConfig(): Promise<void> {
		await this.createConfigFileIfMissing();

		try {
			// Read the config file
			let contents: Buffer = Buffer.alloc(0);
			try {
				contents = await fs.readFile(this.configFileLocation);
				this.logger.info(`Loaded config file ${this.configFileLocation}`);
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
			} catch (err: any) {
				this.logger.error(
					`Failed to load config file ${this.configFileLocation}: ${err.message}`
				);
				throw new Error(
					`Failed to load config file ${this.configFileLocation}`
				);
			}
			let config: Record<string, string> | null = null;

			if (contents.length === 0) {
				this.logger.warn(`Empty config file ${this.configFileLocation}`);
				contents = Buffer.from("{}");
			}

			// Check if the content is plain JSON
			let jsonError;
			let decryptionError = false;
			try {
				config = JSON.parse(contents.toString());
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
					ciphertext: contents,
					cryptoClient: this.cryptoClient,
					keyVersionId: this.keyVersion,
					isAsymmetric: this.isAsymmetric
				}, this.logger);
				try {
					config = JSON.parse(configJson);
					this.config = config ?? {};
					this.lastSavedConfigHash = createHash(MD5_HASH)
						.update(
							JSON.stringify(
								this.config,
								Object.keys(this.config).sort(),
								DEFAULT_JSON_INDENT
							)
						)
						.digest(HEX_DIGEST);
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
				} catch (err: any) {
					decryptionError = true;
					this.logger.error(
						`Failed to parse decrypted config file: ${err.message}`
					);
					throw new Error(
						`Failed to parse decrypted config file ${this.configFileLocation}`
					);
				}
			}
			if (jsonError && decryptionError) {
				this.logger.info(
					`Config file is not a valid JSON file: ${jsonError.message}`
				);
				throw new Error(
					`${this.configFileLocation} may contain JSON format problems`
				);
			}
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} catch (err: any) {
			this.logger.error(`Error loading config: ${err.message}`);
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
			const blob = await encryptBuffer({
				keyId: this.keyId,
				message: stringifiedValue,
				cryptoClient: this.cryptoClient,
				keyVersionId: this.keyVersion,
				isAsymmetric: this.isAsymmetric
			}, this.logger);
			if (blob.length > 0) {
				await fs.writeFile(this.configFileLocation, blob);
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
				this.logger.warn(`Empty config file ${this.configFileLocation}`);
				return "";
			}
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} catch (err: any) {
			this.logger.error(
				`Failed to load config file ${this.configFileLocation}: ${err.message}`
			);
			throw new Error(`Failed to load config file ${this.configFileLocation}`);
		}

		try {
			// Decrypt the file contents
			plaintext = await decryptBuffer({
				keyId: this.keyId,
				cryptoClient: this.cryptoClient,
				keyVersionId: this.keyVersion,
				isAsymmetric: this.isAsymmetric,
				ciphertext,
			}, this.logger);
			if (plaintext.length === 0) {
				this.logger.error(
					`Failed to decrypt config file ${this.configFileLocation}`
				);
			} else if (autosave) {
				// Optionally autosave the decrypted content
				await fs.writeFile(this.configFileLocation, plaintext);
			}
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} catch (err: any) {
			this.logger.error(
				`Failed to write decrypted config file ${this.configFileLocation}: ${err.message}`
			);
			throw new Error(
				`Failed to write decrypted config file ${this.configFileLocation}`
			);
		}

		return plaintext;
	}

	public async changeKey(newKeyId: string, newKeyVersion: string | null): Promise<boolean> {
		const oldKeyId = this.keyId;
		const oldCryptoClient = this.cryptoClient;
		const oldKeyVersion = this.keyVersion;

		try {
			// Update the key and reinitialize the CryptographyClient
			const config = this.config;
			if (Object.keys(config).length == 0) {
				await this.init();
			}
			this.keyId = newKeyId;
			this.keyVersion = newKeyVersion ?? "";
			await this.getKeyDetails();
			await this.saveConfig({}, true);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} catch (error: any) {
			// Restore the previous key and crypto client if the operation fails
			this.keyId = oldKeyId;
			this.cryptoClient = oldCryptoClient;
			this.keyVersion = oldKeyVersion;
			this.logger.error(
				`Failed to change the key to '${newKeyId}' for config '${this.configFileLocation}': ${error.message}`
			);
			await this.getKeyDetails();
			throw new Error(
				`Failed to change the key for ${this.configFileLocation}`
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
			await fs.writeFile(configPath, Buffer.alloc(0));
			// Encrypt an empty configuration and write to the file
			const blob = await encryptBuffer({
				keyId: this.keyId,
				message: "{}",
				cryptoClient: this.cryptoClient,
				keyVersionId: this.keyVersion,
				isAsymmetric: this.isAsymmetric
			}, this.logger);
			if(blob.length>0){
				await fs.writeFile(configPath, blob);
				this.logger.info(`Config file created at: ${configPath}`);
			}
		}
	}

	private async readStorage(): Promise<Record<string, string>> {
		if (!this.config) {
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
