import pino from "pino";
import { GCPKeyValueStorageError } from "./error";
import { getLogger } from "./Logger";
import { DEFAULT_LOG_LEVEL } from "./constants";

/**
 * Configuration for a Google Cloud Key Management Service (KMS) key.
 *
 * @class
 * @param {string} [resourcename] The full resource name of a key in the form
 *     `projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY/cryptoKeyVersions/VERSION`
 * @param {string} [keyName] The name of the key
 * @param {string} [keyRing] The name of the key ring
 * @param {string} [project] The project ID
 * @param {string} [location] The location (region or multi-region)
 * @param {string} [keyVersion] The version of the key. If not provided, the latest version will be used.
 * The permissions provided should have the following roles
 *     - Cloud KMS Admin (`roles/cloudkms.admin`): Manage key rings and keys.
 *     - Cloud KMS CryptoKey Decrypter (`roles/cloudkms.cryptoKeyDecrypter`): Decrypt data using a given key.
 *     - Cloud KMS CryptoKey Encrypter (`roles/cloudkms.cryptoKeyEncrypter`): Encrypt data using a given key.
 *     - Cloud KMS CryptoKey Public Key Viewer (`roles/cloudkms.publicKeyViewer`): Get public keys for a given key.
 */
export class GCPKeyConfig {
    /**
     * The full resource name of the key.
     * @type {string}
     */
    public keyName: string;
    /**
     * The version of the key.
     * @type {string|null}
     */
    public keyVersion: string | null;
    /**
     * The name of the key ring.
     * @type {string}
     */
    public keyRing: string;
    /**
     * The project ID.
     * @type {string}
     */
    public project: string;
    /**
     * The location (region or multi-region).
     * @type {string}
     */
    public location: string;
    private logger: pino.Logger<never, boolean>;

    /**
     * @param {string} [resourcename] The full resource name of a key in the form
     *     `projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY/cryptoKeyVersions/VERSION`
     * @param {string} [keyName] The name of the key
     * @param {string} [keyRing] The name of the key ring
     * @param {string} [project] The project ID
     * @param {string} [location] The location (region or multi-region)
     * @param {string} [keyVersion] The version of the key. If not provided, the latest version will be used.
     */
    constructor(resourcename?: string, keyName?: string, keyRing?: string, project?: string, location?: string, keyVersion?: string | null, logger?: pino.Logger) {
        this.logger = logger == null ? getLogger(DEFAULT_LOG_LEVEL) : logger;
        if (!resourcename) {
            this.keyName = keyName ?? '';
            this.keyVersion = keyVersion ?? '';
            this.keyRing = keyRing ?? '';
            this.project = project ?? '';
            this.location = location ?? '';
        } else {
            const parts = resourcename.split('/');

            if (parts.length < 10) {
                this.logger.error(`given KMS resource path ${resourcename} is invalid`);
                throw new GCPKeyValueStorageError("Invalid KMS resource path");
            }
            this.project = parts[1];
            this.location = parts[3];
            this.keyRing = parts[5];
            this.keyName = parts[7];
            this.keyVersion = parts.length > 9 ? parts[9] : "";
        }

        if (!this.keyName || !this.keyRing || !this.project || !this.location) {
            this.logger.error(`given KMS resource path ${resourcename} is invalid. please provide all [keyname,keyring,project,location] details or directly a valid resource URL`);
            throw new GCPKeyValueStorageError("Invalid KMS resource path");
        }
    }

    public toString(this) {
        this.logger.debug("Converting key config to string");
        return `${this.keyName}, ${this.keyVersion}`;
    }

    public toKeyName(this) {
        this.logger.debug("Converting key config to key name (no key version)");
        return `projects/${this.project}/locations/${this.location}/keyRings/${this.keyRing}/cryptoKeys/${this.keyName}`;
    }

    public toResourceName(this) {
        this.logger.debug("Converting key config to resource name");
        return `projects/${this.project}/locations/${this.location}/keyRings/${this.keyRing}/cryptoKeys/${this.keyName}/cryptoKeyVersions/${this.keyVersion}`;
    }

}
