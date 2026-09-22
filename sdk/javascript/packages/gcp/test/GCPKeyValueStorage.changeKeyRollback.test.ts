// Deliberately does NOT mock `fs`, and does NOT mock the crypto primitives either: the fake
// KMS client below wraps two real RSA keypairs, so the whole envelope (publicEncrypt with the
// key's OAEP hash, privateDecrypt with that same hash, AES-256-GCM payload) runs for real
// against a real file on disk. A failed changeKey() that leaves the old key paired with the
// new key's algorithm still writes a file successfully, so only a real encrypt-then-decrypt
// round trip can show that the written file is unreadable; a mock that returns its input
// unchanged cannot tell the two algorithms apart.
jest.mock('@google-cloud/kms', () => ({
    KeyManagementServiceClient: jest.fn(),
}));
jest.mock('../src/GcpKmsClient', () => ({
    GCPKSMClient: jest.fn().mockImplementation(() => ({
        getCryptoClient: jest.fn(),
        getToken: jest.fn().mockResolvedValue('mock-token'),
    })),
}));
jest.mock('../src/Logger', () => ({
    getLogger: jest.fn().mockReturnValue({
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
    }),
}));

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { generateKeyPairSync, privateDecrypt, KeyObject, constants as cryptoConstants } from 'crypto';
import { crc32c as calculate } from '@aws-crypto/crc32c';
import { GCPKeyValueStorage } from '../src/GCPKeyValueStore';
import { GCPKeyConfig } from '../src/GcpKeyConfig';
import { GCPKSMClient } from '../src/GcpKmsClient';

const PROJECT = 'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys';

// Two asymmetric keys whose declared OAEP hash differs. This is the pairing the ticket
// describes: the old key is SHA1, the new key is SHA256.
const OLD_KEY = `${PROJECT}/old-key/cryptoKeyVersions/1`;
const NEW_KEY = `${PROJECT}/new-key/cryptoKeyVersions/1`;
const OLD_ALGORITHM = 'RSA_DECRYPT_OAEP_2048_SHA1';
const NEW_ALGORITHM = 'RSA_DECRYPT_OAEP_2048_SHA256';

const OAEP_HASH_BY_ALGORITHM: Record<string, string> = {
    RSA_DECRYPT_OAEP_2048_SHA1: 'sha1',
    RSA_DECRYPT_OAEP_2048_SHA256: 'sha256',
};

type FakeKey = {
    purpose: string;
    algorithm: string;
    publicKeyPem: string;
    privateKey: KeyObject;
    failGetPublicKey?: boolean;
};

function generateFakeKey(algorithm: string): FakeKey {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    return {
        purpose: 'ASYMMETRIC_DECRYPT',
        algorithm,
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        privateKey,
    };
}

// Generated once: 2048-bit keygen is the slow part of this file.
const oldKey = generateFakeKey(OLD_ALGORITHM);
const newKey = generateFakeKey(NEW_ALGORITHM);

// One client serving both keys, dispatching on the requested resource name - changeKey() reuses
// the same KMS client object, it only swaps the key config.
function makeFakeKmsClient(keys: Record<string, FakeKey>): any {
    const lookup = (name: string): FakeKey => {
        const shortName = name.split('/cryptoKeys/')[1]?.split('/')[0];
        const key = keys[shortName];
        if (!key) {
            throw new Error(`NOT_FOUND: CryptoKey ${name} not found`);
        }
        return key;
    };

    return {
        getCryptoKey: jest.fn(async (input: { name: string }) => {
            const key = lookup(input.name);
            return [{ purpose: key.purpose, versionTemplate: { algorithm: key.algorithm } }];
        }),
        getPublicKey: jest.fn(async (input: { name: string }) => {
            const key = lookup(input.name);
            if (key.failGetPublicKey) {
                throw new Error('PERMISSION_DENIED: Permission cloudkms.cryptoKeyVersions.viewPublicKey denied');
            }
            return [{
                name: input.name,
                pem: key.publicKeyPem,
                pemCrc32c: { value: calculate(Buffer.from(key.publicKeyPem)) },
            }];
        }),
        // GCP derives the OAEP hash from the key version itself, never from the request, so a
        // blob padded with a different hash than the key declares can never be decrypted.
        asymmetricDecrypt: jest.fn(async (input: { name: string; ciphertext: Buffer }) => {
            const key = lookup(input.name);
            const plaintext = privateDecrypt(
                {
                    key: key.privateKey,
                    oaepHash: OAEP_HASH_BY_ALGORITHM[key.algorithm],
                    padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
                },
                input.ciphertext
            );
            return [{ plaintext, plaintextCrc32c: { value: calculate(plaintext) } }];
        }),
        encrypt: jest.fn(),
        decrypt: jest.fn(),
    };
}

function makeStorage(configPath: string, resourceName: string, cryptoClient: any): GCPKeyValueStorage {
    const sessionConfig = new GCPKSMClient();
    (sessionConfig.getCryptoClient as jest.Mock).mockReturnValue(cryptoClient);
    return new GCPKeyValueStorage(configPath, new GCPKeyConfig(resourceName), sessionConfig);
}

function keyState(storage: GCPKeyValueStorage) {
    const internals = storage as any;
    return {
        keyType: internals.keyType,
        isAsymmetric: internals.isAsymmetric,
        encryptionAlgorithm: internals.encryptionAlgorithm,
        gcpKeyConfig: internals.gcpKeyConfig,
        cryptoClient: internals.cryptoClient,
    };
}

describe('changeKey() state rollback on failure (real RSA keys, real fs)', () => {
    let tmpDir: string;
    let configPath: string;
    let cryptoClient: any;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-change-key-'));
        configPath = path.join(tmpDir, 'config.json');
        oldKey.failGetPublicKey = false;
        newKey.failGetPublicKey = false;
        cryptoClient = makeFakeKmsClient({ 'old-key': oldKey, 'new-key': newKey });
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('restores every key field, not just the key config and client, when the new key fails', async () => {
        const storage = makeStorage(configPath, OLD_KEY, cryptoClient);
        await storage.init();
        await storage.saveString('clientId', 'BEFORE-ROTATION');
        const before = keyState(storage);
        expect(before).toMatchObject({
            keyType: 'ASYMMETRIC_DECRYPT',
            isAsymmetric: true,
            encryptionAlgorithm: OLD_ALGORITHM,
        });

        // getCryptoKey succeeds for the new key, so getKeyDetails() flips all three metadata
        // fields; the encryption that follows it is what fails.
        newKey.failGetPublicKey = true;

        await expect(storage.changeKey(new GCPKeyConfig(NEW_KEY))).rejects.toThrow(
            `Failed to change the key for ${configPath}`
        );

        const after = keyState(storage);
        expect(after.keyType).toBe(before.keyType);
        expect(after.isAsymmetric).toBe(before.isAsymmetric);
        expect(after.encryptionAlgorithm).toBe(OLD_ALGORITHM);
        expect(after.gcpKeyConfig).toBe(before.gcpKeyConfig);
        expect(after.cryptoClient).toBe(before.cryptoClient);
    });

    it('leaves the config still decryptable by the old key after a failed rotation', async () => {
        const storage = makeStorage(configPath, OLD_KEY, cryptoClient);
        await storage.init();
        await storage.saveString('clientId', 'BEFORE-ROTATION');

        newKey.failGetPublicKey = true;
        await expect(storage.changeKey(new GCPKeyConfig(NEW_KEY))).rejects.toThrow();
        newKey.failGetPublicKey = false;

        // Any ordinary write after the failed rotation re-encrypts the whole config.
        await storage.saveString('clientId', 'AFTER-FAILED-ROTATION');
        await storage.saveString('appKey', 'APP-KEY-VALUE');

        // A fresh instance is how the config is read on the next process start: it takes the
        // algorithm from the old key itself, so it can only read a blob that was written with
        // that same algorithm.
        const reopened = makeStorage(configPath, OLD_KEY, cryptoClient);
        await reopened.init();
        await expect(reopened.getString('clientId')).resolves.toBe('AFTER-FAILED-ROTATION');
        await expect(reopened.getString('appKey')).resolves.toBe('APP-KEY-VALUE');
    });

    it('rolls back when the new key has an unsupported purpose', async () => {
        const storage = makeStorage(configPath, OLD_KEY, cryptoClient);
        await storage.init();
        await storage.saveString('clientId', 'BEFORE-ROTATION');
        const before = keyState(storage);

        const signingKey = `${PROJECT}/signing-key/cryptoKeyVersions/1`;
        (cryptoClient.getCryptoKey as jest.Mock).mockImplementation(async (input: { name: string }) => {
            if (input.name.includes('signing-key')) {
                return [{
                    purpose: 'ASYMMETRIC_SIGN',
                    versionTemplate: { algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' },
                }];
            }
            return [{ purpose: oldKey.purpose, versionTemplate: { algorithm: oldKey.algorithm } }];
        });

        await expect(storage.changeKey(new GCPKeyConfig(signingKey))).rejects.toThrow(
            `Failed to change the key for ${configPath}`
        );

        expect(keyState(storage)).toEqual(before);
        await expect(storage.getString('clientId')).resolves.toBe('BEFORE-ROTATION');
    });
});

describe('getKeyDetails() key metadata assignment', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-key-details-'));
        configPath = path.join(tmpDir, 'config.json');
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    // init() has no rollback of its own, so the unsupported-purpose check must reject the key
    // before any field is written rather than after encryptionAlgorithm is already assigned.
    it('assigns no key metadata when init() rejects an unsupported key purpose', async () => {
        const cryptoClient = makeFakeKmsClient({});
        (cryptoClient.getCryptoKey as jest.Mock).mockResolvedValue([
            { purpose: 'ASYMMETRIC_SIGN', versionTemplate: { algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' } },
        ]);
        const storage = makeStorage(configPath, OLD_KEY, cryptoClient);

        await expect(storage.init()).rejects.toThrow('Unsupported Key Spec for GCP KMS Storage');

        const state = keyState(storage);
        expect(state.keyType).toBeUndefined();
        expect(state.isAsymmetric).toBe(false);
        expect(state.encryptionAlgorithm).toBeUndefined();
    });
});
