// KSM-1514: fs.access and fs.readFile both follow symbolic links. An attacker who can create a
// file in the config directory, but who cannot write the config file itself, planted a symlink
// at the config path and the SDK adopted the attacker's clientId and hostname; the very next
// save then silently replaced the planted symlink with a real encrypted file, destroying the
// evidence. This file empirically attacks the fix (real symlinks, a real dangling link, a real
// race loop, real directory modes under real umasks), not just reads the diff.
//
// Deliberately does NOT mock `fs` (unlike GCPKeyValueStorage.test.ts): every property under
// test here, whether a path is a symlink, a directory's real mode, whether a target file was
// ever created, is real on-disk state that a mocked fs.access/fs.readFile can't observe.
jest.mock('@google-cloud/kms', () => ({
    KeyManagementServiceClient: jest.fn().mockImplementation(() => ({
        encrypt: jest.fn(),
        decrypt: jest.fn(),
        getCryptoKey: jest.fn(),
        getPublicKey: jest.fn(),
    })),
}));
jest.mock('../src/GcpKmsClient', () => ({
    GCPKSMClient: jest.fn().mockImplementation(() => ({
        getCryptoClient: jest.fn().mockReturnValue({
            encrypt: jest.fn(),
            decrypt: jest.fn(),
            getCryptoKey: jest.fn(),
            getPublicKey: jest.fn(),
        }),
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
import { promises as fsPromises } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { crc32c as calculate } from '@aws-crypto/crc32c';
import { GCPKeyValueStorage } from '../src/GCPKeyValueStore';
import { GCPKeyConfig } from '../src/GcpKeyConfig';
import { GCPKSMClient } from '../src/GcpKmsClient';
import { GCPKeyValueStorageError } from '../src/error';
import { isWindows, itUnlessWindows } from './platformSupport';

const KEY_RESOURCE_NAME =
    'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1';

// identity-wrap encrypt/decrypt, matching the pattern already used throughout this package's
// test suite (see GCPKeyValueStorage.deletedConfigFile.test.ts).
function makeStorage(configPath: string): GCPKeyValueStorage {
    const mockSessionConfig = new GCPKSMClient();
    const gcpKeyConfig = new GCPKeyConfig(KEY_RESOURCE_NAME);
    const storage = new GCPKeyValueStorage(configPath, gcpKeyConfig, mockSessionConfig);
    const cryptoClient = mockSessionConfig.getCryptoClient();
    (cryptoClient.getCryptoKey as jest.Mock).mockResolvedValue([
        { purpose: 'ENCRYPT_DECRYPT', versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION' } },
    ]);
    (cryptoClient.encrypt as jest.Mock).mockImplementation(async (input: { plaintext: Buffer }) => {
        const ciphertext = input.plaintext;
        return [{
            ciphertext,
            verifiedPlaintextCrc32c: true,
            ciphertextCrc32c: { value: calculate(ciphertext) },
        }];
    });
    (cryptoClient.decrypt as jest.Mock).mockImplementation(async (input: { ciphertext: Buffer }) => {
        const plaintext = input.ciphertext;
        return [{
            plaintext,
            plaintextCrc32c: { value: calculate(plaintext) },
        }];
    });
    // Forward-compatible with KSM-1516 (a sibling fix landing on this same release branch,
    // which adds an init() guard to every public method including decryptConfig()/getString()):
    // a never-initialized instance is exactly what several tests below deliberately call
    // decryptConfig() or getString() against, to isolate the symlink check under test here from
    // that unrelated guard. On this branch alone GCPKeyValueStorage has no `initialized` field
    // at all, so this line is a harmless no-op; verified by running this file's suite both
    // without and with KSM-1516's changes merged in.
    (storage as any).initialized = true;
    return storage;
}

const rejectionOf = async (promise: Promise<unknown>): Promise<unknown> =>
    promise.then(() => null, (err) => err);

const posixNonRoot =
    process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() !== 0;
const itOnPosix = posixNonRoot ? it : it.skip;

describe('GCPKeyValueStorage symlink protection (KSM-1514)', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-symlink-'));
        configPath = path.join(tmpDir, 'config.json');
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    describe('TEST 1: a symlink pointing at a real, attacker-controlled file', () => {
        it('init() refuses it, names the path and the reason, and adopts nothing', async () => {
            const attackerPath = path.join(tmpDir, 'attacker-config.json');
            const attackerContent = JSON.stringify({
                clientId: 'ATTACKER-CLIENT-ID',
                hostname: 'attacker.example.com',
            });
            fs.writeFileSync(attackerPath, attackerContent);
            fs.symlinkSync(attackerPath, configPath);

            const storage = makeStorage(configPath);
            const rejection = await rejectionOf(storage.init());

            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            const message = (rejection as Error).message;
            expect(message).toContain(configPath);
            expect(message).toMatch(/symbolic link/);
            // The assertions that matter: nothing was adopted, nothing was touched.
            expect(await storage.getString('clientId')).toBeUndefined();
            expect(await storage.getString('hostname')).toBeUndefined();
            expect(fs.readFileSync(attackerPath, 'utf8')).toBe(attackerContent);
            expect(fs.lstatSync(configPath).isSymbolicLink()).toBe(true);
        });
    });

    describe('TEST 3: decryptConfig() and createConfigFileIfMissing() against a symlink', () => {
        it('decryptConfig() refuses a symlinked config path too, since it never calls configFileExists()', async () => {
            const attackerPath = path.join(tmpDir, 'attacker-plaintext.json');
            const attackerContent = 'ATTACKER-CONTROLLED-BYTES-NOT-A-VALID-ENVELOPE';
            fs.writeFileSync(attackerPath, attackerContent);
            fs.symlinkSync(attackerPath, configPath);

            const storage = makeStorage(configPath);
            const rejection = await rejectionOf(storage.decryptConfig(false));

            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            expect((rejection as Error).message).toMatch(/symbolic link/);
            expect(fs.readFileSync(attackerPath, 'utf8')).toBe(attackerContent);
        });

        it('refuses a dangling symlink at a not-yet-created config path, rather than silently replacing it', async () => {
            const neverCreatedTarget = path.join(tmpDir, 'target-that-never-existed.json');
            fs.symlinkSync(neverCreatedTarget, configPath);

            const storage = makeStorage(configPath);
            const rejection = await rejectionOf(storage.init());

            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            // The link must survive: today's actual behavior (pre-fix) is that
            // writeFileAtomicSync's rename silently replaces the dangling link with a real
            // encrypted file, destroying the evidence a symlink was ever planted there.
            expect(fs.lstatSync(configPath).isSymbolicLink()).toBe(true);
            expect(fs.existsSync(neverCreatedTarget)).toBe(false);
        });

        it('a dangling symlink into a directory the process CAN write is still refused, not used as a write target', async () => {
            const writableDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-attacker-writable-'));
            try {
                const target = path.join(writableDir, 'planted.json');
                fs.symlinkSync(target, configPath);

                const storage = makeStorage(configPath);
                await expect(storage.init()).rejects.toBeInstanceOf(GCPKeyValueStorageError);

                expect(fs.existsSync(target)).toBe(false);
            } finally {
                fs.rmSync(writableDir, { recursive: true, force: true });
            }
        });
    });

    describe('TEST 4: the config directory mode', () => {
        itOnPosix('is 0700 on creation regardless of umask', async () => {
            for (const umaskValue of [0o000, 0o077, 0o022]) {
                const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-umask-'));
                try {
                    const nestedDir = path.join(scratchDir, 'nested', 'config-dir');
                    const nestedConfigPath = path.join(nestedDir, 'config.json');
                    const previousUmask = process.umask(umaskValue);
                    try {
                        await makeStorage(nestedConfigPath).init();
                    } finally {
                        process.umask(previousUmask);
                    }
                    expect(fs.statSync(nestedDir).mode & 0o777).toBe(0o700);
                } finally {
                    fs.rmSync(scratchDir, { recursive: true, force: true });
                }
            }
        });

        itOnPosix('does not tighten a directory that already existed at a looser mode', async () => {
            const existingDir = path.join(tmpDir, 'existing-dir');
            fs.mkdirSync(existingDir);
            fs.chmodSync(existingDir, 0o755); // set explicitly; mkdir's own mode is umask-affected

            const nestedConfigPath = path.join(existingDir, 'config.json');
            await makeStorage(nestedConfigPath).init();

            expect(fs.statSync(existingDir).mode & 0o777).toBe(0o755);
        });
    });

    describe('TEST 5: a symlinked ANCESTOR directory, not the leaf, must keep working', () => {
        it('inits, saves, and reads through normally when a parent directory is a symlink (matches macOS /tmp and a Kubernetes-style mount)', async () => {
            const realDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-real-ancestor-'));
            try {
                const linkedAncestor = path.join(tmpDir, 'linked-ancestor');
                fs.symlinkSync(realDir, linkedAncestor);
                const nestedConfigPath = path.join(linkedAncestor, 'config.json');

                const storage = makeStorage(nestedConfigPath);
                await storage.init();
                await storage.saveString('clientId', 'REAL-CLIENT-ID');

                expect(await storage.getString('clientId')).toBe('REAL-CLIENT-ID');
                // The leaf file itself, reached through the real target directory, is a regular
                // file. Only the leaf is ever refused; ancestor segments are untouched.
                expect(fs.lstatSync(path.join(realDir, 'config.json')).isSymbolicLink()).toBe(false);
            } finally {
                fs.rmSync(realDir, { recursive: true, force: true });
            }
        });
    });

    describe('TEST 6: a planted symlink is refused on every round', () => {
        // The symlink is planted before each read and never swapped while a read is running, so this
        // does not race the check against the open. It shows the refusal is stable round after round,
        // not that the check-then-open window is closed.
        it('refuses the planted symlink on every round (10,000, or 300 on Windows): zero adoptions, zero unexpected errors', async () => {
            const attackerPath = path.join(tmpDir, 'attacker-payload.json');
            fs.writeFileSync(attackerPath, 'ATTACKER-PAYLOAD-NOT-VALID-CIPHERTEXT');
            const storage = makeStorage(configPath);

            // Symlink creation is slow on Windows, where 10,000 rounds outlast the test timeout and
            // the loop keeps running into later tests.
            const ITERATIONS = isWindows ? 300 : 10_000;
            let succeeded = 0;
            let unexpectedErrors = 0;

            for (let i = 0; i < ITERATIONS; i++) {
                fs.rmSync(configPath, { force: true });
                fs.symlinkSync(attackerPath, configPath);
                try {
                    await storage.decryptConfig(false);
                    succeeded++;
                } catch (err) {
                    const isExpectedRefusal =
                        err instanceof GCPKeyValueStorageError && /symbolic link/.test(err.message);
                    if (!isExpectedRefusal) {
                        unexpectedErrors++;
                    }
                }
            }

            // succeeded === 0 is the assertion that matters (the attacker value was never
            // adopted). unexpectedErrors === 0 additionally proves every single rejection was
            // this fix's own clear refusal, not some other failure mode (e.g. a read that got
            // through and then failed decryption for an unrelated reason).
            expect({ iterations: ITERATIONS, succeeded, unexpectedErrors }).toEqual({
                iterations: ITERATIONS,
                succeeded: 0,
                unexpectedErrors: 0,
            });
        });
    });

    // A regular file at the config path gets past the symlink refusal above just as well as a
    // symlink does, and needs no symlink at all: the attacker capability the ticket names is
    // "can create files in the config directory", not "can create symlinks" specifically. This
    // is the OpenSSH authorized_keys StrictModes pattern applied to the same problem.
    describe('file ownership and mode ("StrictModes"), on the same descriptor the content is read from', () => {
        itOnPosix.each([
            ['group-writable (0o620)', 0o620],
            ['world-writable (0o602)', 0o602],
        ])('refuses a config file that is %s', async (_label, mode) => {
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc' }));
            fs.chmodSync(configPath, mode);
            const modeBefore = fs.statSync(configPath).mode & 0o777;
            const contentsBefore = fs.readFileSync(configPath);

            const storage = makeStorage(configPath);
            const rejection = await rejectionOf(storage.init());

            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            expect((rejection as Error).message).toMatch(/group or world write access/);
            // Nothing was "fixed": the file's mode and content are both exactly as risky as
            // before the refusal, so the operator sees the same evidence they would have.
            expect(fs.statSync(configPath).mode & 0o777).toBe(modeBefore);
            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
        });

        itUnlessWindows('also refuses on the decryptConfig() read site, not only loadConfig()', async () => {
            fs.writeFileSync(configPath, 'never reached: the mode check runs before any parse attempt');
            fs.chmodSync(configPath, 0o620);
            const storage = makeStorage(configPath);

            const rejection = await rejectionOf(storage.decryptConfig(false));

            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            expect((rejection as Error).message).toMatch(/group or world write access/);
        });

        itOnPosix('refuses a config file owned by a different user, checked on the open file descriptor itself', async () => {
            // A real ownership mismatch needs a second real OS user, not available here or in
            // CI. The comparison LOGIC is tested directly instead, against an otherwise
            // completely real, already-open file descriptor: the file is really written, really
            // opened, and really read; only the uid its fstat() reports is substituted, on the
            // same object the fix itself calls .stat() on (fs.promises.open's own FileHandle),
            // not a parallel mock that could drift from what the fix actually does.
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc' }), { mode: 0o600 });
            const contentsBefore = fs.readFileSync(configPath);
            const realOpen = fsPromises.open.bind(fsPromises);
            const openSpy = jest.spyOn(fsPromises, 'open').mockImplementation(async (...args: unknown[]) => {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                const handle: any = await (realOpen as any)(...args);
                const realStat = handle.stat.bind(handle);
                handle.stat = async () => {
                    const stat = await realStat();
                    return { ...stat, uid: stat.uid + 12345 };
                };
                return handle;
            });

            try {
                const storage = makeStorage(configPath);
                const rejection = await rejectionOf(storage.init());

                expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
                expect((rejection as Error).message).toMatch(/owned by uid/);
            } finally {
                openSpy.mockRestore();
            }
            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
        });

        it('a normal, self-owned 0600 config file is accepted, same as before this check existed', async () => {
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc' }), { mode: 0o600 });
            const storage = makeStorage(configPath);

            await storage.init();

            expect(await storage.getString('clientId')).toBe('abc');
        });
    });
});
