// Drives GCPKSMClient through the REAL google-auth-library and gaxios. Neither library is mocked,
// so these tests catch what a mock of @google-cloud/kms cannot: whether the caller's own
// credentials, not an ambient identity, are the ones actually used to sign requests, and what
// shape of credential material each construction path produces. gRPC methods and the raw REST
// calls are answered in-process, so no test here opens a network connection.
import { generateKeyPairSync, randomBytes } from 'crypto';
import { inspect } from 'util';
import axios from 'axios';
import { crc32c } from '@aws-crypto/crc32c';
import { GCPKSMClient } from '../src/GcpKmsClient';
import { GCPKeyValueStorage } from '../src/GCPKeyValueStore';
import { GCPKeyConfig } from '../src/GcpKeyConfig';
import { GCPKeyValueStorageError } from '../src/error';
import { getLogger } from '../src/Logger';

jest.mock('../src/Logger', () => ({
    getLogger: jest.fn().mockReturnValue({
        debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn(),
    }),
}));

// gaxios and google-auth-library are not dependencies of this package. Resolve the copies that
// @google-cloud/kms really uses (kms -> google-gax -> google-auth-library -> gaxios), so the
// interceptor below patches the transport the KMS client sends through.
const resolveFrom = (fromFile: string, id: string) => require.resolve(id, { paths: [require('path').dirname(fromFile)] });
const authLibraryPath = resolveFrom(resolveFrom(require.resolve('@google-cloud/kms'), 'google-gax'), 'google-auth-library');
const { Gaxios } = require(resolveFrom(authLibraryPath, 'gaxios'));
const { UserRefreshClient } = require(authLibraryPath);

function makeKeyPair() {
    const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    return privateKey as unknown as string;
}

// Intercepts gaxios's own transport, one layer below google-auth-library, so google-auth-library's
// real request-building, JWT signing and error handling all still run.
function interceptTokenEndpoint(handler: (body: string) => { status: number; json: object }) {
    const realAdapter = (Gaxios.prototype as any)._defaultAdapter;
    let calls = 0;
    (Gaxios.prototype as any)._defaultAdapter = async function (opts: any) {
        return realAdapter.call(this, {
            ...opts,
            fetchImplementation: async (_url: string, init: any) => {
                calls++;
                const { status, json } = handler(String(init.body));
                return new Response(JSON.stringify(json), { status, headers: { 'content-type': 'application/json' } });
            },
        });
    };
    return { restore: () => { (Gaxios.prototype as any)._defaultAdapter = realAdapter; }, callCount: () => calls };
}

function decodeAssertion(body: string) {
    const params = new URLSearchParams(body);
    const assertion = params.get('assertion')!;
    const [, payloadB64] = assertion.split('.');
    return JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
}

// Every new GCPKSMClient() starts ADC discovery, so the machine's own ADC, gcloud config and
// metadata server must be out of reach. A second fake identity is installed as ADC: a path that
// silently falls back to ADC then signs as adc@..., and the identity checks below fail on any machine.
// Jest gives each test file its own copy of process.env, so nothing leaks to other files. Do not
// restore it in afterAll: discovery started by a constructor can still be running after the last test.
const ADC_EMAIL = 'adc@example.iam.gserviceaccount.com';
const CALLER_EMAIL = 'caller@example.iam.gserviceaccount.com';
let tmpDir: string;

function writeKeyFile(clientEmail: string, privateKey: string) {
    const file = require('path').join(tmpDir, `${clientEmail}.json`);
    require('fs').writeFileSync(file, JSON.stringify({ type: 'service_account', client_email: clientEmail, private_key: privateKey }));
    return file;
}

beforeAll(() => {
    const path = require('path');
    tmpDir = require('fs').mkdtempSync(path.join(require('os').tmpdir(), 'gcp-real-auth-'));
    process.env.HOME = tmpDir;
    process.env.CLOUDSDK_CONFIG = path.join(tmpDir, 'gcloud');
    process.env.METADATA_SERVER_DETECTION = 'none';
    process.env.GOOGLE_CLOUD_PROJECT = 'real-auth-test-project';
    process.env.GOOGLE_APPLICATION_CREDENTIALS = writeKeyFile(ADC_EMAIL, makeKeyPair());
    // With a proxy variable set, gaxios loads https-proxy-agent with import(), which jest refuses
    // without --experimental-vm-modules. No request in this file needs a proxy.
    ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy'].forEach((k) => delete process.env[k]);
});

afterAll(() => {
    require('fs').rmSync(tmpDir, { recursive: true, force: true });
});

// [route, a client made from a fresh key, the identity that must sign]
const ROUTES: Array<[string, (key: string) => GCPKSMClient, string]> = [
    ['new GCPKSMClient() (ADC)', () => new GCPKSMClient(), ADC_EMAIL],
    ['createClientUsingCredentials()', (key) => new GCPKSMClient().createClientUsingCredentials(CALLER_EMAIL, key), CALLER_EMAIL],
    ['createClientFromCredentialsFile()', (key) => new GCPKSMClient().createClientFromCredentialsFile(writeKeyFile(CALLER_EMAIL, key)), CALLER_EMAIL],
];

describe('GCPKSMClient with the real auth stack', () => {
    afterEach(() => jest.restoreAllMocks());

    describe('each construction path is signed by the caller-chosen identity, not an ambient one', () => {
        it('createClientUsingCredentials() signs requests with the given key, not ADC', async () => {
            const key = makeKeyPair();
            const client = new GCPKSMClient().createClientUsingCredentials('caller@example.iam.gserviceaccount.com', key);

            const headers = await client.getCryptoClient().auth.getRequestHeaders('https://cloudkms.googleapis.com/v1/foo:encrypt');
            const [, payloadB64] = headers.get('Authorization')!.replace('Bearer ', '').split('.');
            const claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

            expect(claims.iss).toBe('caller@example.iam.gserviceaccount.com');
        });

        it('createClientFromCredentialsFile() signs requests with the file\'s key, not ADC', async () => {
            const key = makeKeyPair();
            const fs = require('fs');
            const os = require('os');
            const path = require('path');
            const file = path.join(os.tmpdir(), `gcp-kms-test-creds-${process.pid}-${Date.now()}.json`);
            fs.writeFileSync(file, JSON.stringify({ client_email: 'fromfile@example.iam.gserviceaccount.com', private_key: key }));

            try {
                const client = new GCPKSMClient().createClientFromCredentialsFile(file);
                const headers = await client.getCryptoClient().auth.getRequestHeaders('https://cloudkms.googleapis.com/v1/foo:encrypt');
                const [, payloadB64] = headers.get('Authorization')!.replace('Bearer ', '').split('.');
                const claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

                expect(claims.iss).toBe('fromfile@example.iam.gserviceaccount.com');
            } finally {
                fs.unlinkSync(file);
            }
        });
    });

    describe('getToken() requests the raw-path token as the identity of the route', () => {
        it.each(ROUTES)('%s', async (_route, make, expectedIss) => {
            const client = make(makeKeyPair());
            const issuers: string[] = [];
            const interceptor = interceptTokenEndpoint((body) => {
                issuers.push(decodeAssertion(body).iss);
                return { status: 200, json: { access_token: 'ya29.test-token', expires_in: 3600, token_type: 'Bearer' } };
            });

            try {
                await expect(client.getToken()).resolves.toBe('ya29.test-token');
                expect(issuers).toEqual([expectedIss]);
            } finally {
                interceptor.restore();
            }
        });
    });

    describe('every route signs gRPC calls with a locally self-signed, audience-bound JWT (no scope claim, no network round trip)', () => {
        it.each(ROUTES)('%s', async (_route, make, expectedIss) => {
            const client = make(makeKeyPair());
            const interceptor = interceptTokenEndpoint(() => ({ status: 200, json: { access_token: 'unexpected', expires_in: 3600 } }));

            try {
                const headers = await client.getCryptoClient().auth.getRequestHeaders('https://cloudkms.googleapis.com/v1/foo:encrypt');
                const [, payloadB64] = headers.get('Authorization')!.replace('Bearer ', '').split('.');
                const claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

                expect(interceptor.callCount()).toBe(0); // signed locally, no token endpoint round trip
                expect(claims.iss).toBe(expectedIss);
                expect(claims.aud).toBe('https://cloudkms.googleapis.com/'); // bound to the Cloud KMS host
                expect(claims.scope).toBeUndefined(); // a scope claim would make the JWT valid for other Google APIs
            } finally {
                interceptor.restore();
            }
        });
    });

    describe('getToken() never lets a raw auth-library error cross its boundary', () => {
        it('wraps a failed token refresh in a message-only error, not the raw error object', async () => {
            const client = new GCPKSMClient();
            const fakeRefreshToken = 'REFRESH_TOKEN_SECRET_1234567890';
            const errorLog = (getLogger as unknown as () => { error: jest.Mock })().error;
            errorLog.mockClear();

            // Swap in a real UserRefreshClient (the credential type google-auth-library gives ADC
            // for a user/authorized_user identity) so the error getToken() receives is the real
            // shape google-auth-library produces, not a hand-rolled stand-in.
            (client as any).KMSClient = {
                auth: new UserRefreshClient({
                    clientId: 'test-client-id.apps.googleusercontent.com',
                    clientSecret: 'test-client-secret',
                    refreshToken: fakeRefreshToken,
                }),
            };
            const sentRefreshTokens: Array<string | null> = [];
            const interceptor = interceptTokenEndpoint((body) => {
                sentRefreshTokens.push(new URLSearchParams(body).get('refresh_token'));
                return { status: 400, json: { error: 'invalid_grant' } };
            });

            let caught: unknown;
            try {
                await client.getToken();
            } catch (err) {
                caught = err;
            }

            interceptor.restore();
            expect(sentRefreshTokens).toEqual([fakeRefreshToken]); // this client's own refresh, not another identity's
            expect(caught).toBeInstanceOf(GCPKeyValueStorageError);
            expect(inspect(caught, { depth: 10 })).not.toContain(fakeRefreshToken);
            expect(inspect(errorLog.mock.calls, { depth: 10 })).not.toContain(fakeRefreshToken);
            expect((caught as Error).message).toContain('invalid_grant');
        });
    });
});

describe('GCPKeyValueStorage over ADC with the real auth stack', () => {
    const KEY = 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1';
    afterEach(() => jest.restoreAllMocks());

    // Answers the gRPC methods on the real client instance, so grpc-js never opens a channel.
    // encrypt and decrypt are an identity transform with valid CRC32C fields.
    function stubGrpc(session: GCPKSMClient, purpose: string) {
        const kms = session.getCryptoClient();
        jest.spyOn(kms, 'getCryptoKey').mockResolvedValue([{ purpose, versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION' } }] as never);
        const encrypt = jest.spyOn(kms, 'encrypt').mockImplementation((async (req: { plaintext: Buffer }) =>
            [{ ciphertext: req.plaintext, ciphertextCrc32c: { value: crc32c(req.plaintext) }, verifiedPlaintextCrc32c: true }]) as never);
        const decrypt = jest.spyOn(kms, 'decrypt').mockImplementation((async (req: { ciphertext: Buffer }) =>
            [{ plaintext: req.ciphertext, plaintextCrc32c: { value: crc32c(req.ciphertext) } }]) as never);
        return { encrypt, decrypt };
    }

    it('a RAW_ENCRYPT_DECRYPT key sends the ADC token to rawEncrypt and rawDecrypt, never to gRPC encrypt or decrypt', async () => {
        const session = new GCPKSMClient();
        const grpc = stubGrpc(session, 'RAW_ENCRYPT_DECRYPT');
        const post = jest.spyOn(axios, 'post').mockImplementation((async (url: string, body: Record<string, string>) =>
            url.endsWith(':rawEncrypt')
                ? { data: { ciphertext: body.plaintext, initializationVector: randomBytes(12).toString('base64') } }
                : { data: { plaintext: body.ciphertext } }) as never);
        const interceptor = interceptTokenEndpoint(() => ({ status: 200, json: { access_token: 'ya29.adc-token', expires_in: 3600, token_type: 'Bearer' } }));

        try {
            const configPath = require('path').join(tmpDir, 'raw', 'config.json');
            const storage = await new GCPKeyValueStorage(configPath, new GCPKeyConfig(KEY), session).init();
            await storage.saveString('clientId', 'raw-client');
            const reread = await new GCPKeyValueStorage(configPath, new GCPKeyConfig(KEY), session).init();

            await expect(reread.getString('clientId')).resolves.toBe('raw-client');
            // decryptConfig() fetches its own token, separately from init().
            const rawDecrypts = () => post.mock.calls.filter((call) => String(call[0]).endsWith(':rawDecrypt')).length;
            const decryptsBefore = rawDecrypts();
            await expect(reread.decryptConfig(false)).resolves.toContain('raw-client');
            expect(rawDecrypts()).toBe(decryptsBefore + 1);
            expect(post.mock.calls.map((call) => String(call[0]).split(':').pop())).toEqual(expect.arrayContaining(['rawEncrypt', 'rawDecrypt']));
            post.mock.calls.forEach((call) => expect((call[2] as { headers: Record<string, string> }).headers.Authorization).toBe('Bearer ya29.adc-token'));
            expect(grpc.encrypt).not.toHaveBeenCalled();
            expect(grpc.decrypt).not.toHaveBeenCalled();
        } finally {
            interceptor.restore();
        }
    });

    it('an ENCRYPT_DECRYPT key never asks for a token and never takes the raw REST path', async () => {
        const session = new GCPKSMClient();
        const grpc = stubGrpc(session, 'ENCRYPT_DECRYPT');
        const post = jest.spyOn(axios, 'post').mockRejectedValue(new Error('hermetic test: unexpected raw REST call'));
        const interceptor = interceptTokenEndpoint(() => ({ status: 200, json: { access_token: 'unexpected', expires_in: 3600 } }));

        try {
            const configPath = require('path').join(tmpDir, 'symmetric', 'config.json');
            const storage = await new GCPKeyValueStorage(configPath, new GCPKeyConfig(KEY), session).init();
            await storage.saveString('clientId', 'grpc-client');
            await expect(storage.decryptConfig(false)).resolves.toContain('grpc-client');

            expect(interceptor.callCount()).toBe(0);
            expect(post).not.toHaveBeenCalled();
            expect(grpc.encrypt).toHaveBeenCalled();
            expect(grpc.decrypt).toHaveBeenCalled();
        } finally {
            interceptor.restore();
        }
    });
});
