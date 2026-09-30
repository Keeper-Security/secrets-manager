// Drives GCPKSMClient through the REAL google-auth-library and gaxios (only @google-cloud/kms's
// own network transport is out of scope here; that's covered by GCPKeyValueStorage tests).
// Neither library is mocked, so these tests catch what a mock of @google-cloud/kms cannot:
// whether the caller's own credentials, not an ambient identity, are the ones actually used to
// sign requests, and what shape of credential material each construction path produces.
import { generateKeyPairSync } from 'crypto';
import { GCPKSMClient } from '../src/GcpKmsClient';
import { Gaxios } from 'gaxios';

jest.mock('../src/Logger', () => ({
    getLogger: jest.fn().mockReturnValue({
        debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn(),
    }),
}));

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

    describe('the explicit-credential routes sign a locally self-signed, audience-bound JWT (no OAuth scope, no network round trip)', () => {
        it('createClientUsingCredentials() never asks the token endpoint for an access token', async () => {
            const key = makeKeyPair();
            const client = new GCPKSMClient().createClientUsingCredentials('caller@example.iam.gserviceaccount.com', key);
            const interceptor = interceptTokenEndpoint(() => ({ status: 200, json: { access_token: 'unexpected', expires_in: 3600 } }));

            try {
                const headers = await client.getCryptoClient().auth.getRequestHeaders('https://cloudkms.googleapis.com/v1/foo:encrypt');
                const [, payloadB64] = headers.get('Authorization')!.replace('Bearer ', '').split('.');
                const claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

                expect(interceptor.callCount()).toBe(0); // signed locally, no token endpoint round trip
                expect(claims.aud).toBe('https://cloudkms.googleapis.com/'); // bound to the Cloud KMS host, not scope-bound to all Google APIs
                expect(claims.scope).toBeUndefined(); // not a scope-bound credential usable elsewhere
            } finally {
                interceptor.restore();
            }
        });
    });

    describe('getToken() never lets a raw auth-library error cross its boundary', () => {
        it('wraps a failed token refresh in a message-only error, not the raw error object', async () => {
            const client = new GCPKSMClient();
            const fakeRefreshToken = 'REFRESH_TOKEN_SECRET_1234567890';

            // Swap in a real UserRefreshClient (the credential type google-auth-library gives ADC
            // for a user/authorized_user identity) so the error getToken() receives is the real
            // shape google-auth-library produces, not a hand-rolled stand-in.
            const { UserRefreshClient } = require('google-auth-library');
            (client as any).KMSClient = {
                auth: new UserRefreshClient({
                    clientId: 'test-client-id.apps.googleusercontent.com',
                    clientSecret: 'test-client-secret',
                    refreshToken: fakeRefreshToken,
                }),
            };
            const interceptor = interceptTokenEndpoint(() => ({ status: 400, json: { error: 'invalid_grant' } }));

            let caught: unknown;
            try {
                await client.getToken();
            } catch (err) {
                caught = err;
            }

            interceptor.restore();
            expect(caught).toBeInstanceOf(Error);
            const inspected = require('util').inspect(caught, { depth: 10 });
            expect(inspected).not.toContain(fakeRefreshToken);
            expect((caught as Error).message).toContain('invalid_grant');
        });
    });
});
