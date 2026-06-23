import {KeeperRecordLink, getLinks, KeeperRecord, platform} from '../'
import {createCipheriv, randomBytes} from 'crypto'

// KSM-1010: KeeperRecordLink typed accessor tests (mirrors Python record_link_test.py)

const plainLink = (payload: object, path?: string, ownerRecordUid = 'RU_owner'): KeeperRecordLink => {
    const data = platform.bytesToBase64(platform.stringToBytes(JSON.stringify(payload)))
    return new KeeperRecordLink({recordUid: 'RU_test', data, path}, ownerRecordUid)
}

const encryptedLink = async (payload: object, key: Uint8Array, path?: string, ownerRecordUid = 'RU_owner'): Promise<KeeperRecordLink> => {
    const encrypted = await platform.encryptWithKey(platform.stringToBytes(JSON.stringify(payload)), key)
    const data = platform.bytesToBase64(encrypted)
    return new KeeperRecordLink({recordUid: 'RU_test', data, path}, ownerRecordUid)
}

// Encrypt with a specific IV so we can control the first decoded byte (for the fallthrough test)
const encryptWithCustomIv = (data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array => {
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(iv)) as any
    const ct: Buffer = Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()])
    const tag: Buffer = cipher.getAuthTag()
    const result = new Uint8Array(iv.length + ct.length + tag.length)
    result.set(iv, 0)
    result.set(ct, iv.length)
    result.set(tag, iv.length + ct.length)
    return result
}

// ── test 1 ─────────────────────────────────────────────────────────────────────
test('boolean accessors read plain JSON; absent keys default to false', () => {
    const link = plainLink({is_admin: true, rotation: true, connections: false})
    expect(link.isAdminUser()).toBe(true)
    expect(link.allowsRotation()).toBe(true)
    expect(link.allowsConnections()).toBe(false)
    expect(link.allowsPortForwards()).toBe(false)
    expect(link.isLaunchCredential()).toBe(false)
    expect(link.isIamUser()).toBe(false)
    expect(link.belongsTo()).toBe(false)
    expect(link.noUpdateServices()).toBe(false)
})

// ── test 2 ─────────────────────────────────────────────────────────────────────
test('version, decoded data, and readable-JSON heuristic', () => {
    const link = plainLink({version: 3, is_admin: false})
    expect(link.getLinkDataVersion()).toBe(3)
    const decoded = link.getDecodedData()
    expect(decoded).not.toBeNull()
    expect(decoded!.startsWith('{')).toBe(true)
    expect(link.hasReadableData()).toBe(true)

    // Non-JSON base64 is not "readable"
    const raw = new KeeperRecordLink({
        recordUid: 'RU',
        data: platform.bytesToBase64(platform.stringToBytes('not json at all')),
        path: undefined
    }, 'owner')
    expect(raw.hasReadableData()).toBe(false)
    expect(raw.getLinkDataVersion()).toBeNull()

    // Invalid base64 returns null (Node's Buffer.from is lenient; we validate before decoding)
    const bad = new KeeperRecordLink({recordUid: 'RU', data: '!!! not base64 !!!', path: undefined}, 'owner')
    expect(bad.getDecodedData()).toBeNull()
    expect(() => bad.getDecodedData()).not.toThrow()
})

// ── test 3 ─────────────────────────────────────────────────────────────────────
test('mightBeEncrypted is gated to known encrypted paths only', () => {
    expect(plainLink({}, 'ai_settings').mightBeEncrypted()).toBe(true)
    expect(plainLink({}, 'jit_settings').mightBeEncrypted()).toBe(true)
    expect(plainLink({}, 'meta').mightBeEncrypted()).toBe(false)
    expect(plainLink({}, 'something_else').mightBeEncrypted()).toBe(false)
    expect(plainLink({}, undefined).mightBeEncrypted()).toBe(false)
})

// ── test 4 ─────────────────────────────────────────────────────────────────────
test('getDecryptedData roundtrip: correct key decrypts, wrong/absent key yields null', async () => {
    const key = platform.getRandomBytes(32)
    const payload = {enabled: true, ttl: 3600}
    const link = await encryptedLink(payload, key, 'jit_settings')

    const decrypted = await link.getDecryptedData(key)
    expect(decrypted).not.toBeNull()
    expect(JSON.parse(decrypted!)).toEqual(payload)

    expect(await link.getDecryptedData(undefined)).toBeNull()

    const wrongKey = platform.getRandomBytes(32)
    expect(await link.getDecryptedData(wrongKey)).toBeNull()
})

// ── test 5 ─────────────────────────────────────────────────────────────────────
test('getLinkData auto-detects plain JSON vs encrypted data', async () => {
    const plain = plainLink({aiEnabled: true}, 'ai_settings')
    const data = await plain.getLinkData()
    expect(data).not.toBeNull()
    expect(data!['aiEnabled']).toBe(true)

    const key = platform.getRandomBytes(32)
    const enc = await encryptedLink({enabled: true}, key, 'jit_settings')
    expect(await enc.getLinkData()).toBeNull()
    const withKey = await enc.getLinkData(key)
    expect(withKey).not.toBeNull()
    expect(withKey!['enabled']).toBe(true)
})

// ── test 6 ─────────────────────────────────────────────────────────────────────
test('settings accessors are gated to the matching path', async () => {
    const key = platform.getRandomBytes(32)
    const ai = plainLink({aiEnabled: true}, 'ai_settings')
    const jit = plainLink({enabled: true}, 'jit_settings')

    expect(await ai.getAiSettingsData(key)).not.toBeNull()
    expect(await ai.getJitSettingsData(key)).toBeNull()
    expect(await jit.getJitSettingsData(key)).not.toBeNull()
    expect(await jit.getAiSettingsData(key)).toBeNull()

    expect(await ai.getSettingsForPath('ai_settings')).not.toBeNull()
    expect(await ai.getSettingsForPath('other')).toBeNull()
})

// ── test 7 ─────────────────────────────────────────────────────────────────────
test('getLinks wraps typed links; entry without recordUid is skipped', () => {
    const record: KeeperRecord = {
        recordUid: 'main_uid',
        data: {},
        revision: 1,
        links: [
            {recordUid: 'meta_uid', data: platform.bytesToBase64(platform.stringToBytes(
                JSON.stringify({allowedSettings: {rotation: true}, version: 1}))), path: 'meta'},
            {recordUid: 'cred_uid', data: platform.bytesToBase64(platform.stringToBytes(
                JSON.stringify({is_admin: true, is_launch_credential: true}))), path: undefined},
            {recordUid: 'ref_uid', data: undefined, path: undefined},
            {recordUid: '', data: undefined, path: undefined}, // empty UID is skipped
        ]
    }

    const links = getLinks(record)
    expect(links).toHaveLength(3)
    expect(links.every(l => l instanceof KeeperRecordLink)).toBe(true)

    expect(links[0].recordUid).toBe('meta_uid')
    expect(links[0].path).toBe('meta')
    expect(links[0].allowsRotation()).toBe(true)
    expect(links[0].getLinkDataVersion()).toBe(1)

    expect(links[1].isAdminUser()).toBe(true)
    expect(links[1].isLaunchCredential()).toBe(true)

    expect(links[2].recordUid).toBe('ref_uid')

    // Raw links unchanged
    expect(record.links).toHaveLength(4)
})

// ── test 8 ─────────────────────────────────────────────────────────────────────
test('string-encoded values are not coerced to bool or int', () => {
    const link = plainLink({is_admin: 'true', rotation: 'false', version: '3'})
    expect(link.isAdminUser()).toBe(false)
    expect(link.allowsRotation()).toBe(false)
    expect(link.getLinkDataVersion()).toBeNull()

    const typed = plainLink({is_admin: true, version: 3})
    expect(typed.isAdminUser()).toBe(true)
    expect(typed.getLinkDataVersion()).toBe(3)

    // Boolean is not a valid integer version
    const boolVersion = plainLink({version: true})
    expect(boolVersion.getLinkDataVersion()).toBeNull()
})

// ── test 9 ─────────────────────────────────────────────────────────────────────
test('hasEncryptedData detects ciphertext; printable text and JSON are not encrypted', async () => {
    const key = platform.getRandomBytes(32)
    const enc = await encryptedLink({secret: 'value'}, key)
    expect(enc.hasEncryptedData()).toBe(true)

    const text = new KeeperRecordLink({
        recordUid: 'RU',
        data: platform.bytesToBase64(platform.stringToBytes('just plain readable text, not json')),
        path: undefined
    }, 'owner')
    expect(text.hasEncryptedData()).toBe(false)

    expect(plainLink({a: 1}).hasEncryptedData()).toBe(false)

    const noData = new KeeperRecordLink({recordUid: 'RU', data: undefined, path: undefined}, 'owner')
    expect(noData.hasEncryptedData()).toBe(false)
})

// ── test 10 ────────────────────────────────────────────────────────────────────
test('getSettingsForPath decrypts encrypted payload for a matching path', async () => {
    const key = platform.getRandomBytes(32)
    const link = await encryptedLink({customSetting: 42}, key, 'custom_settings')

    const data = await link.getSettingsForPath('custom_settings', key)
    expect(data).not.toBeNull()
    expect(data!['customSetting']).toBe(42)
    expect(await link.getSettingsForPath('other', key)).toBeNull()
})

// ── test 11 ────────────────────────────────────────────────────────────────────
test('meta link: permission booleans fall back to allowedSettings', async () => {
    const link = plainLink({
        allowedSettings: {
            rotation: true, connections: true, portForwards: true,
            sessionRecording: true, typescriptRecording: false,
            aiEnabled: true, aiSessionTerminate: true, remoteBrowserIsolation: true
        },
        rotateOnTermination: false,
        version: 1,
        no_update_services: true
    }, 'meta')

    expect(link.allowsRotation()).toBe(true)
    expect(link.allowsConnections()).toBe(true)
    expect(link.allowsPortForwards()).toBe(true)
    expect(link.allowsSessionRecording()).toBe(true)
    expect(link.allowsTypescriptRecording()).toBe(false)
    expect(link.allowsRemoteBrowserIsolation()).toBe(true)
    expect(link.aiEnabled()).toBe(true)
    expect(link.aiSessionTerminate()).toBe(true)

    expect(link.rotatesOnTermination()).toBe(false)
    expect(link.getLinkDataVersion()).toBe(1)
    expect(link.noUpdateServices()).toBe(true)

    const allowed = link.getAllowedSettings()
    expect(allowed['rotation']).toBe(true)

    const meta = await link.getMetaData()
    expect(meta).not.toBeNull()
    expect(meta!['version']).toBe(1)
    expect(await plainLink({}, undefined).getMetaData()).toBeNull()
})

// ── test 12 ────────────────────────────────────────────────────────────────────
test('credential link: user flags and rotation_settings object', () => {
    const link = plainLink({
        is_admin: true, is_iam_user: false, belongs_to: true, is_launch_credential: true,
        rotation_settings: {schedule: '', pwd_complexity: 'ZmFrZS1jb21wbGV4aXR5',
            disabled: false, noop: false, saas_record_uid_list: []}
    })

    expect(link.isAdminUser()).toBe(true)
    expect(link.isIamUser()).toBe(false)
    expect(link.belongsTo()).toBe(true)
    expect(link.isLaunchCredential()).toBe(true)

    const rs = link.getRotationSettings()
    expect(rs).not.toBeNull()
    expect(rs!['schedule']).toBe('')
    expect(rs!['disabled']).toBe(false)
    expect(rs!['saas_record_uid_list']).toEqual([])

    expect(plainLink({is_admin: true}).getRotationSettings()).toBeNull()
})

// ── test 13 ────────────────────────────────────────────────────────────────────
test('data-less reference link answers all accessors with false/null', async () => {
    const link = new KeeperRecordLink({recordUid: 'RU_ref', data: undefined, path: undefined}, 'owner')

    expect(link.recordUid).toBe('RU_ref')
    expect(link.isAdminUser()).toBe(false)
    expect(link.allowsRotation()).toBe(false)
    expect(link.getLinkDataVersion()).toBeNull()
    expect(link.getDecodedData()).toBeNull()
    expect(await link.getDecryptedData(platform.getRandomBytes(32))).toBeNull()
    expect(await link.getLinkData()).toBeNull()
    expect(link.getAllowedSettings()).toEqual({})
    expect(link.getRotationSettings()).toBeNull()
    expect(link.hasReadableData()).toBe(false)
    expect(link.hasEncryptedData()).toBe(false)
})

// ── test 14 ────────────────────────────────────────────────────────────────────
test('ai_settings link decrypts to riskLevels payload', async () => {
    const key = platform.getRandomBytes(32)
    const payload = {
        version: 'v1.0.0',
        riskLevels: {
            critical: {tags: {allow: [], deny: []}, aiSessionTerminate: true},
            high: {tags: {allow: [], deny: []}, aiSessionTerminate: true},
            low: {tags: {allow: []}, aiSessionTerminate: false}
        }
    }
    const link = await encryptedLink(payload, key, 'ai_settings')

    const data = await link.getAiSettingsData(key)
    expect(data).toEqual(payload)
    expect(link.getLinkDataVersion()).toBeNull() // version is a string here
})

// ── test 15 ────────────────────────────────────────────────────────────────────
test('jit_settings link decrypts to elevation payload', async () => {
    const key = platform.getRandomBytes(32)
    const payload = {
        createEphemeral: true, elevate: true,
        elevationMethod: 'group', elevationString: 'arn:aws', baseDistinguishedName: ''
    }
    const link = await encryptedLink(payload, key, 'jit_settings')

    expect(await link.getJitSettingsData(key)).toEqual(payload)
})

// ── test 16 ────────────────────────────────────────────────────────────────────
test('top-level boolean wins over allowedSettings fallback', () => {
    const link = plainLink({rotation: false, allowedSettings: {rotation: true}})
    expect(link.allowsRotation()).toBe(false)

    const onlyNested = plainLink({allowedSettings: {rotation: true}})
    expect(onlyNested.allowsRotation()).toBe(true)
})

// ── test 17 ────────────────────────────────────────────────────────────────────
test('ciphertext coincidentally starting with { or [ still decrypts (fallthrough)', async () => {
    const key = platform.getRandomBytes(32)
    const payload = {createEphemeral: true, elevate: true}
    const plaintext = platform.stringToBytes(JSON.stringify(payload))

    for (const marker of [0x7b /* { */, 0x5b /* [ */]) {
        const iv = new Uint8Array(12)
        iv[0] = marker
        randomBytes(11).copy(Buffer.from(iv.buffer), 1)

        const ciphertext = encryptWithCustomIv(plaintext, key, iv)
        const link = new KeeperRecordLink({
            recordUid: 'RU',
            data: platform.bytesToBase64(ciphertext),
            path: 'jit_settings'
        }, 'owner')

        const decoded = link.getDecodedData()
        expect(decoded).not.toBeNull()
        expect(decoded!.charCodeAt(0)).toBe(marker)

        expect(await link.getLinkData(key)).toEqual(payload)
        expect(await link.getJitSettingsData(key)).toEqual(payload)
        expect(await link.getSettingsForPath('jit_settings', key)).toEqual(payload)
        expect(await link.getLinkData(undefined)).toBeNull()
    }

    // Plain JSON fast path is unaffected
    expect(await plainLink({a: 1}).getLinkData()).toEqual({a: 1})
})
