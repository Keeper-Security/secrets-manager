import {KeeperHttpResponse, KeyValueStorage, platform} from './platform'
import {webSafe64FromBytes, webSafe64ToBytes} from './utils'

export {KeyValueStorage} from './platform'

let packageVersion = '[VI]{version}[/VI]'
const KEY_HOSTNAME = 'hostname' // base url for the Secrets Manager service
const KEY_TRANSMISSION_KEY = 'transmissionKey'
const KEY_SERVER_PUBIC_KEY_ID = 'serverPublicKeyId'
const KEY_CLIENT_ID = 'clientId'
const KEY_CLIENT_KEY = 'clientKey' // The key that is used to identify the client before public key
const KEY_APP_KEY = 'appKey' // The application key with which all secrets are encrypted
const KEY_PRIVATE_KEY = 'privateKey' // The client's private key
const CLIENT_ID_HASH_TAG = 'KEEPER_SECRETS_MANAGER_CLIENT_ID' // Tag for hashing the client key to client id

let keeperPublicKeys: Record<number, Uint8Array>

export const initialize = (pkgVersion?: string) => {
    if (pkgVersion) {
        packageVersion = pkgVersion
    }
    let keyNumber = 7
    keeperPublicKeys = [
        'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
        'BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ',
        'BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g',
        'BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg',
        'BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk',
        'BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY',
        'BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI',
        'BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE',
        'BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8',
        'BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c',
        'BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU'
    ].reduce((keys, key) => {
        keys[keyNumber++] = webSafe64ToBytes(key)
        return keys
    }, {})
}

type TransmissionKey = {
    publicKeyId: number
    encryptedKey: Uint8Array
}

type GetPayload = {
    clientVersion: string
    clientId: string
    publicKey?: string   // passed once when binding
    requestedRecords?: string[] // only return these records
}

type UpdatePayload = {
    clientVersion: string
    clientId: string
    recordUid?: string   // for update, uid of the record
    data?: string        // for update, the record data
}

type SecretsManagerResponseFolder = {
    folderUid: string
    folderKey: string
    records: SecretsManagerResponseRecord[]
}

type SecretsManagerResponseRecord = {
    recordUid: string
    recordKey: string
    data: string
    files: SecretsManagerResponseFile[]
}

type SecretsManagerResponseFile = {
    fileUid: string
    fileKey: string
    data: string
    url: string
    thumbnailUrl: string
}

type SecretsManagerResponse = {
    encryptedAppKey: string
    folders: SecretsManagerResponseFolder[]
    records: SecretsManagerResponseRecord[]
}

export type KeeperSecrets = {
    records: KeeperRecord[]
}

export type KeeperRecord = {
    recordUid: string
    folderUid?: string
    data: any
    files?: KeeperFile[]
}

export type KeeperFile = {
    fileUid: string
    data: any
    url?: string
    thumbnailUrl?: string
}

type KeeperError = {
    error?: string
    key_id?: number
}

const prepareGetPayload = async (storage: KeyValueStorage, recordsFilter?: string[]): Promise<GetPayload> => {
    const clientId = await storage.getString(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Id is missing from the configuration')
    }
    const payload: GetPayload = {
        clientVersion: 'ms' + packageVersion, // TODO generate client version for SM
        clientId: clientId
    }
    const appKey = await storage.getBytes(KEY_APP_KEY)
    if (!appKey) {
        const publicKey = await platform.exportPublicKey(KEY_PRIVATE_KEY, storage)
        payload.publicKey = platform.bytesToBase64(publicKey)
    }
    if (recordsFilter) {
        payload.requestedRecords = recordsFilter
    }
    return payload
}

const prepareUpdatePayload = async (storage: KeyValueStorage, record: KeeperRecord): Promise<UpdatePayload> => {
    const clientId = await storage.getString(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Id is missing from the configuration')
    }
    const recordBytes = platform.stringToBytes(JSON.stringify(record.data))
    const encryptedRecord = await platform.encrypt(recordBytes, record.recordUid)
    return {
        clientVersion: 'ms' + packageVersion, // TODO generate client version for SM
        clientId: clientId,
        recordUid: record.recordUid,
        data: webSafe64FromBytes(encryptedRecord)
    }
}

export const generateTransmissionKey = async (storage: KeyValueStorage): Promise<TransmissionKey> => {
    const transmissionKey = platform.getRandomBytes(32)
    await platform.importKey(KEY_TRANSMISSION_KEY, transmissionKey)
    const keyNumberString = await storage.getString(KEY_SERVER_PUBIC_KEY_ID)
    const keyNumber = keyNumberString ? Number(keyNumberString) : 7
    const keeperPublicKey = keeperPublicKeys[keyNumber]
    if (!keeperPublicKey) {
        throw new Error(`Key number ${keyNumber} is not supported`)
    }
    const encryptedKey = await platform.publicEncrypt(transmissionKey, keeperPublicKeys[keyNumber])
    return {
        publicKeyId: keyNumber,
        encryptedKey: encryptedKey
    }
}

const encryptAndSignPayload = async (storage: KeyValueStorage, transmissionKey: TransmissionKey, payload: GetPayload | UpdatePayload): Promise<{ encryptedPayload: Uint8Array, signature: Uint8Array }> => {
    const payloadBytes = platform.stringToBytes(JSON.stringify(payload))
    const encryptedPayload = await platform.encrypt(payloadBytes, KEY_TRANSMISSION_KEY)
    const signatureBase = Uint8Array.of(...transmissionKey.encryptedKey, ...encryptedPayload)
    const signature = await platform.sign(signatureBase, KEY_PRIVATE_KEY, storage)
    return {encryptedPayload, signature}
}

const postQuery = async (storage: KeyValueStorage, path: string, payload: GetPayload | UpdatePayload): Promise<KeeperHttpResponse> => {
    const hostName = await storage.getString(KEY_HOSTNAME)
    if (!hostName) {
        throw new Error('hostname is missing from the configuration')
    }
    const url = `https://${hostName}/api/rest/sm/v1/${path}`
    while (true) {
        const transmissionKey = await generateTransmissionKey(storage)
        const {encryptedPayload, signature} = await encryptAndSignPayload(storage, transmissionKey, payload)
        const httpResponse = await platform.post(url, encryptedPayload, {
            PublicKeyId: transmissionKey.publicKeyId.toString(),
            TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
            Authorization: `Signature ${platform.bytesToBase64(signature)}`
        })
        if (httpResponse.statusCode !== 200) {
            const errorMessage = platform.bytesToString(httpResponse.data.slice(0, 1000))
            try {
                const errorObj: KeeperError = JSON.parse(errorMessage)
                if (errorObj.error === 'key') {
                    await storage.saveString(KEY_SERVER_PUBIC_KEY_ID, errorObj.key_id!.toString())
                    continue
                }
            } catch {
            }
            throw new Error(errorMessage)
        }
        return httpResponse
    }
}

const decryptRecord = async (record: SecretsManagerResponseRecord): Promise<KeeperRecord> => {
    const decryptedRecord = await platform.decrypt(platform.base64ToBytes(record.data), record.recordUid)
    const keeperRecord: KeeperRecord = {
        recordUid: record.recordUid,
        data: JSON.parse(platform.bytesToString(decryptedRecord))
    }
    if (record.files) {
        keeperRecord.files = []
        for (const file of record.files) {
            await platform.unwrap(platform.base64ToBytes(file.fileKey), file.fileUid, record.recordUid)
            const decryptedFile = await platform.decrypt(platform.base64ToBytes(file.data), file.fileUid)
            keeperRecord.files.push({
                fileUid: file.fileUid,
                data: JSON.parse(platform.bytesToString(decryptedFile)),
                url: file.url,
                thumbnailUrl: file.thumbnailUrl
            })
        }
    }
    return keeperRecord
}

const fetchAndDecryptSecrets = async (storage: KeyValueStorage, recordsFilter?: string[]): Promise<{ secrets: KeeperSecrets, justBound: boolean }> => {
    const payload = await prepareGetPayload(storage, recordsFilter)
    const httpResponse = await postQuery(storage, 'get_secret', payload)
    const decryptedResponse = await platform.decrypt(httpResponse.data, KEY_TRANSMISSION_KEY)
    const response = JSON.parse(platform.bytesToString(decryptedResponse)) as SecretsManagerResponse

    const records: KeeperRecord[] = []
    let justBound = false
    if (response.encryptedAppKey) {
        justBound = true
        await platform.unwrap(platform.base64ToBytes(response.encryptedAppKey), KEY_APP_KEY, KEY_CLIENT_KEY, storage)
        await storage.delete(KEY_CLIENT_KEY)
    }
    if (response.records) {
        for (const record of response.records) {
            await platform.unwrap(platform.base64ToBytes(record.recordKey), record.recordUid, KEY_APP_KEY, storage, true)
            const decryptedRecord = await decryptRecord(record)
            records.push(decryptedRecord)
        }
    }
    if (response.folders) {
        for (const folder of response.folders) {
            await platform.unwrap(platform.base64ToBytes(folder.folderKey), folder.folderUid, KEY_APP_KEY, storage, true)
            for (const record of folder.records) {
                await platform.unwrap(platform.base64ToBytes(record.recordKey), record.recordUid, folder.folderUid)
                const decryptedRecord = await decryptRecord(record)
                decryptedRecord.folderUid = folder.folderUid
                records.push(decryptedRecord)
            }
        }
    }
    const secrets: KeeperSecrets = {
        records: records
    }
    return {secrets, justBound}
}

export const getClientId = async (clientKey: string): Promise<string> => {
    const clientKeyHash = await platform.hash(webSafe64ToBytes(clientKey), CLIENT_ID_HASH_TAG)
    return platform.bytesToBase64(clientKeyHash)
}

export const initializeStorage = async (storage: KeyValueStorage, clientKey?: string, hostName?: string | 'keepersecurity.com' | 'keepersecurity.eu' | 'keepersecurity.au') => {
    const existingClientId = await storage.getString(KEY_CLIENT_ID)
    if (existingClientId && !clientKey) {
        return
    }
    if (!clientKey) {
        throw new Error(`Storage is not initialized`)
    }
    const clientKeyBytes = webSafe64ToBytes(clientKey)
    const clientKeyHash = await platform.hash(clientKeyBytes, CLIENT_ID_HASH_TAG)
    const clientId = platform.bytesToBase64(clientKeyHash)
    if (existingClientId && existingClientId === clientId) {
        return  // the storage is already initialized
    }
    if (existingClientId) {
        throw new Error(`The storage is already initialized with a different client Id (${existingClientId})`)
    }
    await storage.saveString(KEY_HOSTNAME, hostName!)
    await storage.saveString(KEY_CLIENT_ID, clientId)
    await platform.importKey(KEY_CLIENT_KEY, clientKeyBytes, storage)
    await platform.generatePrivateKey(KEY_PRIVATE_KEY, storage)
}

export const getSecrets = async (storage: KeyValueStorage, recordsFilter?: string[]): Promise<KeeperSecrets> => {
    const {secrets, justBound} = await fetchAndDecryptSecrets(storage, recordsFilter)
    if (justBound) {
        try {
            await fetchAndDecryptSecrets(storage, recordsFilter)
        } catch (e) {
            console.error(e)
        }
    }
    return secrets
}

export const updateSecret = async (storage: KeyValueStorage, record: KeeperRecord): Promise<void> => {
    const payload = await prepareUpdatePayload(storage, record)
    await postQuery(storage, 'update_secret', payload)
}

export const downloadFile = async (file: KeeperFile): Promise<Uint8Array> => {
    const fileResponse = await platform.get(file.url!, {})
    return platform.decrypt(fileResponse.data, file.fileUid)
}

export const downloadThumbnail = async (file: KeeperFile): Promise<Uint8Array> => {
    const fileResponse = await platform.get(file.thumbnailUrl!, {})
    return platform.decrypt(fileResponse.data, file.fileUid)
}
