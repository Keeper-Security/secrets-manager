import {KeeperHttpResponse, KeyValueStorage, TransmissionKey, EncryptedPayload, platform} from './platform'
import {webSafe64FromBytes, webSafe64ToBytes} from './utils'

export {KeyValueStorage} from './platform'

let packageVersion = '[VI]{version}[/VI]'
const KEY_HOSTNAME = 'hostname' // base url for the Secrets Manager service
const KEY_SERVER_PUBIC_KEY_ID = 'serverPublicKeyId'
const KEY_CLIENT_ID = 'clientId'
const KEY_CLIENT_KEY = 'clientKey' // The key that is used to identify the client before public key
const KEY_APP_KEY = 'appKey' // The application key with which all secrets are encrypted
const KEY_OWNER_PUBLIC_KEY = 'appOwnerPublicKey' // The application owner public key, to create records
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

export type SecretManagerOptions = {
    storage: KeyValueStorage
    queryFunction?: (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload, allowUnverifiedCertificate?: boolean) => Promise<KeeperHttpResponse>
    allowUnverifiedCertificate?: boolean;
}

type GetPayload = {
    clientVersion: string
    clientId: string
    publicKey?: string   // passed once when binding
    requestedRecords?: string[] // only return these records
}

type DeletePayload = {
    clientVersion: string
    clientId: string
    recordUids: string[]
}

type UpdatePayload = {
    clientVersion: string
    clientId: string
    recordUid: string
    data: string
    revision?: number
}

type CreatePayload = {
    clientVersion: string
    clientId: string
    recordUid: string
    recordKey: string
    folderUid: string
    folderKey: string
    data: string
}

type FileUploadPayload = {
    clientVersion: string
    clientId: string
    fileRecordUid: string
    fileRecordKey: string
    fileRecordData: string
    ownerRecordUid: string
    ownerRecordData: string
    linkKey: string
    fileSize: number
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
    revision: number
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
    appData: string
    encryptedAppKey?: string  // received only on the first response
    appOwnerPublicKey?: string   // received only on the first response
    folders: SecretsManagerResponseFolder[]
    records: SecretsManagerResponseRecord[]
    expiresOn: number
    warnings: string[]
}

type SecretsManagerAddFileResponse = {
    url: string
    parameters: string
    successStatusCode: number
}

export type KeeperSecrets = {
    appData: {
        title: string
        type: string
    }
    expiresOn?: Date
    records: KeeperRecord[]
    warnings?: string[]
}

export type KeeperRecord = {
    recordUid: string
    folderUid?: string
    data: any
    revision?: number
    files?: KeeperFile[]
}

export type KeeperFile = {
    fileUid: string
    data: any
    url?: string
    thumbnailUrl?: string
}

export type KeeperFileUpload = {
    name: string
    title: string
    type?: string
    data: Uint8Array
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
        clientVersion: 'ms' + packageVersion,
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
        clientVersion: 'ms' + packageVersion,
        clientId: clientId,
        recordUid: record.recordUid,
        data: webSafe64FromBytes(encryptedRecord),
        revision: record.revision
    }
}

const prepareDeletePayload = async (storage: KeyValueStorage, recordUids: string[]): Promise<DeletePayload> => {
    const clientId = await storage.getString(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Id is missing from the configuration')
    }
    console.log("recordUIDs: ", recordUids);
    return {
        clientVersion: 'ms' + packageVersion,
        clientId: clientId,
        recordUids: recordUids
    }
}

const prepareCreatePayload = async (storage: KeyValueStorage, folderUid: string, recordData: any): Promise<CreatePayload> => {
    const clientId = await storage.getString(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Id is missing from the configuration')
    }
    const ownerPublicKey = await storage.getBytes(KEY_OWNER_PUBLIC_KEY)
    if (!ownerPublicKey) {
        throw new Error('Application owner public key is missing from the configuration')
    }
    const recordBytes = platform.stringToBytes(JSON.stringify(recordData))
    const recordKey = platform.getRandomBytes(32)
    const recordUid = platform.getRandomBytes(16)
    const encryptedRecord = await platform.encryptWithKey(recordBytes, recordKey)
    const encryptedRecordKey = await platform.publicEncrypt(recordKey, ownerPublicKey)
    const encryptedFolderKey = await platform.encrypt(recordKey, folderUid)
    return {
        clientVersion: 'ms' + packageVersion,
        clientId: clientId,
        recordUid: webSafe64FromBytes(recordUid),
        recordKey: platform.bytesToBase64(encryptedRecordKey),
        folderUid: folderUid,
        folderKey: platform.bytesToBase64(encryptedFolderKey),
        data: webSafe64FromBytes(encryptedRecord)
    }
}

const prepareFileUploadPayload = async (storage: KeyValueStorage, ownerRecord: KeeperRecord, file: KeeperFileUpload): Promise<{
    payload: FileUploadPayload,
    encryptedFileData: Uint8Array
}> => {
    const clientId = await storage.getString(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Id is missing from the configuration')
    }
    const ownerPublicKey = await storage.getBytes(KEY_OWNER_PUBLIC_KEY)
    if (!ownerPublicKey) {
        throw new Error('Application owner public key is missing from the configuration')
    }
    const fileData = {
        name: file.name,
        size: file.data.length,
        title: file.title,
        lastModified: new Date().getTime(),
        type: file.type
    }
    const fileRecordBytes = platform.stringToBytes(JSON.stringify(fileData))
    const fileRecordKey = platform.getRandomBytes(32)
    const fileRecordUid = webSafe64FromBytes(platform.getRandomBytes(16))
    const encryptedFileRecord = await platform.encryptWithKey(fileRecordBytes, fileRecordKey)
    const encryptedFileRecordKey = await platform.publicEncrypt(fileRecordKey, ownerPublicKey)
    const encryptedLinkKey = await platform.encrypt(fileRecordKey, ownerRecord.recordUid)
    const encryptedFileData = await platform.encryptWithKey(file.data, fileRecordKey)

    let fileRef = ownerRecord.data.fields.find(x => x.type == 'fileRef')
    if (fileRef) {
        fileRef.value.push(fileRecordUid)
    } else {
        fileRef = {type: 'fileRef', value: [fileRecordUid]}
        ownerRecord.data.fields.push(fileRef)
    }
    const ownerRecordBytes = platform.stringToBytes(JSON.stringify(ownerRecord.data))
    const encryptedOwnerRecord = await platform.encrypt(ownerRecordBytes, ownerRecord.recordUid)

    return {
        payload: {
            clientVersion: 'ms' + packageVersion,
            clientId: clientId,
            fileRecordUid: fileRecordUid,
            fileRecordKey: platform.bytesToBase64(encryptedFileRecordKey),
            fileRecordData: webSafe64FromBytes(encryptedFileRecord),
            ownerRecordUid: ownerRecord.recordUid,
            ownerRecordData: webSafe64FromBytes(encryptedOwnerRecord),
            linkKey: platform.bytesToBase64(encryptedLinkKey),
            fileSize: encryptedFileData.length
        },
        encryptedFileData
    }
}

const postFunction = async (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload, allowUnverifiedCertificate?: boolean): Promise<KeeperHttpResponse> => {
    return platform.post(url, payload.payload,
        {
            PublicKeyId: transmissionKey.publicKeyId.toString(),
            TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
            Authorization: `Signature ${platform.bytesToBase64(payload.signature)}`
        }, allowUnverifiedCertificate)
}

export const generateTransmissionKey = async (storage: KeyValueStorage): Promise<TransmissionKey> => {
    const transmissionKey = platform.getRandomBytes(32)
    const keyNumberString = await storage.getString(KEY_SERVER_PUBIC_KEY_ID)
    const keyNumber = keyNumberString ? Number(keyNumberString) : 7
    const keeperPublicKey = keeperPublicKeys[keyNumber]
    if (!keeperPublicKey) {
        throw new Error(`Key number ${keyNumber} is not supported`)
    }
    const encryptedKey = await platform.publicEncrypt(transmissionKey, keeperPublicKeys[keyNumber])
    return {
        publicKeyId: keyNumber,
        key: transmissionKey,
        encryptedKey: encryptedKey
    }
}

const encryptAndSignPayload = async (storage: KeyValueStorage, transmissionKey: TransmissionKey, payload: GetPayload | UpdatePayload | FileUploadPayload): Promise<EncryptedPayload> => {
    const payloadBytes = platform.stringToBytes(JSON.stringify(payload))
    const encryptedPayload = await platform.encryptWithKey(payloadBytes, transmissionKey.key)
    const signatureBase = Uint8Array.of(...transmissionKey.encryptedKey, ...encryptedPayload)
    const signature = await platform.sign(signatureBase, KEY_PRIVATE_KEY, storage)
    return {payload: encryptedPayload, signature}
}

const postQuery = async (options: SecretManagerOptions, path: string, payload: GetPayload | UpdatePayload | FileUploadPayload): Promise<Uint8Array> => {
    const hostName = await options.storage.getString(KEY_HOSTNAME)
    if (!hostName) {
        throw new Error('hostname is missing from the configuration')
    }
    const url = `https://${hostName}/api/rest/sm/v1/${path}`
    while (true) {
        const transmissionKey = await generateTransmissionKey(options.storage)
        const encryptedPayload = await encryptAndSignPayload(options.storage, transmissionKey, payload)
        const response = await (options.queryFunction || postFunction)(url, transmissionKey, encryptedPayload, options.allowUnverifiedCertificate)
        if (response.statusCode !== 200) {
            let errorMessage
            if (response.data) {
                errorMessage = platform.bytesToString(response.data.slice(0, 1000))
                try {
                    const errorObj: KeeperError = JSON.parse(errorMessage)
                    if (errorObj.error === 'key') {
                        await options.storage.saveString(KEY_SERVER_PUBIC_KEY_ID, errorObj.key_id!.toString())
                        continue
                    }
                } catch {
                }
            } else {
                errorMessage = `unknown ksm error, code ${response.statusCode}`
            }
            throw new Error(errorMessage)
        }
        return response.data
            ? platform.decryptWithKey(response.data, transmissionKey.key)
            : new Uint8Array()
    }
}

const decryptRecord = async (record: SecretsManagerResponseRecord, storage?: KeyValueStorage): Promise<KeeperRecord> => {
    const decryptedRecord = await platform.decrypt(platform.base64ToBytes(record.data), record.recordUid || KEY_APP_KEY, storage)
    const keeperRecord: KeeperRecord = {
        recordUid: record.recordUid,
        data: JSON.parse(platform.bytesToString(decryptedRecord)),
        revision: record.revision
    }
    if (record.files) {
        keeperRecord.files = []
        for (const file of record.files) {
            await platform.unwrap(platform.base64ToBytes(file.fileKey), file.fileUid, record.recordUid || KEY_APP_KEY)
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

const fetchAndDecryptSecrets = async (options: SecretManagerOptions, recordsFilter?: string[]): Promise<{ secrets: KeeperSecrets, justBound: boolean }> => {
    const storage = options.storage
    const payload = await prepareGetPayload(storage, recordsFilter)
    const responseData = await postQuery(options, 'get_secret', payload)
    const response = JSON.parse(platform.bytesToString(responseData)) as SecretsManagerResponse

    const records: KeeperRecord[] = []
    let justBound = false
    if (response.encryptedAppKey) {
        justBound = true
        await platform.unwrap(platform.base64ToBytes(response.encryptedAppKey), KEY_APP_KEY, KEY_CLIENT_KEY, storage)
        await storage.delete(KEY_CLIENT_KEY)
        await storage.saveString(KEY_OWNER_PUBLIC_KEY, response.appOwnerPublicKey!)
    }
    if (response.records) {
        for (const record of response.records) {
            if (record.recordKey) {
                await platform.unwrap(platform.base64ToBytes(record.recordKey), record.recordUid, KEY_APP_KEY, storage, true)
            }
            const decryptedRecord = await decryptRecord(record, storage)
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
    let appData
    if (response.appData) {
        appData = JSON.parse(platform.bytesToString(await platform.decrypt(webSafe64ToBytes(response.appData), KEY_APP_KEY, storage)))
    }
    const secrets: KeeperSecrets = {
        appData: appData,
        expiresOn: response.expiresOn > 0 ? new Date(response.expiresOn) : undefined,
        records: records
    }
    if (response.warnings && response.warnings.length > 0) {
        secrets.warnings = response.warnings
    }
    return {secrets, justBound}
}

export const getClientId = async (clientKey: string): Promise<string> => {
    const clientKeyHash = await platform.hash(webSafe64ToBytes(clientKey), CLIENT_ID_HASH_TAG)
    return platform.bytesToBase64(clientKeyHash)
}

export const initializeStorage = async (storage: KeyValueStorage, oneTimeToken: string, hostName?: string | 'keepersecurity.com' | 'keepersecurity.eu' | 'keepersecurity.au') => {
    const tokenParts = oneTimeToken.split(':')
    let host, clientKey
    if (tokenParts.length === 1) {
        if (!hostName) {
            throw new Error('The hostname must be present in the token or as a parameter')
        }
        host = hostName
        clientKey = oneTimeToken
    } else {
        host = {
            US: 'keepersecurity.com',
            EU: 'keepersecurity.eu',
            AU: 'keepersecurity.com.au',
            GOV: 'govcloud.keepersecurity.us'
        }[tokenParts[0].toUpperCase()]
        if (!host) {
            host = tokenParts[0]
        }
        clientKey = tokenParts[1]
    }
    const clientKeyBytes = webSafe64ToBytes(clientKey)
    const clientKeyHash = await platform.hash(clientKeyBytes, CLIENT_ID_HASH_TAG)
    const clientId = platform.bytesToBase64(clientKeyHash)
    const existingClientId = await storage.getString(KEY_CLIENT_ID)
    if (existingClientId) {
        if (existingClientId === clientId) {
            return  // the storage is already initialized
        }
        throw new Error(`The storage is already initialized with a different client Id (${existingClientId})`)
    }
    await storage.saveString(KEY_HOSTNAME, host)
    await storage.saveString(KEY_CLIENT_ID, clientId)
    await platform.importKey(KEY_CLIENT_KEY, clientKeyBytes, storage)
    await platform.generatePrivateKey(KEY_PRIVATE_KEY, storage)
}

export const getSecrets = async (options: SecretManagerOptions, recordsFilter?: string[]): Promise<KeeperSecrets> => {
    platform.cleanKeyCache()
    const {secrets, justBound} = await fetchAndDecryptSecrets(options, recordsFilter)
    if (justBound) {
        try {
            await fetchAndDecryptSecrets(options, recordsFilter)
        } catch (e) {
            console.error(e)
        }
    }
    return secrets
}

export const findSecretsByTitle = async (records: KeeperRecord[], recordTitle: string): Promise<KeeperRecord[]> => {
    return records.filter(record => record.data.title === recordTitle)
}

export const findSecretByTitle = async (records: KeeperRecord[], recordTitle: string): Promise<KeeperRecord | undefined> => {
    return records.find(record => record.data.title === recordTitle)
}

export const getSecretsByTitle = async (options: SecretManagerOptions, recordTitle: string): Promise<KeeperRecord[]> => {
    const secrets  = await getSecrets(options)
    return secrets.records.filter(record => record.data.title === recordTitle)
}

export const getSecretByTitle = async (options: SecretManagerOptions, recordTitle: string): Promise<KeeperRecord | undefined> => {
    const secrets  = await getSecrets(options)
    return secrets.records.find(record => record.data.title === recordTitle)
}

export const updateSecret = async (options: SecretManagerOptions, record: KeeperRecord): Promise<void> => {
    const payload = await prepareUpdatePayload(options.storage, record)
    await postQuery(options, 'update_secret', payload)
}

export const deleteSecret = async (options: SecretManagerOptions, recordUids: string[]): Promise<void> => {
    const payload = await prepareDeletePayload(options.storage, recordUids)
    await postQuery(options, 'delete_secret', payload)
}

export const createSecret = async (options: SecretManagerOptions, folderUid: string, recordData: any): Promise<string> => {
    if (!platform.hasKeysCached()) {
        await getSecrets(options) // need to warm up keys cache before posting a record
    }
    const payload = await prepareCreatePayload(options.storage, folderUid, recordData)
    await postQuery(options, 'create_secret', payload)
    return payload.recordUid
}

export const downloadFile = async (file: KeeperFile): Promise<Uint8Array> => {
    const fileResponse = await platform.get(file.url!, {})
    return platform.decrypt(fileResponse.data, file.fileUid)
}

export const downloadThumbnail = async (file: KeeperFile): Promise<Uint8Array> => {
    const fileResponse = await platform.get(file.thumbnailUrl!, {})
    return platform.decrypt(fileResponse.data, file.fileUid)
}

export const uploadFile = async (options: SecretManagerOptions, ownerRecord: KeeperRecord, file: KeeperFileUpload): Promise<string> => {
    const { payload, encryptedFileData } = await prepareFileUploadPayload(options.storage, ownerRecord, file)
    const responseData = await postQuery(options, 'add_file', payload)
    const response = JSON.parse(platform.bytesToString(responseData)) as SecretsManagerAddFileResponse
    const uploadResult = await platform.fileUpload(response.url, JSON.parse(response.parameters), encryptedFileData)
    if (uploadResult.statusCode !== response.successStatusCode) {
        throw new Error(`Upload failed (${uploadResult.statusMessage}), code ${uploadResult.statusCode}`)
    }
    return payload.fileRecordUid
}
