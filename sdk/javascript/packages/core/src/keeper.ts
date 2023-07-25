import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, platform, TransmissionKey} from './platform'
import {webSafe64FromBytes, webSafe64ToBytes, tryParseInt} from './utils'
import {parseNotation} from './notation'

export {KeyValueStorage} from './platform'

let packageVersion = '[VI]{version}[/VI]'
const KEY_HOSTNAME = 'hostname' // base url for the Secrets Manager service
const KEY_SERVER_PUBLIC_KEY_ID = 'serverPublicKeyId'
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
    allowUnverifiedCertificate?: boolean
}

export type QueryOptions = {
    recordsFilter?: string[]
    foldersFilter?: string[]
}

export type CreateOptions = {
    folderUid: string
    subFolderUid?: string
}

type AnyPayload =
    GetPayload
    | DeletePayload
    | DeleteFolderPayload
    | UpdatePayload
    | CreatePayload
    | CreateFolderPayload
    | UpdateFolderPayload
    | FileUploadPayload

type CommonPayload = {
    clientVersion: string
    clientId: string
}

type GetPayload = CommonPayload & {
    publicKey?: string   // passed once when binding
    requestedRecords?: string[] // only return these records
    requestedFolders?: string[] // only return these folders
}

type DeletePayload = CommonPayload & {
    recordUids: string[]
}

type DeleteFolderPayload = CommonPayload & {
    folderUids: string[]
    forceDeletion: boolean
}

type UpdatePayload = CommonPayload & {
    recordUid: string
    data: string
    revision: number
}

type CreatePayload = CommonPayload & {
    recordUid: string
    recordKey: string
    folderUid: string
    folderKey: string
    data: string,
    subFolderUid?: string
}

type CreateFolderPayload = CommonPayload & {
    folderUid: string
    sharedFolderUid: string
    sharedFolderKey: string
    data: string
    parentUid?: string
}

type UpdateFolderPayload = CommonPayload & {
    folderUid: string
    data: string
}

type FileUploadPayload = CommonPayload & {
    fileRecordUid: string
    fileRecordKey: string
    fileRecordData: string
    ownerRecordUid: string
    ownerRecordData: string
    linkKey: string
    fileSize: number
}

type SecretsManagerDeleteResponseRecord = {
    errorMessage: string
    recordUid: string
    responseCode: string
}

type SecretsManagerDeleteResponseFolder =  {
    errorMessage: string
    folderUid: string
    responseCode: string
}

type SecretsManagerResponseFolder = {
    folderUid: string
    folderKey: string
    data: string
    parent: string
    revision: number
    records: SecretsManagerResponseRecord[]
}

type SecretsManagerResponseRecord = {
    recordUid: string
    recordKey: string
    data: string
    revision: number
    files: SecretsManagerResponseFile[]
    innerFolderUid: string
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
    extra?: {}
}

type SecretsManagerDeleteResponse = {
    records: SecretsManagerDeleteResponseRecord[]
    folders: SecretsManagerDeleteResponseFolder[]
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
    extra?: {}
}

export type KeeperRecord = {
    recordUid: string
    folderUid?: string
    innerFolderUid?: string
    data: any
    revision: number
    files?: KeeperFile[]
}

export type KeeperFolder = {
    folderUid: string
    parentUid?: string
    name?: string
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

const prepareGetPayload = async (storage: KeyValueStorage, queryOptions?: QueryOptions): Promise<GetPayload> => {
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
    if (queryOptions?.recordsFilter) {
        payload.requestedRecords = queryOptions.recordsFilter
    }
    if (queryOptions?.foldersFilter) {
        payload.requestedFolders = queryOptions.foldersFilter
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
    return {
        clientVersion: 'ms' + packageVersion,
        clientId: clientId,
        recordUids: recordUids
    }
}

const prepareDeleteFolderPayload = async (storage: KeyValueStorage, folderUids: string[], forceDeletion: boolean = false): Promise<DeleteFolderPayload> => {
    const clientId = await storage.getString(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Id is missing from the configuration')
    }
    return {
        clientVersion: 'ms' + packageVersion,
        clientId: clientId,
        folderUids: folderUids,
        forceDeletion: forceDeletion
    }
}

const prepareCreatePayload = async (storage: KeyValueStorage, createOptions: CreateOptions, recordData: any): Promise<CreatePayload> => {
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
    const encryptedFolderKey = await platform.encrypt(recordKey, createOptions.folderUid)
    return {
        clientVersion: 'ms' + packageVersion,
        clientId: clientId,
        recordUid: webSafe64FromBytes(recordUid),
        recordKey: platform.bytesToBase64(encryptedRecordKey),
        folderUid: createOptions.folderUid,
        folderKey: platform.bytesToBase64(encryptedFolderKey),
        data: webSafe64FromBytes(encryptedRecord),
        subFolderUid: createOptions.subFolderUid
    }
}

const prepareCreateFolderPayload = async (storage: KeyValueStorage, createOptions: CreateOptions, folderName: string): Promise<CreateFolderPayload> => {
    const clientId = await storage.getString(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Id is missing from the configuration')
    }
    const folderDataBytes = platform.stringToBytes(JSON.stringify({
        name: folderName
    }))
    const folderKey = platform.getRandomBytes(32)
    const folderUid = platform.getRandomBytes(16)
    const encryptedFolderData = await platform.encryptWithKey(folderDataBytes, folderKey, true)
    const encryptedFolderKey = await platform.encrypt(folderKey, createOptions.folderUid, undefined, true)
    return {
        clientVersion: 'ms' + packageVersion,
        clientId: clientId,
        folderUid: webSafe64FromBytes(folderUid),
        sharedFolderUid: createOptions.folderUid,
        sharedFolderKey: webSafe64FromBytes(encryptedFolderKey),
        data: webSafe64FromBytes(encryptedFolderData),
        parentUid: createOptions.subFolderUid
    }
}

const prepareUpdateFolderPayload = async (storage: KeyValueStorage, folderUid: string, folderName: string): Promise<UpdateFolderPayload> => {
    const clientId = await storage.getString(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Id is missing from the configuration')
    }
    const folderDataBytes = platform.stringToBytes(JSON.stringify({
        name: folderName
    }))
    const encryptedFolderData = await platform.encrypt(folderDataBytes, folderUid, undefined, true)
    return {
        clientVersion: 'ms' + packageVersion,
        clientId: clientId,
        folderUid: folderUid,
        data: webSafe64FromBytes(encryptedFolderData)
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
    const keyNumberString = await storage.getString(KEY_SERVER_PUBLIC_KEY_ID)
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

const postQuery = async (options: SecretManagerOptions, path: string, payload: AnyPayload): Promise<Uint8Array> => {
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
                        await options.storage.saveString(KEY_SERVER_PUBLIC_KEY_ID, errorObj.key_id!.toString())
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
        revision: record.revision,
    }
    if (record.innerFolderUid) {
        keeperRecord.innerFolderUid = record.innerFolderUid
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

const fetchAndDecryptSecrets = async (options: SecretManagerOptions, queryOptions?: QueryOptions): Promise<{ secrets: KeeperSecrets, justBound: boolean }> => {
    const storage = options.storage
    const payload = await prepareGetPayload(storage, queryOptions)
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
    if (response.extra && Object.keys(response.extra).length > 0) {
        secrets.extra = response.extra
    }
    return {secrets, justBound}
}

const getSharedFolderUid = (folders: SecretsManagerResponseFolder[], parent: string): string | undefined => {
    while (true) {
        const parentFolder = folders.find(x => x.folderUid === parent)
        if (!parentFolder) {
            return undefined
        }
        if (parentFolder.parent) {
            parent = parentFolder.parent
        } else {
            return parent
        }
    }
};

const fetchAndDecryptFolders = async (options: SecretManagerOptions): Promise<KeeperFolder[]> => {
    const storage = options.storage
    const payload = await prepareGetPayload(storage)
    const responseData = await postQuery(options, 'get_folders', payload)
    const response = JSON.parse(platform.bytesToString(responseData)) as SecretsManagerResponse
    const folders: KeeperFolder[] = []
    if (response.folders) {
        for (const folder of response.folders) {
            let decryptedData: Uint8Array
            const decryptedFolder: KeeperFolder = {
                folderUid: folder.folderUid
            }
            if (folder.parent) {
                decryptedFolder.parentUid = folder.parent
                const sharedFolderUid = getSharedFolderUid(response.folders, folder.parent)
                if (!sharedFolderUid) {
                    throw new Error('Folder data inconsistent - unable to locate shared folder')
                }
                await platform.unwrap(platform.base64ToBytes(folder.folderKey), folder.folderUid, sharedFolderUid, storage, true, true)
                decryptedData = await platform.decrypt(platform.base64ToBytes(folder.data), folder.folderUid, storage, true)
            } else {
                await platform.unwrap(platform.base64ToBytes(folder.folderKey), folder.folderUid, KEY_APP_KEY, storage, true)
                decryptedData = await platform.decrypt(platform.base64ToBytes(folder.data), folder.folderUid, storage, true)
            }
            decryptedFolder.name = JSON.parse(platform.bytesToString(decryptedData))['name']
            folders.push(decryptedFolder)
        }
    }
    return folders
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
            GOV: 'govcloud.keepersecurity.us',
            JP: 'keepersecurity.jp',
            CA: 'keepersecurity.ca'

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
    const queryOptions = recordsFilter
        ? {recordsFilter: recordsFilter}
        : undefined
    return getSecrets2(options, queryOptions)
}

export const getSecrets2 = async (options: SecretManagerOptions, queryOptions?: QueryOptions): Promise<KeeperSecrets> => {
    platform.cleanKeyCache()
    const {secrets, justBound} = await fetchAndDecryptSecrets(options, queryOptions)
    if (justBound) {
        try {
            await fetchAndDecryptSecrets(options, queryOptions)
        } catch (e) {
            console.error(e)
        }
    }
    return secrets
}

export const getFolders = async (options: SecretManagerOptions): Promise<KeeperFolder[]> => {
    platform.cleanKeyCache()
    return await fetchAndDecryptFolders(options)
}

// tryGetNotationResults returns a string list with all values specified by the notation or empty list on error.
// It simply logs any errors and continue returning an empty string list on error.
export const tryGetNotationResults = async (options: SecretManagerOptions, notation: string): Promise<string[]> => {
    try {
        return await getNotationResults(options, notation)
    }
    catch (e)
    {
        console.error(e)
    }
    return [] as string[]
}

// Notation:
// keeper://<uid|title>/<field|custom_field>/<type|label>[INDEX][PROPERTY]
// keeper://<uid|title>/file/<filename|fileUID>
// Record title, field label, filename sections need to escape the delimiters /[]\ -> \/ \[ \] \\
//
// GetNotationResults returns selection of the value(s) from a single field as a string list.
// Multiple records or multiple fields found results in error.
// Use record UID or unique record titles and field labels so that notation finds a single record/field.
//
// If field has multiple values use indexes - numeric INDEX specifies the position in the value list
// and PROPERTY specifies a single JSON object property to extract (see examples below for usage)
// If no indexes are provided - whole value list is returned (same as [])
// If PROPERTY is provided then INDEX must be provided too - even if it's empty [] which means all
//
// Extracting two or more but not all field values simultaneously is not supported - use multiple notation requests.
//
// Files are returned as URL safe base64 encoded string of the binary content
//
// Note: Integrations and plugins usually return single string value - result[0] or ''
//
// Examples:
//  RECORD_UID/file/filename.ext             => ['URL Safe Base64 encoded binary content']
//  RECORD_UID/field/url                     => ['127.0.0.1', '127.0.0.2'] or [] if empty
//  RECORD_UID/field/url[]                   => ['127.0.0.1', '127.0.0.2'] or [] if empty
//  RECORD_UID/field/url[0]                  => ['127.0.0.1'] or error if empty
//  RECORD_UID/custom_field/name[first]      => Error, numeric index is required to access field property
//  RECORD_UID/custom_field/name[][last]     => ['Smith', 'Johnson']
//  RECORD_UID/custom_field/name[0][last]    => ['Smith']
//  RECORD_UID/custom_field/phone[0][number] => '555-5555555'
//  RECORD_UID/custom_field/phone[1][number] => '777-7777777'
//  RECORD_UID/custom_field/phone[]          => ['{\'number\': \'555-555...\'}', '{\'number\': \'777...\'}']
//  RECORD_UID/custom_field/phone[0]         => ['{\'number\': \'555-555...\'}']

// getNotationResults returns a string list with all values specified by the notation or throws an error.
// Use tryGetNotationResults() to just log errors and continue returning an empty string list on error.
export const getNotationResults = async (options: SecretManagerOptions, notation: string): Promise<string[]> => {
    let result: string[] = []

    const parsedNotation = parseNotation(notation) // prefix, record, selector, footer
    if (parsedNotation.length < 3)
        throw new Error(`Invalid notation ${notation}`)

    if (parsedNotation[1].text == null)
        throw new Error(`Invalid notation ${notation}`)
    const recordToken = parsedNotation[1].text[0] // UID or Title
    if (parsedNotation[2].text == null)
        throw new Error(`Invalid notation ${notation}`)
    const selector = parsedNotation[2].text[0] // type|title|notes or file|field|custom_field

    // to minimize traffic - if it looks like a Record UID try to pull a single record
    let records: KeeperRecord[] = []
    if (/^[A-Za-z0-9_-]{22}$/.test(recordToken)) {
        const secrets = await getSecrets(options, [recordToken])
        records = secrets.records
        if (records.length > 1)
            throw new Error(`Notation error - found multiple records with same UID '${recordToken}'`)
    }

    // If RecordUID is not found - pull all records and search by title
    if (records.length < 1)
    {
        const secrets = await getSecrets(options)
        if (secrets?.records != null)
            records = await findSecretsByTitle(secrets.records, recordToken)
    }

    if (records.length > 1)
        throw new Error(`Notation error - multiple records match record '${recordToken}'`)
    if (records.length < 1)
        throw new Error(`Notation error - no records match record '${recordToken}'`)

    const record = records[0]
    const parameter = parsedNotation[2].parameter != null ? parsedNotation[2].parameter[0] : ''
    const index1 = parsedNotation[2].index1 != null ? parsedNotation[2].index1[0] : ''
    const index2 = parsedNotation[2].index2 != null ? parsedNotation[2].index2[0] : ''

    switch (selector.toLowerCase()) {
        case 'type': { if (record?.data?.type != null) result.push(record.data.type); break }
        case 'title': { if (record?.data?.title != null) result.push(record.data.title); break }
        case 'notes': { if (record?.data?.notes != null) result.push(record.data.notes); break }
        case 'file': {
            if (parameter == null)
                throw new Error(`Notation error - Missing required parameter: filename or file UID for files in record '${recordToken}'`)
            if ((record?.files?.length || 0) < 1)
                throw new Error(`Notation error - Record ${recordToken} has no file attachments.`)
            let files = record.files!.filter(x => parameter == x?.data?.name || parameter == x.fileUid)
            // file searches do not use indexes and rely on unique file names or fileUid
            const numFiles = (files == null ? 0 : files.length)
            if (numFiles > 1)
                throw new Error(`Notation error - Record ${recordToken} has multiple files matching the search criteria '${parameter}'`)
            if (numFiles < 1)
                throw new Error(`Notation error - Record ${recordToken} has no files matching the search criteria '${parameter}'`)
            const contents = await downloadFile(files[0])
            const text = webSafe64FromBytes(contents)
            result.push(text)
            break
        }
        case 'field':
        case 'custom_field': {
            if (parsedNotation[2].parameter == null)
                throw new Error('Notation error - Missing required parameter for the field (type or label): ex. /field/type or /custom_field/MyLabel')

            const fields = (selector.toLowerCase() == 'field' ? record.data.fields :
                            selector.toLowerCase() == 'custom_field' ? record.data.custom : null)
            if (!fields)
                throw new Error(`Notation error - Expected /field or /custom_field but found /${selector}`)

            const flds = fields.filter(x => parameter == x.type || parameter == x.label)
            if ((flds?.length || 0) > 1)
                throw new Error(`Notation error - Record ${recordToken} has multiple fields matching the search criteria '${parameter}'`)
            if ((flds?.length || 0) < 1)
                throw new Error(`Notation error - Record ${recordToken} has no fields matching the search criteria '${parameter}'`)
            const field = flds[0]
            //const fieldType = field?.type || ''

            const idx = tryParseInt(index1, -1) // -1 = full value
            // valid only if [] or missing - ex. /field/phone or /field/phone[]
            if (idx == -1 && !(parsedNotation[2].index1 == null || parsedNotation[2].index1[1] == '' || parsedNotation[2].index1[1] == '[]'))
                throw new Error(`Notation error - Invalid field index ${idx}.`)

            let values = (field?.value != null ? field.value as Object[] : [] as Object[])
            if (idx >= values.length)
                throw new Error(`Notation error - Field index out of bounds ${idx} >= ${values.length} for field ${parameter}`)
            if (idx >= 0) // single index
                values = [ values[idx] ]

            const fullObjValue = (parsedNotation[2].index2 == null || parsedNotation[2].index2[1] == '' || parsedNotation[2].index2[1] == '[]')
            let objPropertyName = ''
            if (parsedNotation[2].index2 != null)
                objPropertyName = parsedNotation[2].index2[0]

            const res: string[] = []
            for (let i = 0; i < values.length; i++) {
                const fldValue = values[i]
                // Do not throw here to allow for ex. field/name[][middle] to pull [middle] only where present
                // NB! Not all properties of a value are always required even when the field is marked as required
                // ex. On a required `name` field only 'first' and 'last' properties are required but not 'middle'
                // so missing property in a field value is not always an error
                if (fldValue == null)
                    console.log('Notation error - Empty field value for field ', parameter) // throw?

                if (fullObjValue) {
                    res.push(typeof fldValue === 'string' ? fldValue as string : JSON.stringify(fldValue))
                } else if (fldValue != null) {
                    if (objPropertyName in fldValue) {
                        let propKey = objPropertyName as keyof typeof fldValue
                        const propValue = fldValue[propKey]
                        res.push(typeof propValue === 'string' ? propValue as string : JSON.stringify(propValue))
                    } else
                    console.log(`Notation error - value object has no property '${objPropertyName}'`) // skip
                } else
                    console.log(`Notation error - Cannot extract property '${objPropertyName}' from null value.`)
            }

            if (res.length != values.length)
                console.log(`Notation warning - extracted ${res.length} out of ${values.length} values for '${objPropertyName}' property.`)
            if (res.length > 0)
                result.push.apply(result, res)
            break
        }
        default: { throw new Error(`Invalid notation ${notation}`) }
    }
    return result
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

export const deleteSecret = async (options: SecretManagerOptions, recordUids: string[]): Promise<SecretsManagerDeleteResponse> => {
    const payload = await prepareDeletePayload(options.storage, recordUids)
    const responseData = await postQuery(options, 'delete_secret', payload)
    return JSON.parse(platform.bytesToString(responseData)) as SecretsManagerDeleteResponse
}

export const deleteFolder = async (options: SecretManagerOptions, folderUids: string[], forceDeletion?: boolean): Promise<SecretsManagerDeleteResponse> => {
    const payload = await prepareDeleteFolderPayload(options.storage, folderUids, forceDeletion)
    const responseData = await postQuery(options, 'delete_folder', payload)
    return JSON.parse(platform.bytesToString(responseData)) as SecretsManagerDeleteResponse
}

export const createSecret = async (options: SecretManagerOptions, folderUid: string, recordData: any): Promise<string> => {
    if (!platform.hasKeysCached()) {
        await getSecrets(options) // need to warm up keys cache before posting a record
    }
    const payload = await prepareCreatePayload(options.storage, {folderUid: folderUid}, recordData)
    await postQuery(options, 'create_secret', payload)
    return payload.recordUid
}

export const createSecret2 = async (options: SecretManagerOptions, createOptions: CreateOptions, recordData: any): Promise<string> => {
    if (!platform.hasKeysCached()) {
        await getFolders(options) // need to warm up keys cache before posting a record
    }
    const payload = await prepareCreatePayload(options.storage, createOptions, recordData)
    await postQuery(options, 'create_secret', payload)
    return payload.recordUid
}

export const createFolder = async (options: SecretManagerOptions, createOptions: CreateOptions, folderName: string): Promise<string> => {
    if (!platform.hasKeysCached()) {
        await getSecrets(options) // need to warm up keys cache before posting a record
    }
    const payload = await prepareCreateFolderPayload(options.storage, createOptions, folderName)
    await postQuery(options, 'create_folder', payload)
    return payload.folderUid
}

export const updateFolder = async (options: SecretManagerOptions, folderUid: string, folderName: string): Promise<void> => {
    if (!platform.hasKeysCached()) {
        await getSecrets(options) // need to warm up keys cache before posting a record
    }
    const payload = await prepareUpdateFolderPayload(options.storage, folderUid, folderName)
    await postQuery(options, 'update_folder', payload)
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

export const addCustomField = (record: KeeperRecord, field: KeeperRecordField): void => {
    if (record.data.custom == null || record.data.custom == undefined)
        record.data.custom = []
    record.data.custom.push(field)
}

export class KeeperRecordField {
    type: string = ''
    label?: string
}

export class LoginField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'login'
        this.value = [value]
      }
}

export type PasswordComplexity = {
    length?: number
    caps?: number
    lowercase?: number
    digits?: number
    special?: number
}

export class PasswordField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    enforceGeneration? : boolean
    complexity? : PasswordComplexity
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'password'
        this.value = [value]
      }
}

export class UrlField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'url'
        this.value = [value]
      }
}

export class FileRefField extends KeeperRecordField {
    required? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'fileRef'
        this.value = [value]
      }
}

export class OneTimeCodeField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'oneTimeCode'
        this.value = [value]
      }
}

export type Name = {
    first?: string
    middle?: string
    last?: string
}

export class NameField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: Name[]
    constructor(value: Name) {
        super()
        this.type = 'name'
        this.value = [value]
      }
}

export class BirthDateField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: number[]
    constructor(value: number) {
        super()
        this.type = 'birthDate'
        this.value = [value]
      }
}

export class DateField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: number[]
    constructor(value: number) {
        super()
        this.type = 'date'
        this.value = [value]
      }
}

export class ExpirationDateField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: number[]
    constructor(value: number) {
        super()
        this.type = 'expirationDate'
        this.value = [value]
      }
}

export class TextField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'text'
        this.value = [value]
      }
}

export type SecurityQuestion = {
    question?: string
    answer?: string
}

export class SecurityQuestionField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: SecurityQuestion[]
    constructor(value: SecurityQuestion) {
        super()
        this.type = 'securityQuestion'
        this.value = [value]
      }
}

export class MultilineField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'multiline'
        this.value = [value]
      }
}

export class EmailField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'email'
        this.value = [value]
      }
}

export class CardRefField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'cardRef'
        this.value = [value]
      }
}

export class AddressRefField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'addressRef'
        this.value = [value]
      }
}

export class PinCodeField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'pinCode'
        this.value = [value]
      }
}

export type Phone = {
    region?: string
    number?: string
    ext?: string
    type?: string
}

export class PhoneField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: Phone[]
    constructor(value: Phone) {
        super()
        this.type = 'phone'
        this.value = [value]
      }
}

export class SecretField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'secret'
        this.value = [value]
      }
}

export class SecureNoteField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'note'
        this.value = [value]
      }
}

export class AccountNumberField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'accountNumber'
        this.value = [value]
      }
}

export type PaymentCard = {
    cardNumber?: string
    cardExpirationDate?: string
    cardSecurityCode?: string
}

export class PaymentCardField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: PaymentCard[]
    constructor(value: PaymentCard) {
        super()
        this.type = 'paymentCard'
        this.value = [value]
      }
}

export type BankAccount = {
    accountType?: string
    routingNumber?: string
    accountNumber?: string
    otherType?: string
}

export class BankAccountField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: BankAccount[]
    constructor(value: BankAccount) {
        super()
        this.type = 'bankAccount'
        this.value = [value]
      }
}

export type KeyPair = {
    publicKey?: string
    privateKey?: string
}

export class KeyPairField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: KeyPair[]
    constructor(value: KeyPair) {
        super()
        this.type = 'keyPair'
        this.value = [value]
      }
}

export type Host = {
    hostName?: string
    port?: string
}

export class HostField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: Host[]
    constructor(value: Host) {
        super()
        this.type = 'host'
        this.value = [value]
      }
}

export type Address = {
    street1?: string
    street2?: string
    city?: string
    state?: string
    country?: string
    zip?: string
}

export class AddressField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: Address[]
    constructor(value: Address) {
        super()
        this.type = 'address'
        this.value = [value]
      }
}

export class LicenseNumberField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'licenseNumber'
        this.value = [value]
      }
}

export class RecordRefField extends KeeperRecordField {
    required? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'recordRef'
        this.value = [value]
      }
}

export type Schedule = {
    type?: string
    utcTime?: string
    weekday?: string
    intervalCount?: number
}

export class ScheduleField extends KeeperRecordField {
    required? : boolean
    value?: Schedule[]
    constructor(value: Schedule) {
        super()
        this.type = 'schedule'
        this.value = [value]
      }
}

export type Script = {
    fileRef?: string
    command?: string
    recordRef?: string[]
}

export class ScriptField extends KeeperRecordField {
    required?: boolean
    privacyScreen?: boolean
    value?: Script[]
    constructor(value: Script) {
        super()
        this.type = 'script'
        this.value = [value]
      }
}

export class DirectoryTypeField extends KeeperRecordField {
    required? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'directoryType'
        this.value = [value]
      }
}

export class DatabaseTypeField extends KeeperRecordField {
    required? : boolean
    value?: string[]
    constructor(value: string) {
        super()
        this.type = 'databaseType'
        this.value = [value]
      }
}

export class PamHostnameField extends KeeperRecordField {
    required? : boolean
    privacyScreen? : boolean
    value?: Host[]
    constructor(value: Host) {
        super()
        this.type = 'pamHostname'
        this.value = [value]
      }
}

export type PamResource = {
    controllerUid?: string
    folderUid?: string
    resourceRef?: string[]
}

export class PamResourceField extends KeeperRecordField {
    required? : boolean
    value?: PamResource[]
    constructor(value: PamResource) {
        super()
        this.type = 'pamResources'
        this.value = [value]
      }
}

export class CheckboxField extends KeeperRecordField {
    required? : boolean
    value?: boolean[]
    constructor(value: boolean) {
        super()
        this.type = 'checkbox'
        this.value = [value]
      }
}

export type PrivateKey = {
    crv?: string
    d?: string
    ext?: boolean
    key_ops?: string[]
    kty?: string
    x?: string
    y?: string
}

export type Passkey = {
    privateKey?: PrivateKey
    credentialId?: string
    signCount?: number
    userId?: string
    relyingParty?: string
    username?: string
    createdDate?: number
}

export class PasskeyField extends KeeperRecordField {
    required?: boolean
    value?: Passkey[]
    constructor(value: Passkey) {
        super()
        this.type = 'passkey'
        this.value = [value]
      }
}
