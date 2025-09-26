process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const fs = require('fs');

const {
    getSecrets,
    initializeStorage,
    localConfigStorage,
    postFunction
} = require('@keeper-security/secrets-manager-core')

const CACHE_FILENAME = 'cache.dat';

// This is basic example of creating custom caching function
// ⓘ This will store only last request, however you can use any tool to extend this functionality
// ⓘ Stale cache entries can cause version mismatches if records are updated from other keepersecurity utils. Prefer fresh reads

const cachingPostFunction = async (url, transmissionKey, payload, allowUnverifiedCertificate) => {
    try {
        const response = await postFunction(
            url,
            transmissionKey,
            payload,
            allowUnverifiedCertificate
        )

        if (response.statusCode == 200) {
            fs.writeFileSync(CACHE_FILENAME, Buffer.concat([transmissionKey.key, response.data]))
        }

        return response
    } catch (e) {
        console.error(e)
        let cachedData
        try {
            cachedData = fs.readFileSync(CACHE_FILENAME)
        } catch {
        }
        if (!cachedData) {
            throw new Error('Cached value does not exist')
        }
        console.log('Using cached data')
        transmissionKey.key = cachedData.slice(0, 32)
        return {
            statusCode: 200,
            data: cachedData.slice(32),
            headers: []
        }
    }
}

const getKeeperRecords = async () => {
    const storage = localConfigStorage("config.json")

    const options = {
        storage,
        queryFunction: cachingPostFunction
    }

    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, 'US:EXAMPLE_ONE_TIME_TOKEN', 'keepersecurity.com')
    const {records} = await getSecrets(options)

    console.log(records)
}

getKeeperRecords().finally()
