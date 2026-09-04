const {
    getSecrets,
    initializeStorage,
    localConfigStorage,
    createCachingFunction
} = require('@keeper-security/secrets-manager-core')

// This is a basic example of using the SDK's built-in caching function.
// ⓘ createCachingFunction stores only the last successful request, but you can supply your own
//   queryFunction to extend this behavior.
// ⓘ Stale cache entries can cause version mismatches if records are updated from other keepersecurity
//   utils. createCachingFunction rejects cache entries older than its maxCacheAgeMs (default 24h).

const getKeeperRecords = async () => {
    const storage = localConfigStorage("config.json")

    const options = {
        storage,
        queryFunction: createCachingFunction(storage)
    }

    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, 'US:EXAMPLE_ONE_TIME_TOKEN', 'keepersecurity.com')
    const {records} = await getSecrets(options)

    console.log(records)
}

getKeeperRecords().catch((e) => {
    console.error(`Failed to load Keeper secrets: ${e?.message ?? String(e)}`)
    process.exitCode = 1
})
