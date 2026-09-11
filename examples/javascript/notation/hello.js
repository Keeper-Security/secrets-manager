const {
    getSecrets,
    initializeStorage,
    localConfigStorage,
    getNotationResults,
    tryGetNotationResults
} = require('@keeper-security/secrets-manager-core')

const main = async () => {
    const storage = localConfigStorage("config.json")
    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, 'US:EXAMPLE_ONE_TIME_TOKEN', 'keepersecurity.com')

    const {records} = await getSecrets({storage: storage})
    const firstRecord = records[0]

    // Notation addresses a single value by record UID/title + selector, without paging
    // through a full getSecrets() result yourself: keeper://<uid-or-title>/field/<type>
    const loginNotation = `keeper://${firstRecord.recordUid}/field/login`
    const [login] = await getNotationResults({storage: storage}, loginNotation)
    console.log(`login via notation: ${login}`)

    // tryGetNotationResults() never throws - it logs and returns an empty array on error,
    // so it's safe to call speculatively against a field that may not be present.
    const missingNotation = `keeper://${firstRecord.recordUid}/field/does_not_exist`
    const missing = await tryGetNotationResults({storage: storage}, missingNotation)
    console.log(`missing field via tryGetNotationResults: ${JSON.stringify(missing)} (empty array, no throw)`)

    // getNotationResults() is the throwing variant - same lookup, surfaced as a real error.
    try {
        await getNotationResults({storage: storage}, missingNotation)
    } catch (e) {
        console.log(`getNotationResults threw as expected: ${e.message}`)
    }
}

main().finally()
