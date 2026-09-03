const {
    getSecrets,
    getLinks,
    initializeStorage,
    localConfigStorage
} = require('@keeper-security/secrets-manager-core')

const main = async () => {
    const storage = localConfigStorage("config.json")
    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, 'US:EXAMPLE_ONE_TIME_TOKEN', 'keepersecurity.com')

    const {records} = await getSecrets({storage: storage})

    // A PAM record's linked records (a credential, rotation/connection metadata, JIT
    // elevation settings, AI risk settings, ...) live in record.links, not a dedicated
    // field. getLinks() wraps each raw link in a typed accessor. Decryption keys are
    // pulled automatically from the same key cache getSecrets() just populated, so
    // there's no need to supply one explicitly for any of the calls below.
    const record = records.find(r => (r.links || []).length > 0)
    if (!record) {
        console.log('No record with linked records found')
        return
    }

    const links = getLinks(record)
    console.log(`${record.recordUid} has ${links.length} linked record(s)`)

    for (const link of links) {
        console.log(`- linked record ${link.recordUid} (path: ${link.path ?? 'none'})`)

        if (link.path === 'meta') {
            console.log(`  metadata: ${JSON.stringify(await link.getMetaData())}`)
            console.log(`  allows rotation: ${link.allowsRotation()}, allows connections: ${link.allowsConnections()}`)
        } else if (link.path === 'jit_settings') {
            console.log(`  JIT elevation settings: ${JSON.stringify(await link.getJitSettingsData())}`)
        } else if (link.path === 'ai_settings') {
            console.log(`  AI risk settings: ${JSON.stringify(await link.getAiSettingsData())}`)
        } else {
            // A credential-type link has no path - flags are read directly off its
            // decoded link data via the boolean accessors.
            console.log(`  is admin user: ${link.isAdminUser()}, is launch credential: ${link.isLaunchCredential()}`)
        }
    }
}

main().catch((e) => {
    console.error(`Failed to run pam-linked-records example: ${e?.message ?? String(e)}`)
    process.exitCode = 1
})
