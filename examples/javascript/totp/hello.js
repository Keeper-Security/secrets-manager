const {
    getSecrets,
    initializeStorage,
    localConfigStorage,
    getTotpCode
} = require('@keeper-security/secrets-manager-core')

const main = async () => {
    const storage = localConfigStorage("config.json")
    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, 'US:EXAMPLE_ONE_TIME_TOKEN', 'keepersecurity.com')

    const {records} = await getSecrets({storage: storage})

    // The otpauth:// URL lives in a record's "oneTimeCode" field, not the record itself.
    const record = records.find(r => r.data.fields.some(f => f.type === 'oneTimeCode'))
    if (!record) {
        console.log('No record with a oneTimeCode field found')
        return
    }

    const otpField = record.data.fields.find(f => f.type === 'oneTimeCode')
    const otpUrl = otpField.value[0]

    const totp = await getTotpCode(otpUrl)
    if (!totp) {
        console.log('getTotpCode returned null - the field value was not a valid otpauth:// URL')
        return
    }
    console.log(`code: ${totp.code}, time left: ${totp.timeLeft}s, period: ${totp.period}s`)

    // unixTimeSeconds lets a caller compute the code for a specific moment (e.g. for
    // deterministic tests) instead of "now".
    const fixedTime = 1700000000
    const totpAtFixedTime = await getTotpCode(otpUrl, fixedTime)
    console.log(`code at ${fixedTime}: ${totpAtFixedTime.code}`)
}

main().catch((e) => {
    console.error(`Failed to run totp example: ${e?.message ?? String(e)}`)
    process.exitCode = 1
})
