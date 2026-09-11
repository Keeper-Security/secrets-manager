const {
    getSecrets,
    initializeStorage,
    localConfigStorage,
    uploadFile,
    downloadFile
} = require('@keeper-security/secrets-manager-core')
const fs = require('fs')

const main = async () => {
    const storage = localConfigStorage("config.json")
    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, 'US:EXAMPLE_ONE_TIME_TOKEN', 'keepersecurity.com')

    const {records} = await getSecrets({storage: storage})
    const ownerRecord = records[0]

    // Files attach to a record - there's no way to upload a file without an owner record.
    const localFilePath = './upload-me.txt'
    if (!fs.existsSync(localFilePath)) {
        fs.writeFileSync(localFilePath, 'hello from the file-upload example\n')
    }
    const data = fs.readFileSync(localFilePath)

    const fileUid = await uploadFile({storage: storage}, ownerRecord, {
        name: 'upload-me.txt',
        title: 'upload-me.txt',
        type: 'text/plain',
        data: data
    })
    console.log(`uploaded file UID: ${fileUid}`)

    // Round-trip: re-fetch the record (uploadFile doesn't mutate the in-memory copy) and
    // download the file we just uploaded to prove the bytes round-trip correctly.
    //
    // The server can take a moment after uploadFile() returns before the file's download
    // URL is populated in a getSecrets() response, so poll briefly rather than fetching once.
    let uploadedFile
    for (let attempt = 1; attempt <= 5 && !uploadedFile?.url; attempt++) {
        const {records: refreshedRecords} = await getSecrets({storage: storage}, [ownerRecord.recordUid])
        uploadedFile = refreshedRecords[0].files.find(f => f.fileUid === fileUid)
        if (!uploadedFile?.url) {
            await new Promise(resolve => setTimeout(resolve, 1000))
        }
    }
    if (!uploadedFile?.url) {
        throw new Error(`Uploaded file ${fileUid} has no download URL yet after 5 attempts`)
    }

    const downloaded = await downloadFile(uploadedFile)
    const matches = Buffer.compare(data, Buffer.from(downloaded)) === 0
    console.log(`downloaded bytes match uploaded bytes: ${matches}`)
}

// uploadFile()'s underlying HTTP response is never drained, which leaves the process
// alive after main() resolves - exit explicitly rather than leave a script that appears
// to hang after printing its result.
main().finally(() => process.exit(0))
