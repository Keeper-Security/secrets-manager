const {
    getFolders,
    createFolder,
    updateFolder,
    deleteFolder,
    initializeStorage,
    localConfigStorage
} = require('@keeper-security/secrets-manager-core')

const main = async () => {
    const storage = localConfigStorage("config.json")
    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, 'US:EXAMPLE_ONE_TIME_TOKEN', 'keepersecurity.com')

    const folders = await getFolders({storage: storage})
    console.log(folders)

    // A folder with no parentUid is itself a shared folder. New folders must be created
    // inside one - pass its UID as createOptions.folderUid (it becomes the new folder's
    // sharedFolderUid, not a direct parent; pass createOptions.subFolderUid too to nest
    // under an existing regular folder instead of directly under the shared folder).
    const sharedFolder = folders.find(f => !f.parentUid)
    if (!sharedFolder) {
        console.log('No shared folder found - create one in the vault first')
        return
    }

    const newFolderUid = await createFolder({storage: storage}, {folderUid: sharedFolder.folderUid}, 'Example folder')
    console.log(`created folder UID: ${newFolderUid}`)

    await updateFolder({storage: storage}, newFolderUid, 'Example folder (renamed)')
    console.log('renamed folder')

    const deleteResult = await deleteFolder({storage: storage}, [newFolderUid])
    console.log(`delete result: ${JSON.stringify(deleteResult)}`)
}

main().finally()
