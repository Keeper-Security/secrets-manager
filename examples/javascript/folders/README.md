# Folders

Lists folders, creates a new one, renames it, then deletes it.

## Functions demonstrated

- `getFolders(options)`: returns every folder the application has access to, as `KeeperFolder[]` (`{ folderUid, parentUid?, name? }`).
- `createFolder(options, createOptions, folderName)`: creates a new folder. `createOptions` is `{ folderUid, subFolderUid? }`:
  - `folderUid` must be the UID of a shared folder (a `KeeperFolder` entry with no `parentUid`, which is what distinguishes a shared folder from a regular sub-folder in the `getFolders()` result). It becomes the new folder's shared-folder association, not its direct visual parent.
  - `subFolderUid` is optional; set it to an existing regular folder's UID to nest the new folder under it instead of directly under the shared folder.
- `updateFolder(options, folderUid, folderName)`: renames a folder.
- `deleteFolder(options, folderUids, forceDeletion?)`: deletes one or more folders by UID.

## Running

1. Replace the placeholder token in `hello.js` with a real one-time access token for your vault.
2. Make sure the vault has at least one shared folder.
3. `npm install`
4. `npm run run`

Expected output: the current folder list, the new folder's UID, a rename confirmation, then the delete result.
