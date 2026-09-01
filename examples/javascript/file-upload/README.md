# File upload

Uploads a local file to a record, then downloads it back and confirms the bytes round-trip.

## Function demonstrated

`uploadFile(options, ownerRecord, file)`: attaches `file` to `ownerRecord` and returns the new file's UID.
`file` is a `KeeperFileUpload`: `{ name, title, type?, data }`, where `data` is a `Uint8Array`.

Files always attach to a record - there's no way to upload a file to a folder directly. This complements
`downloadFile`, already shown in the `hello-secret` example, which only covers reading an existing file.

The script polls briefly after uploading: the server can take a moment to populate the new file's download
URL in a `getSecrets()` response, so fetching once immediately after `uploadFile()` returns can find a file
entry with no `url` yet. It also calls `process.exit(0)` explicitly at the end, since `uploadFile()`'s
underlying HTTP response is never read and leaves the socket (and the process) open otherwise.

## Running

1. Replace the placeholder token in `hello.js` with a real one-time access token for your vault.
2. `npm install`
3. `npm run run`

Expected output: the uploaded file's UID, then `true` confirming the downloaded bytes match what was uploaded.
