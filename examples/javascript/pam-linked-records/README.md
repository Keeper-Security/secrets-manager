# PAM linked records

Reads a PAM record's linked records - the mechanism PAM resources use to associate a
credential, connection/rotation metadata, JIT elevation settings, and AI risk settings
with a resource record.

## Concept

In the Keeper vault, a PAM resource (e.g. a machine or database) links to other records rather than
embedding their data directly. Those links are exposed on `record.links` as a raw
`{ recordUid, data?, path? }[]`. `path` identifies what kind of link it is:

- `'meta'`: rotation/connection permission metadata (plain JSON)
- `'jit_settings'`: just-in-time elevation settings (encrypted)
- `'ai_settings'`: AI risk-level settings (encrypted)
- no path: a credential link (admin/IAM/launch-credential flags)

## Functions demonstrated

- `getLinks(record)`: wraps `record.links` as `KeeperRecordLink[]`, one typed accessor per link. Decryption
  keys are pulled automatically from the SDK's internal key cache (already populated by the preceding
  `getSecrets()` call), so none of the accessor methods below need a key argument in normal use.
- `KeeperRecordLink` accessors used here: `getMetaData()`, `allowsRotation()`, `allowsConnections()`,
  `getJitSettingsData()`, `getAiSettingsData()`, `isAdminUser()`, `isLaunchCredential()`. Several more
  exist (`isIamUser()`, `belongsTo()`, `allowsPortForwards()`, `getRotationSettings()`, `getAllowedSettings()`,
  and the generic `getLinkData()`/`getDecryptedData()` for reading a link's raw payload directly).

## Running

1. Replace the placeholder token in `hello.js` with a real one-time access token for your vault.
2. Make sure the vault has at least one PAM record with linked records.
3. `npm install`
4. `npm run run`

Expected output: the linked-record count for the first record that has any, followed by each link's UID,
path, and the relevant typed accessor values for that path.
