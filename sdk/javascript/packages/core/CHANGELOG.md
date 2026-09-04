# Change Log

## 17.6.0
- KSM-1073 - Added `dbConnectionMethod` to `PamSettingsConnection`.
- KSM-1079 - Fixed `getFolders()` crashing when a folder in the response has a corrupted or missing key. The SDK now skips undecryptable folders and returns the remaining folders normally.
- KSM-1084 - Fixed `deleteSecret()` and `deleteFolder()` silently reporting success when the server rejected some UIDs. The SDK now surfaces per-item error messages from the server to the caller.
- KSM-748 - Fixed `getSecrets()` silently dropping records created by Commander or the Vault UI inside shared folders. The SDK now uses the folder key to decrypt the record key for any flat record that has `innerFolderUid` set. This matches the behavior for records in `folders[].records[]`.
- KSM-1035 - Fixed throttle retry jitter being two-sided, which could reduce a retry delay below the computed floor. Jitter is now one-sided (0 to +25%). The SDK also caps a server-supplied `retry_after` at 176s to prevent an arbitrarily long wait.
- KSM-1128 - Bounded the server key-rotation retry in `postQuery`. When the server sends `{"error":"key"}`, the code retries at most 3 times before throwing a typed `KeeperError`, instead of retrying forever. Before storing a suggested `key_id`, the code validates its shape (positive integer) and its membership in the bundled key table (keys 7-18). An unsupported key id can no longer corrupt the configuration. The pinned custom-key path does not change.
- KSM-1254 - Fixed the Node platform's `hash()` ignoring its `tag` parameter and always hashing with a hardcoded string; it now hashes with the caller-supplied tag, matching the browser implementation and the `Platform` contract. No behavior change for existing callers (the SDK's only caller already passed that same string).
- KSM-1332 - Fixed the browser IndexedDB storage hanging forever on a storage failure. `localConfigStorage` and `secureStorage` wired only `onsuccess`, so a failed IndexedDB open, read, write or delete left the promise pending with no error, no rejection and no timeout. All eight wrappers now reject with a typed `KeeperError`, and the blocked-upgrade and missing-object-store paths reject too instead of hanging.
- KSM-1263 - Fixed config and cache file permissions not being re-applied on every write. `fs.openSync`'s mode argument only takes effect when a file is created, so a config or cache file that already existed with looser permissions kept them; permissions are now explicitly reset to 0600 after every write.
- KSM-1267 - `getFolders()` now classifies why an undecryptable folder was skipped (`integrity`, `format`, `missing-key`, or `malformed-data`) instead of logging an opaque, unclassified error, and logs one summary line naming every folder UID it had to omit. Added an optional `onDecryptionError` callback to `SecretManagerOptions`, invoked once per skipped folder, so a caller can react to or throw to fail closed on a partial result; existing callers that do not set it see no behavior change. Both the Node and browser platforms' `unwrap()` now reject an unwrapped key of the wrong length immediately (a corrupted-but-plausible 16- or 24-byte result was previously accepted by both platforms and cached, failing later at an unrelated call site with a much harder to diagnose error). The underlying finding (the shared-folder key wrap uses unauthenticated AES-256-CBC, a format fixed server-side that the SDK cannot change unilaterally) was reviewed and confirmed low-impact: a manipulated folder key is still caught by the existing AES-GCM authentication on the record keys inside that folder.
- KSM-1266 - Fixed `localConfigStorage` treating every config-read failure as "no config yet." A missing file is still a legitimate fresh start, and so now is one left completely empty by a process killed mid-save (a partially-written file is not covered by this - there is no reliable way to distinguish a truncated write from genuine corruption, so it still throws). Permission errors, malformed JSON, invalid UTF-8 byte sequences, and JSON that parses but isn't an object (`null`, a number, an array) now throw a typed `KeeperError` instead of silently starting fresh or misbehaving on first use. A leading UTF-8 BOM (produced by tools like Windows Notepad or PowerShell's `Set-Content`) is stripped and the file is read normally, not treated as corruption. `saveStorage`'s write path now writes to a temporary file and renames it into place atomically, instead of truncating the destination before writing (which could previously leave a 0-byte file on disk after a failed write), and wraps its own failures (e.g. `EACCES`, `ENOSPC`) in the same `KeeperError` guarantee. Node validates config readability eagerly, at construction; the browser `localConfigStorage` (KSM-1332, same release) defers the equivalent check lazily to first storage access, since IndexedDB has no synchronous API to check eagerly against - this timing difference between the two platforms is expected and now documented in-code. The write path now resolves a symlinked config path and writes through the real file. It no longer replaces the symlink. Some deployments manage a "current config" symlink this way. The SDK writes a hard-linked config path in place instead. Every hard link still sees the update. This matches the behavior hard links had before this fix. The new atomic write no longer breaks this case. An atomic write now needs write and execute permission on the config file's directory, not just the file itself. A directory locked down to file-only write access will fail every save from now on. If a crash happens between opening the temporary file and the rename, the SDK now removes the leftover file automatically on the next read. Before this fix, the file stayed on disk indefinitely. A failed save no longer leaves the in-memory value ahead of the value on disk. `localConfigStorage` now throws the new `KeeperStorageError`, which extends `KeeperError`. Its `code` field carries the original filesystem error code, for example `EACCES` or `ENOSPC`, when one exists. Concurrent `saveString`/`saveBytes`/`delete` calls on the same `localConfigStorage` instance now run one at a time. Before this fix, two overlapping calls could interleave so that a failed save's rollback erased a different, already-successful call's data.
- KSM-1265 - **BREAKING (Node only):** Security fix (CWE-312, CWE-345): the Node `cachingPostFunction` stored its AES transmission key in plaintext next to the ciphertext it protected, in a fixed path relative to the process's working directory, and restored it with no integrity check. Replaced it with `createCachingFunction(storage, options?)`:
  ```
  // before
  queryFunction: cachingPostFunction
  // after
  queryFunction: createCachingFunction(storage)
  // with a custom cache path or freshness window
  queryFunction: createCachingFunction(storage, {cachePath, maxCacheAgeMs})
  ```
  The cache is now encrypted with a key derived from the app key already held in the config (so reading the cache requires the config, not just the cache file), authenticated so a tampered or corrupted file is rejected instead of silently trusted, bounded by a configurable freshness window (default 24h), and located at `~/.keeper/ksm-cache.dat` by default instead of the working directory. Usage was limited to the opt-in caching example, which has been updated to use the new function. If you called `cachingPostFunction` directly, delete the old cache file in your working directory after upgrading; it is not removed automatically. `cachePath` and `maxCacheAgeMs` are now named fields on an options object instead of positional arguments, since Node's and the browser's second positional argument meant different things; the browser signature (`createCachingFunction(storage, maxCacheAgeMs?)`) is unchanged and still non-breaking there, since the new `maxCacheAgeMs` parameter is optional and an old-format cached value is simply treated as a cache miss. A symlinked cache directory is rejected outright (throws) on both read and write. A symlinked cache file itself is not rejected with an error - the write silently replaces it with a real file instead of following it, and the read still requires the actual content underneath to pass its own integrity check - there is no legitimate externally-managed symlink convention for a path the SDK itself names, unlike the config file's own symlink handling, which is unchanged and intentionally different (see the KSM-1266 entry above). Both the config file and the cache file are now written atomically (to a temporary file, then renamed into place, via one shared primitive), so a write that fails partway through can no longer leave a corrupted or truncated file behind. The cache directory is created at `0700` and re-hardened to `0700` if this call is the one that creates it; a caller-supplied `cachePath` pointing at a directory that already exists (for example, a file directly inside `$HOME`) keeps whatever permissions it already had - the SDK does not narrow permissions on a directory it doesn't own. Known limitation: the very first (bind) call's response is not cached, since caching requires an app key that the bind call itself establishes; every call after that caches normally. In the browser, when the app key is held as a non-extractable `CryptoKey` (`useObjects: true`), caching is a no-op rather than an error, the same graceful degradation already used for a network failure with no prior cache. A network failure served from cache now logs a warning, since the caller is getting a response that may be stale. This package now also declares an `exports` field so bundlers and modern TypeScript resolve the correct platform-specific type declarations for the browser bundle; a consumer still on TypeScript's legacy `moduleResolution: "node"` continues to see the Node type declarations regardless, unchanged from before.
- Maintenance: Updated `minimatch`, `@babel/core`, and `handlebars` dev dependencies.

## 17.5.0
- KSM-1029 - Fixed stale pinned server key error: when the server rejects a configured custom server public key, the diagnostic message now propagates to the caller instead of being swallowed by a bare catch.
- KSM-880 - Added automatic throttle retry with exponential backoff. On HTTP 403 `{"error":"throttled"}`, `postQuery` now retries up to 5 times with exponentially increasing delays (11s, 22s, 44s, 88s, 176s) plus ±25% jitter, honoring `retry_after` from the response when present; a typed `KeeperThrottleError` is thrown once retries are exhausted. Existing key-rotation retry behavior is unchanged.
- KSM-901 - Add support for connecting to isolated deployments whose server public key is not bundled with the SDK. Supply the custom key in any of three ways: an extended one-time token in the 4-segment format (`<region>:clientKey:keyId:serverPublicKey`), the `serverPublicKey` / `serverPublicKeyId` config fields, or the `serverPublicKey` / `serverPublicKeyId` options on `SecretManagerOptions` (passed to `getSecrets`). New region keywords for isolated deployments are recognized as server identifiers. While a custom key is configured, server-pushed key-rotation hints are suppressed so the custom key is preserved.
- KSM-887 - Added `secureStorage(dbName)` browser storage backend: generates a non-extractable AES-256-GCM `CryptoKey` stored in IndexedDB so KSM credentials are never held in extractable form in browser storage.
- KSM-1010 - Added `KeeperRecordLink` typed accessor class and `getLinks()` function (TypeScript port of Python KSM-992): exposes permission booleans (`isAdminUser`, `allowsRotation`, `allowsConnections`, etc. with `allowedSettings` fallback), data accessors (`getDecodedData`, `getDecryptedData`, `getLinkData`), and settings accessors (`getAiSettingsData`, `getJitSettingsData`, `getMetaData`, `getSettingsForPath`); all accessors are non-throwing.
- KSM-984 - Fixed `webSafe64ToBytes` and `base64ToBytes` (Node and browser) to guard against `null`/`undefined` config values: null/undefined input now throws a typed `KeeperError` naming the bad field instead of a cryptic native `TypeError`.
- KSM-1025 - Add an exported `KeeperError` base class so SDK errors can be distinguished from unexpected runtime failures via `instanceof KeeperError`. `KeeperThrottleError` now extends `KeeperError` (which extends `Error`), and the `null`/`undefined` config-value guards throw `KeeperError`; existing `instanceof Error` handling is unaffected. Migration of the remaining `throw new Error(...)` sites to this hierarchy is tracked under the KSM-1024 epic.
- KSM-758 - Replace deprecated `rollup-plugin-sourcemaps@0.6.3` with `rollup-plugin-sourcemaps2@0.5.6` — resolves peer dependency warnings with Rollup 4.x; bumped to 0.5.6 to resolve transitive `picomatch` HIGH vulnerability (dev dependency only, no production impact)
- Security: Bump `rollup` devDependency from `^4.52.3` to `^4.60.1` — fixes HIGH severity arbitrary file write via path traversal (CVE affects 4.0.0–4.58.0)

## 17.4.0
- KSM-669 - Crypto issues when using getFolders() on Cloudflare workers with JS SDK
- KSM-697 - Fix file permissions for config files (write with 0600 permissions for security)
- KSM-731 - Fix notation lookup with record shortcuts (handles duplicate UIDs from shortcuts)
- KSM-739 - Added transmission public key #18 for Gov Cloud Dev support
- Security: Updated transitive dependencies (glob 10.5.0, js-yaml 3.14.2)

## 17.3.0
- KSM-534 - Added proxy support
- KSM-575 - Resolve DOM Clobbering CVE-2024-43788
- KSM-657 - Added custom caching example
- KSM-661 - Handle broken records, files, and folders

## 17.2.0
- KSM-581: Added GraphSync library to read GraphSync links

## 17.1.0
- KSM-588: Enhance JS SDK to enable editing of external shares

## 17.0.0
- KSM-574 - Replace Node.js Buffer with Browser-Compatible Alternative

## 16.6.3
- KSM-489 - Added transaction support for updateSecret
- KSM-521 - Dependencies upgrade
- KSM-549 - Stop generating UIDs that start with "-"
- KSM-556 - Added new field types and updated PAM field types

## 16.6.2
- KSM-487 - Dependencies upgrade

## 16.6.1
- KSM-438 - include enterprise logo in KSM response, `extra` field. (related to KA-5546)
- Bump dependencies

## 16.6.0
- KSM-412 - Added support for Folders
- KSM-432 - Improved support for Passkey field type
- Dependencies upgrade

## 16.5.2
- KSM-407 - New field type: Passkey
- KSM-402 - New filed type: script and modification to record types
- KSM-377 - Added support for PAM record types

## 16.5.1
- Adding back missing methods for the Notation improvements

## 16.5.0
- Notation improvements - new parser, notation URIs using record title, new escape characters
- Creation of the custom fields
- Logging improvement

## 16.4.0
- KSM-310 - Improved password generation entropy
- Record deletion

## 16.3.3
- KSM-273 - Avoid reliance on external package for file upload with Node
- Added support to Japan `JP` and Canada `CA` regions
