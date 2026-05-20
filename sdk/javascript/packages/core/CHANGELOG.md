# Change Log

## 17.4.1
- KSM-901 - Add IL5 (DoD Impact Level 5) support: region mapping (`IL5` → `il5.keepersecurity.us`) and custom server public key injection via three layers — OTS token (`IL5:TOKEN:keyId:publicKey`), `ClientConfiguration` fields (`serverPublicKey` / `serverPublicKeyId`), and `initialize()` options parameter. When a custom key is configured, server-side key rotation hints are suppressed so the client stays pinned to the IL5 key.
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
