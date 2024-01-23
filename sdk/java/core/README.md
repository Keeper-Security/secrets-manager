## Keeper Secrets Manager Java SDK

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/java-sdk

# Change Log

## 16.6.3
- KSM-486 - Fix security provider not supporting AES/CBC/PKCS7Padding
- KSM-473 - Make Notation function public

## 16.6.2
- KSM-452 - Java SDK broken when using Java default crypto provider.
- KSM-453 - Upgrade kotlin-stdlib-jdk8 dependency scope to api

## 16.6.1
- KSM-443 - Improved folder support and updated unit tests

## 16.6.0
- KSM-415 - Added support for Folders

## 16.5.4
- KSM-431 - Improved Passkey field type support
- KSM-421 - Improved Logging

## 16.5.3
- KSM-401 - Update PAM Record types and Field types to have latest updates
- KSM-406 - New field type: Passkey
- KSM-382 - Support for record Transactions

## 16.5.2
- KSM-379 - Remove deprecation from getValue function

## 16.5.1
- KSM-374 - Add support for PAM record types

## 16.5.0
- KSM-314 - Notation improvements
- KSM-356 - Create custom fields

## 16.4.0
- KSM-293 - Allow to run under Java 16+
- KSM-309 - Improved password generation
- Record Deletion

## 16.3.6
- KSM-324 - Support for new regions: Japan and Canada
- Checking for SecureRandom to work properly. Throw exception if `haveged` or `rng-tools` are not installed
