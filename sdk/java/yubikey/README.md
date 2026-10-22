# Keeper Secrets Manager YubiKey Signer

This module keeps the Keeper Secrets Manager client private key on a YubiKey.
The YubiKey PIV application generates the key.
The key never leaves the device.
The SDK config holds no `privateKey`, and the YubiKey signs every request.

Requirements:

- A YubiKey with a PIV application that supports ECC P-256 (YubiKey 4 or 5). The module rejects other devices.
- Keeper Secrets Manager Java SDK `core` 17.5.0 or later.
- PC/SC. macOS and Windows include it. Linux needs `pcscd`.

The module talks to the YubiKey through `javax.smartcardio` in the JDK.
It needs no Yubico tools and no native libraries.

## Usage

Each KSM config needs its own key pair.
`generateKey()` puts each new key in the first free retired slot.
The config keeps the public key of that key, and the public key finds the slot later.

```kotlin
// Once, with a One-Time Access Token: generate the key on the YubiKey and bind its public key
YubiKeySigner(pin).use { signer ->
    signer.verifyPin() // a wrong PIN fails here with the retries left
    initializeStorage(storage, "US:ONE_TIME_TOKEN", null, signer.generateKey())
    val secrets = getSecrets(SecretsManagerOptions(storage, signer = signer, appKeyProtector = signer))
}

// Later runs: find the slot that holds the key of this config
YubiKeySigner.forPublicKey(pin, storage.getBytes(KEY_PUBLIC_KEY)!!).use { signer ->
    val secrets = getSecrets(SecretsManagerOptions(storage, signer = signer, appKeyProtector = signer))
}
```

Java:

```java
try (YubiKeySigner signer = new YubiKeySigner(pin)) {
    SecretsManager.initializeStorage(storage, "US:ONE_TIME_TOKEN", null, signer.generateKey());
    KeeperSecrets secrets = SecretsManager.getSecrets(SecretsManagerOptions.withSigner(storage, signer, signer));
}
try (YubiKeySigner signer = YubiKeySigner.forPublicKey(pin, storage.getBytes(SecretsManager.KEY_PUBLIC_KEY))) {
    KeeperSecrets secrets = SecretsManager.getSecrets(SecretsManagerOptions.withSigner(storage, signer, signer));
}
```

## App key wrapping

When you pass the signer as `appKeyProtector`, the config keeps the app key only in wrapped form (`appKeyWrapped`).

- **Wrapping key:** The YubiKey has one P-256 key-agreement key for all configs. It lives in slot 9D, or in a free retired slot if 9D is in use. A certificate named `Keeper Secrets Manager App Key Wrapping` marks it. `generateKey()` creates it if it is missing. The name alone is not trusted, because anyone with the management key can write a certificate. The SDK also checks that the key was generated on the YubiKey and that its PIN policy fits the config. If a slot fails the check, the SDK stops with an error that names the slot.
- **Format:** The wrapped key is an ECIES blob (format version 2). It holds the wrapping public key, an ephemeral public key, and the app key encrypted with AES-256-GCM. The AES key comes from the NIST SP 800-56C one-step KDF, bound to the format version, the curve, and both public keys.
- **Wrapping:** Wrapping needs neither the PIN nor the management key.
- **Unwrapping:** The YubiKey does the ECDH step and needs the PIN once for each signer. The signer then keeps the app key in memory until you call `close()`.
- **Failure:** If wrapping fails, binding fails and the SDK stores nothing. The error names the exception class of the failure and leaves out its message. Core treats text from a signer or protector as possibly secret. Run the command again after you fix the cause. The SDK does not store a plain app key as a fallback.
- **Plain key in the config:** If the config has a plain `appKey` and you pass a protector, the SDK stops with an error. Call `migrateAppKeyToProtector(options)` once to wrap the key and delete the plain one.

## Unattended use

KSM often runs where nobody can type a PIN, for example in services, CI, and cron jobs.
The PIN policy of a key is fixed when you generate the key.
The SDK never stores the PIN.
For unattended use, generate the key with `PinPolicy.NEVER` and open the signer without a PIN.

```kotlin
YubiKeySigner().use { signer ->
    initializeStorage(storage, "US:ONE_TIME_TOKEN", null, signer.generateKey(pinPolicy = PinPolicy.NEVER))
    getSecrets(SecretsManagerOptions(storage, signer = signer, appKeyProtector = signer))
}
YubiKeySigner.forPublicKey(storage.getBytes(KEY_PUBLIC_KEY)!!).use { signer -> /* ... */ }
```

- **Second wrapping key:** The app key of a PIN-less config goes to a second, PIN-less wrapping key. Its certificate is named `Keeper Secrets Manager App Key Wrapping, no PIN`. `generateKey` creates it if it is missing. A config with a PIN-protected key never uses it.
- **Generation:** `generateKey` still needs the management key, but it needs no PIN.
- **Touch policy:** Keep the touch policy at `NEVER`. This is the default for retired slots. A touch needs a person too.
- **What it is:** A non-exportable client key. It is not multi-factor authentication. The YubiKey is the only factor for a PIN-less key.
- **Who can use the key:** Any code that can reach the card while the YubiKey is plugged in can ask it to sign and to unwrap the app key. Which accounts can reach the card depends on the PC/SC policy of the host, not only on the account that runs your service. The config and the YubiKey are both needed to use the KSM application. A stolen config alone is useless, and a stolen YubiKey alone is useless. Both together give full access from any computer.
- **What that code can copy:** The signer keeps the app key in memory until `close()`. Code that runs as the same user can read it. If response caching is on, a copied app key and the cache file decrypt the cached secrets without the YubiKey.
- **Management key:** Only the management key protects a PIN-less key from being replaced. Changing the PIN and the PUK does not. Change the management key from the factory default before you generate a PIN-less key. Anyone who can reach the card can also block the PIN and the PUK and then reset the PIV application, which deletes every key on it. That denies service. It does not leak a key.
- **Dedicated YubiKey:** Use a YubiKey that stays in the machine, not one that a person carries.
- **Containers:** Do not mount the PC/SC socket into containers that you do not trust.
- **Finding PIN-less configs:** `privateKeyLocation` in the config ends with `, unattended (no PIN)`. Search your configs for that text.

A `PinProvider` asks for the PIN only when the YubiKey requires it, and only once for each signer.
One code path can serve PIN-less and PIN-protected keys.

## Key names

PIV keys have no names.
Tools such as ykman, Yubico Authenticator, and Keychain Access show the subject of the slot certificate instead.
At binding, the SDK calls `onBound`.
The signer then writes a self-signed certificate named after the KSM application title into the slot of the config.
The slot key signs the certificate, and the management key from `generateKey()` authorizes the write.
macOS can then list the key in Keychain Access and can offer to pair the smart card.

## Options

- **Slot:** `YubiKeySigner(pin, slot, readerName)`. With no slot, `generateKey()` uses the first retired slot (`RETIRED1` to `RETIRED20`, slots 82 to 95) that holds no key and no certificate. This leaves the standard slots 9A, 9C, and 9E free for smart card login. The app key wrapping key uses 9D when it is free (see App key wrapping). Firmware 5.3 or later is necessary to find a free slot and to use `forPublicKey`. On older YubiKeys, pass the slot. The default PIN policy verifies the PIN once for each connection. `PivSlot.SIGNATURE` (9C) asks for the PIN on every request.
- **Reader:** With no `readerName`, the module uses the first connected YubiKey. `YubiKeySigner.listYubiKeys()` lists the connected YubiKeys.
- **Management key:** `generateKey(managementKey, pinPolicy, touchPolicy, overwrite)`. The default is the factory key. 3DES and AES management keys work. `TouchPolicy.ALWAYS` makes every request wait for a touch. `generateKey` refuses to replace a key or certificate in the slot unless you set `overwrite = true`.
- **Key location:** `signer.keyLocation` tells people which YubiKey holds the key of a config, for example `"YubiKey 5C NFC FIPS, serial 12345678, PIV slot 82 (RETIRED1)"`. The SDK saves it in the config as `privateKeyLocation`. It is information only. `forPublicKey` finds the slot by public key. A PIN-less key adds `, unattended (no PIN)`.
- **Public key:** `signer.publicKey` reads the public key of the slot (firmware 5.3 or later). Core keeps `publicKey` in the config after binding when the private key is external.

## Security notes

- **Change the factory credentials.** The PIV PIN, PUK, and management key have well-known defaults. Anyone who has the YubiKey and knows the defaults can use or replace the keys. Change all three before you use the YubiKey. Yubico Authenticator and `ykman piv access` do this.
- **Use firmware 5.7 or later for new keys.** Yubico advisory YSA-2024-03 (CVE-2024-45678, called EUCLEAK) covers ECDSA keys on YubiKey 5 firmware before 5.7.0. An attacker who holds the YubiKey, has specialized equipment, and knows the PIN of a PIV key can recover the private key and clone it. Yubico rates the issue moderate. Yubico advises RSA or Ed25519 keys, but Keeper needs an ECDSA P-256 client key, so firmware is the only fix. A key generated with `PinPolicy.NEVER` has no PIN to slow the attack. `signer.version` shows the PIV application version, which equals the firmware version.
- **The Keeper server does not know where the key lives.** It stores the public key and checks signatures. It cannot tell a YubiKey key from a software key. Yubico PIV attestation can prove that a key was generated on a YubiKey, but the SDK does not send or check it. Do not describe a config as hardware protected because of anything the server knows.
- **A lost YubiKey means a new binding.** The app key is wrapped to a key on the YubiKey, and the private key exists nowhere else. If you lose the YubiKey, the config no longer works. Create a new One-Time Access Token and bind again.
- **The PIN does not protect against other processes while a signer is open.** Tested on a YubiKey 5C NFC FIPS (firmware 5.4.3): after a signer verified the PIN for a key with the default PIN policy, a second process on the same host signed with that key and sent no PIN. This lasts only while the signer is open. When the signer closes, any process has to select the PIV application again, which drops the PIN state. Close the signer as soon as you finish, and do not leave one open in a long-running process on a shared host. A client key generated with `PinPolicy.ALWAYS` is not exposed this way when it signs: on the same YubiKey the card allowed one operation for each PIN check, and a second process was refused. The signer sends the PIN it holds before every operation, so users see no extra prompts. The app key wrapping key keeps the default policy, so `ALWAYS` protects request signing only.
- **PIN limits.** The PIN is 6 to 8 ASCII characters. A wrong PIN uses one of the PIN retries of the YubiKey. `signer.verifyPin()` reports the retries left, for example `Wrong PIV PIN, 2 retries left`. Call it before the SDK. Inside an SDK call, core shows only the exception class, such as `WrongPinException`.
- **Memory.** The signer keeps the PIN until `close()`, so it can verify the PIN again after another application resets the card. JVM strings are immutable, so `close()` wipes the PIN array that you pass, not copies that other code made.

## Troubleshooting

- **No YubiKey found:** Plug in the YubiKey. Make sure no other application holds the card. Yubico Authenticator and the `gpg` smart card daemon can do this. Close them and try again.
- **No YubiKey found on Linux, although it is plugged in:** `pcscd` may be refusing your account. The JDK does not report a refusal as an error. It lists no readers, so you see `Connected readers: []`. Look in the `pcscd` log (for example `journalctl -u pcscd`) for `Rejected unauthorized PC/SC client`. The default polkit policy of `pcscd` allows only users in an active local session, so a service or an SSH login is refused. Add a rule for the one account that runs your service, for example in `/etc/polkit-1/rules.d/50-ksm-pcsc.rules`, and keep it to that account, because the rule is the access control for the key:

  ```javascript
  polkit.addRule(function(action, subject) {
      if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
           action.id == "org.debian.pcsc-lite.access_card") &&
          subject.user == "ksm-service") {
          return polkit.Result.YES;
      }
  });
  ```

  Checked with Ubuntu 24.04, pcsc-lite 2.0.3, and no reader attached: the named account was accepted and other accounts were still refused. The `access_card` action, which `pcscd` checks when a client connects to a card, was not exercised.
- **Other PC/SC errors:** The message shows the code that the PC/SC service returned.
- **PIN prompts at every start:** This is correct for a PIN-protected key. Use a `PinPolicy.NEVER` key for unattended use.
- **JDK 8 on recent macOS:** `javax.smartcardio` can fail to find the PC/SC framework. Run with `-Dsun.security.smartcardio.library=/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC`.
