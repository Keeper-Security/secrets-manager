package com.keepersecurity.secretsManager.yubikey

import com.keepersecurity.secretsManager.core.AppData
import com.keepersecurity.secretsManager.core.AppKeyProtector
import com.keepersecurity.secretsManager.core.KEY_PRIVATE_KEY_PIN
import com.keepersecurity.secretsManager.core.KeyValueStorage
import com.keepersecurity.secretsManager.core.RequestSigner
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.util.Base64
import javax.smartcardio.Card
import javax.smartcardio.CardChannel
import javax.smartcardio.CardException
import javax.smartcardio.TerminalFactory

/**
 * Keeps the Keeper Secrets Manager client key on a YubiKey (PIV application) and signs requests with it.
 * It also protects the app key: the config keeps it only wrapped by a key-agreement key on the YubiKey.
 *
 * Each KSM config needs its own key pair, so every config uses its own slot. The app key wrapping key is
 * shared by all configs and lives in slot 9D (or a free retired slot when 9D is taken). Usage:
 * ```
 * // Once, with a One-Time Access Token: generate a key in the first free retired slot
 * YubiKeySigner(pin).use { signer ->
 *     initializeStorage(storage, oneTimeToken, publicKey = signer.generateKey())
 *     getSecrets(SecretsManagerOptions(storage, signer = signer, appKeyProtector = signer))
 * }
 * // Later: the config keeps its public key, which locates the slot
 * YubiKeySigner.forPublicKey(pin, storage.getBytes(KEY_PUBLIC_KEY)!!).use { signer ->
 *     getSecrets(SecretsManagerOptions(storage, signer = signer, appKeyProtector = signer))
 * }
 * ```
 * For unattended use, generate the key with [PinPolicy.NEVER] and open the signer without a PIN:
 * ```
 * YubiKeySigner().use { signer -> initializeStorage(storage, oneTimeToken, publicKey = signer.generateKey(pinPolicy = PinPolicy.NEVER)) }
 * YubiKeySigner.forPublicKey(storage.getBytes(KEY_PUBLIC_KEY)!!).use { signer -> ... }
 * ```
 * A [PinProvider] supplies the PIN only when the YubiKey asks for it, so one code path serves both kinds of keys.
 * [savePin] keeps the PIN of a PIN-protected key in the config for a while, see [PinProvider.fromStorage].
 *
 * The keys must be ECC P-256; YubiKeys whose PIV application does not support it are rejected.
 * The PIN is kept in memory until [close] so the signer can re-verify it after a card reset.
 */
class YubiKeySigner internal constructor(
    pin: CharArray?,
    private val pinProvider: PinProvider?,
    slot: PivSlot?,
    private val connector: () -> Connection
) : RequestSigner, AppKeyProtector, AutoCloseable {

    /**
     * [slot] null lets [generateKey] pick the first free retired slot (RETIRED1..RETIRED20).
     * [readerName] null uses the first connected YubiKey.
     */
    @JvmOverloads
    constructor(pin: CharArray, slot: PivSlot? = null, readerName: String? = null) :
            this(pin, null, slot, { connectReader(readerName) })

    /** Asks [pinProvider] for the PIN only when the YubiKey requires it */
    @JvmOverloads
    constructor(pinProvider: PinProvider, slot: PivSlot? = null, readerName: String? = null) :
            this(null, pinProvider, slot, { connectReader(readerName) })

    /** Without a PIN, for keys generated with [PinPolicy.NEVER] */
    @JvmOverloads
    constructor(slot: PivSlot? = null, readerName: String? = null) :
            this(null, null, slot, { connectReader(readerName) })

    internal class Connection(val channel: CardChannel, private val card: Card?) {
        fun beginExclusive() {
            try { card?.beginExclusive() } catch (_: CardException) { }
        }

        fun endExclusive() {
            try { card?.endExclusive() } catch (_: CardException) { }
        }

        // Resetting the card clears the PIN verification state
        fun close() {
            try { card?.disconnect(true) } catch (_: CardException) { }
        }
    }

    private class WrappingKey(val slot: PivSlot, val publicKey: ByteArray, val pinless: Boolean)

    private var pin: CharArray? = pin?.copyOf()
    private var pinFromConfig = false
    private var connection: Connection? = null
    private var session: PivSession? = null
    private var pinVerified = false
    private var keyChecked = false
    private var pinAlways = false
    private var closed = false
    private var device: String? = null
    private var location: String? = null  // keyLocation of the current slot
    private var wrappingKey: WrappingKey? = null
    private val unwrapped = HashMap<String, ByteArray>()

    // Kept from generateKey until onBound names the slot's certificate after the application
    private var pendingCertificate: Pair<ByteArray, ByteArray>? = null  // management key, public key

    /** The slot holding the key; null until [generateKey] picks one */
    var slot: PivSlot? = slot
        @Synchronized get
        private set

    /** PIV application version, e.g. "5.4.3" for firmware 5.4.3 */
    val version: String
        @Synchronized get() = withSession { it.version.joinToString(".") }

    /**
     * Where the key is kept, e.g. "YubiKey 5C NFC FIPS, serial 12345678, PIV slot 82 (RETIRED1)"; null until
     * a slot is selected. The SDK saves it in the config as KEY_PRIVATE_KEY_LOCATION. The model name is the
     * one ykman shows, and the serial is printed on the YubiKey. A key generated with [PinPolicy.NEVER] adds
     * ", unattended (no PIN)".
     */
    override val keyLocation: String?
        @Synchronized get() {
            val slot = slot ?: return null
            // Core reads it before every request, so it is built once per slot
            location?.let { return it }
            return withSession { s ->
                val device = device ?: describeDevice(s).also { device = it }
                "$device, PIV slot ${"%02X".format(slot.keyRef)} (${slot.name})" + if (isPinless(s)) ", unattended (no PIN)" else ""
            }.also { location = it }
        }

    private fun describeDevice(s: PivSession): String {
        val info = s.deviceInfo
        val name = info?.name ?: if (s.version[0] == 4) "YubiKey 4" else "YubiKey"
        val serial = info?.serial ?: s.serial()
        return if (serial != null) "$name, serial $serial" else name
    }

    /** The slot's public key as a raw uncompressed P-256 point (65 bytes). Requires firmware 5.3 or later. */
    val publicKey: ByteArray
        @Synchronized get() = withSession { s ->
            if (!s.metadataSupported) throw YubiKeyException("Reading the public key back requires YubiKey firmware 5.3 or later")
            val slot = requireSlot()
            val metadata = s.getMetadata(slot.keyRef) ?: throw YubiKeyException("There is no key in the slot $slot")
            requireP256(metadata, slot)
            metadata.publicKey ?: malformed()
        }

    /**
     * Generates an ECC P-256 key in [slot], or in the first free retired slot when no slot was given.
     * Returns the raw public key for `initializeStorage(publicKey = ...)`.
     * Refuses to replace an existing key or certificate unless [overwrite] is set.
     *
     * Also creates the app key wrapping key if the YubiKey has none (firmware 5.3 or later), and keeps
     * [managementKey] in memory until binding, when the slot gets a certificate named after the application.
     * A [PinPolicy.NEVER] key, for unattended use, needs no PIN and gets its own PIN-less wrapping key.
     */
    @JvmOverloads
    @Synchronized
    fun generateKey(
        managementKey: ByteArray = DEFAULT_MANAGEMENT_KEY,
        pinPolicy: PinPolicy = PinPolicy.DEFAULT,
        touchPolicy: TouchPolicy = TouchPolicy.DEFAULT,
        overwrite: Boolean = false
    ): ByteArray = withSession { s ->
        val slot = this.slot ?: freeSlot(s)
        val hasKey = s.metadataSupported && s.getMetadata(slot.keyRef) != null
        val hasCertificate = s.hasCertificate(slot.objectId)
        if ((hasKey || hasCertificate) && !overwrite) {
            throw YubiKeyException("The slot $slot already holds a ${if (hasKey) "key" else "certificate"}; pass overwrite = true to replace it")
        }
        val pinless = pinPolicy == PinPolicy.NEVER
        // Check the PIN before touching the slot, so a wrong PIN can't leave an orphaned key behind
        if (!pinless) verifyPin(s)
        s.authenticateManagementKey(managementKey)
        val publicKey = s.generateEcP256(slot.keyRef, pinPolicy.value, touchPolicy.value)
        // The old certificate no longer matches the key
        if (hasCertificate) s.deleteCertificate(slot.objectId)
        this.slot = slot
        keyChecked = false
        location = null

        val probe = ByteArray(32).also { SecureRandom().nextBytes(it) }
        if (!verify(publicKey, probe, signWith(s, probe))) {
            throw YubiKeyException("The key generated in the slot $slot failed the signature self-check")
        }
        if (s.metadataSupported) ensureWrappingKey(s, managementKey, pinless)
        pendingCertificate?.first?.fill(0)
        pendingCertificate = managementKey.copyOf() to publicKey
        publicKey
    }

    /**
     * Wraps the app key to the YubiKey's wrapping key; needs neither the PIN nor the management key.
     * The app key of a [PinPolicy.NEVER] client key goes to the PIN-less wrapping key, any other to the PIN one.
     */
    @Synchronized
    override fun wrap(appKey: ByteArray): ByteArray {
        val (key, pinless) = withSession { s ->
            val pinless = isPinless(s)
            findWrappingKey(s, pinless) to pinless
        }
        key ?: throw YubiKeyException("This YubiKey has no ${if (pinless) "PIN-less " else ""}app key wrapping key; generateKey() creates it")
        return AppKeyWrap.wrap(key.publicKey, appKey)
    }

    /**
     * Saves the PIN in the config as KEY_PRIVATE_KEY_PIN, so that runs opened with [PinProvider.fromStorage] need
     * nobody to enter it; [removePin] makes the config attended again. The PIN is verified on the YubiKey first,
     * so a wrong PIN is never saved. The config then holds the PIN in plain text: anyone with the config and
     * the YubiKey can use the key.
     */
    @Synchronized
    fun savePin(storage: KeyValueStorage) {
        val pin = withSession { s ->
            verifyPin(s)
            requirePin()
        }
        storage.saveString(KEY_PRIVATE_KEY_PIN, String(pin))
    }

    /** Unwraps with ECDH on the YubiKey (PIN required); the result is cached in memory until [close] */
    @Synchronized
    override fun unwrap(wrappedAppKey: ByteArray): ByteArray {
        val cacheKey = Base64.getEncoder().encodeToString(wrappedAppKey)
        unwrapped[cacheKey]?.let { return it.copyOf() }
        val wrapped = AppKeyWrap.parse(wrappedAppKey)
        val sharedSecret = withSession { s ->
            val slot = wrappingKey?.takeIf { it.publicKey.contentEquals(wrapped.wrappingPublicKey) }?.slot
                ?: findSlot(s, wrapped.wrappingPublicKey)
                ?: throw YubiKeyException("The key that wrapped the app key is not on the connected YubiKey")
            withPin(s) { s.ecdhP256(slot.keyRef, wrapped.ephemeralPublicKey) }
        }
        val appKey = AppKeyWrap.unwrap(wrapped, sharedSecret)
        sharedSecret.fill(0)
        unwrapped[cacheKey] = appKey
        return appKey.copyOf()
    }

    /** Names the slot's certificate after the application once the client is bound */
    @Synchronized
    override fun onBound(appData: AppData) {
        val (managementKey, publicKey) = pendingCertificate ?: return
        pendingCertificate = null
        try {
            withSession { s ->
                val slot = requireSlot()
                s.authenticateManagementKey(managementKey)
                writeCertificate(s, slot, publicKey, appData.title.ifBlank { DEFAULT_KEY_NAME }, keyAgreement = false)
            }
        } finally {
            managementKey.fill(0)
        }
    }

    @Synchronized
    override fun sign(data: ByteArray): ByteArray = withSession { s -> signWith(s, data) }

    @Synchronized
    override fun close() {
        closed = true
        pin?.fill('\u0000')
        pin = null
        pendingCertificate?.first?.fill(0)
        pendingCertificate = null
        unwrapped.values.forEach { it.fill(0) }
        unwrapped.clear()
        disconnect()
    }

    override fun toString() = "YubiKeySigner(slot=$slot)"

    // Finds the slot holding publicKey; requires firmware 5.3 or later
    private fun selectSlot(publicKey: ByteArray) = withSession { s ->
        slot = findSlot(s, publicKey) ?: throw YubiKeyException("The key of this config is not on the connected YubiKey")
        keyChecked = false
        location = null
    }

    private fun findSlot(s: PivSession, publicKey: ByteArray): PivSlot? {
        if (!s.metadataSupported) throw YubiKeyException("Finding a key by its public key requires YubiKey firmware 5.3 or later")
        return PivSlot.values().firstOrNull { s.getMetadata(it.keyRef)?.publicKey?.contentEquals(publicKey) == true }
    }

    // The first retired slot with neither a key nor a certificate
    private fun freeSlot(s: PivSession): PivSlot {
        if (!s.metadataSupported) throw YubiKeyException("Pass the slot explicitly: firmware older than 5.3 cannot report empty slots")
        return PivSlot.values().filter { it.name.startsWith("RETIRED") }.firstOrNull { isEmpty(s, it) }
            ?: throw YubiKeyException("All retired PIV slots of this YubiKey are in use")
    }

    private fun isEmpty(s: PivSession, slot: PivSlot) = s.getMetadata(slot.keyRef) == null && !s.hasCertificate(slot.objectId)

    // Whether the selected key was generated with PinPolicy.NEVER; such keys are for unattended use
    private fun isPinless(s: PivSession): Boolean {
        val slot = slot ?: return false
        return s.metadataSupported && s.getMetadata(slot.keyRef)?.pinPolicy == PinPolicy.NEVER.value
    }

    // The wrapping key is the P-256 key whose certificate is named WRAPPING_KEY_NAME, or PINLESS_WRAPPING_KEY_NAME
    // for the app keys of unattended configs
    private fun findWrappingKey(s: PivSession, pinless: Boolean): WrappingKey? {
        wrappingKey?.takeIf { it.pinless == pinless }?.let { return it }
        if (!s.metadataSupported) throw YubiKeyException("Wrapping the app key requires YubiKey firmware 5.3 or later")
        val name = if (pinless) PINLESS_WRAPPING_KEY_NAME else WRAPPING_KEY_NAME
        for (slot in listOf(PivSlot.KEY_MANAGEMENT) + PivSlot.values().filter { it.name.startsWith("RETIRED") }) {
            val metadata = s.getMetadata(slot.keyRef) ?: continue
            if (metadata.algorithm != ALG_ECCP256 || metadata.publicKey == null) continue
            val certificate = s.getCertificate(slot.objectId) ?: continue
            if (Certificates.commonName(certificate) == name) {
                return WrappingKey(slot, metadata.publicKey, pinless).also { wrappingKey = it }
            }
        }
        return null
    }

    // The app key wrapping key: a P-256 key-agreement key in slot 9D (or a free retired slot when 9D is taken),
    // identified by its certificate name. Generated only when missing; the PIN-less one with PinPolicy.NEVER.
    private fun ensureWrappingKey(s: PivSession, managementKey: ByteArray, pinless: Boolean): ByteArray {
        findWrappingKey(s, pinless)?.let { return it.publicKey }
        val slot = if (isEmpty(s, PivSlot.KEY_MANAGEMENT)) PivSlot.KEY_MANAGEMENT else freeSlot(s)
        if (!pinless) verifyPin(s)
        s.authenticateManagementKey(managementKey)
        val pinPolicy = if (pinless) PinPolicy.NEVER else PinPolicy.DEFAULT
        val publicKey = s.generateEcP256(slot.keyRef, pinPolicy.value, TouchPolicy.DEFAULT.value)
        writeCertificate(s, slot, publicKey, if (pinless) PINLESS_WRAPPING_KEY_NAME else WRAPPING_KEY_NAME, keyAgreement = true)
        wrappingKey = WrappingKey(slot, publicKey, pinless)
        return publicKey
    }

    // Requires management key authentication; the certificate is signed by the slot's own key (PIN required)
    private fun writeCertificate(s: PivSession, slot: PivSlot, publicKey: ByteArray, name: String, keyAgreement: Boolean) {
        val certificate = Certificates.selfSigned(publicKey, name, keyAgreement) { tbs ->
            val digest = MessageDigest.getInstance("SHA-256").digest(tbs)
            withPin(s) { s.signEcP256(slot.keyRef, digest) }
        }
        s.putCertificate(slot.objectId, certificate)
    }

    private fun requireSlot(): PivSlot =
        slot ?: throw YubiKeyException("No slot selected; generate a key with generateKey() or use forPublicKey()")

    private fun signWith(s: PivSession, data: ByteArray): ByteArray {
        val slot = requireSlot()
        if (!keyChecked) {
            if (s.metadataSupported) {
                val metadata = s.getMetadata(slot.keyRef)
                    ?: throw YubiKeyException("There is no key in the slot $slot; generate one with generateKey()")
                requireP256(metadata, slot)
                pinAlways = metadata.pinPolicy == PinPolicy.ALWAYS.value
            } else {
                pinAlways = slot == PivSlot.SIGNATURE
            }
            keyChecked = true
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        return withPin(s, always = pinAlways) { s.signEcP256(slot.keyRef, digest) }
    }

    // Runs a private key operation, verifying the PIN first if needed. Re-verifies once when the PIN state
    // was lost (another application used the card) or the key requires the PIN every time.
    // A PIN not fetched yet is fetched only when the card refuses the operation, so PIN-less keys never need one.
    private fun <T> withPin(s: PivSession, always: Boolean = false, operation: () -> T): T {
        if (always || (!pinVerified && pin != null)) verifyPin(s)
        return try {
            operation()
        } catch (e: SecurityStatusException) {
            verifyPin(s)
            operation()
        }
    }

    private fun verifyPin(s: PivSession) {
        pinVerified = false
        val pin = requirePin()
        if (!pinFromConfig) {
            s.verifyPin(pin)
        } else {
            // Unattended runs must not lock the PIN: keep the last retry for a person
            val retries = s.pinRetries()
            if (retries != null && retries <= 1) {
                throw YubiKeyException("Not using the PIN saved in the config ($KEY_PRIVATE_KEY_PIN), PIN retries left: $retries; " +
                        "enter the PIN interactively or correct $KEY_PRIVATE_KEY_PIN")
            }
            try {
                s.verifyPin(pin)
            } catch (e: WrongPinException) {
                throw YubiKeyException("The PIN saved in the config ($KEY_PRIVATE_KEY_PIN) is wrong, ${e.retriesLeft} retries left", e)
            }
        }
        pinVerified = true
    }

    // The PIN given to the constructor, or the one fetched from the PinProvider on first need
    private fun requirePin(): CharArray {
        pin?.let { return it }
        val provider = pinProvider ?: throw noPinException()
        val stored = (provider as? StoragePinProvider)?.storedPin()
        pinFromConfig = stored != null
        return (stored ?: provider.pin()).also { pin = it }
    }

    // Runs block on the open session; reconnects once if the card was reset or re-inserted
    private fun <T> withSession(block: (PivSession) -> T): T {
        if (closed) throw YubiKeyException("The YubiKey signer is closed")
        var attempt = 0
        while (true) {
            val s = session ?: connect()
            val c = connection!!
            c.beginExclusive()
            try {
                return block(s)
            } catch (e: Exception) {
                // CardException: reader I/O failed; IllegalStateException: the card was disconnected
                if (e !is CardException && e !is IllegalStateException) throw e
                disconnect()
                if (++attempt > 1) throw YubiKeyException("Lost connection to the YubiKey: ${e.message}", e)
            } finally {
                c.endExclusive()
            }
        }
    }

    private fun connect(): PivSession {
        val c = connector()
        val s = PivSession(c.channel)
        try {
            s.select()
        } catch (e: Exception) {
            c.close()
            throw e
        }
        connection = c
        session = s
        pinVerified = false
        keyChecked = false
        return s
    }

    private fun disconnect() {
        connection?.close()
        connection = null
        session = null
        pinVerified = false
    }

    private fun requireP256(metadata: PivMetadata, slot: PivSlot) {
        if (metadata.algorithm != ALG_ECCP256) {
            throw YubiKeyException("The key in the slot $slot is not an ECC P-256 key (algorithm ${"%02X".format(metadata.algorithm)})")
        }
    }

    companion object {
        /** Certificate name that marks the app key wrapping key */
        const val WRAPPING_KEY_NAME = "Keeper Secrets Manager App Key Wrapping"

        /** Certificate name that marks the PIN-less app key wrapping key, used by configs whose key has PinPolicy.NEVER */
        const val PINLESS_WRAPPING_KEY_NAME = "Keeper Secrets Manager App Key Wrapping, no PIN"

        // Certificate name of a client key whose application has no title
        private const val DEFAULT_KEY_NAME = "Keeper Secrets Manager"

        /** The factory default PIV management key (3DES, or AES-192 on firmware 5.7+) */
        @JvmStatic
        val DEFAULT_MANAGEMENT_KEY: ByteArray
            get() = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8)

        /**
         * Opens a signer for the slot holding [publicKey], the raw public key kept in the KSM config.
         * Requires firmware 5.3 or later.
         */
        @JvmStatic
        @JvmOverloads
        fun forPublicKey(pin: CharArray, publicKey: ByteArray, readerName: String? = null): YubiKeySigner =
            forPublicKey(pin, null, publicKey) { connectReader(readerName) }

        /** Asks [pinProvider] for the PIN only when the YubiKey requires it, e.g. `PinProvider.fromStorage(storage, prompt)` */
        @JvmStatic
        @JvmOverloads
        fun forPublicKey(pinProvider: PinProvider, publicKey: ByteArray, readerName: String? = null): YubiKeySigner =
            forPublicKey(null, pinProvider, publicKey) { connectReader(readerName) }

        /** Without a PIN, for keys generated with [PinPolicy.NEVER] */
        @JvmStatic
        @JvmOverloads
        fun forPublicKey(publicKey: ByteArray, readerName: String? = null): YubiKeySigner =
            forPublicKey(null, null, publicKey) { connectReader(readerName) }

        /** Deletes the PIN saved by [savePin], so the config needs someone to enter the PIN again */
        @JvmStatic
        fun removePin(storage: KeyValueStorage) = storage.delete(KEY_PRIVATE_KEY_PIN)

        internal fun forPublicKey(pin: CharArray?, pinProvider: PinProvider?, publicKey: ByteArray, connector: () -> Connection): YubiKeySigner {
            val signer = YubiKeySigner(pin, pinProvider, null, connector)
            try {
                signer.selectSlot(publicKey)
            } catch (e: Exception) {
                signer.close()
                throw e
            }
            return signer
        }

        /** Names of the connected PC/SC readers that look like YubiKeys */
        @JvmStatic
        fun listYubiKeys(): List<String> = terminals().filter { it.name.contains("yubikey", ignoreCase = true) }.map { it.name }

        private fun terminals() = try {
            TerminalFactory.getDefault().terminals().list()
        } catch (e: CardException) {
            // macOS and pcsc-lite report "no readers" as an exception
            emptyList()
        }

        private fun connectReader(readerName: String?): Connection {
            val terminals = terminals()
            val terminal = if (readerName != null) {
                terminals.firstOrNull { it.name == readerName }
                    ?: throw YubiKeyException("Smart card reader '$readerName' not found. Connected readers: ${terminals.map { it.name }}")
            } else {
                terminals.firstOrNull { it.name.contains("yubikey", ignoreCase = true) && it.isCardPresent }
                    ?: throw YubiKeyException("No YubiKey found. Connected readers: ${terminals.map { it.name }}")
            }
            return try {
                val card = terminal.connect("*")
                Connection(card.basicChannel, card)
            } catch (e: CardException) {
                // Usually another application holds the card exclusively
                throw YubiKeyException("Cannot connect to ${terminal.name}: ${e.message}. Another application may be holding " +
                        "the YubiKey (Yubico Authenticator, gpg's scdaemon); close it and retry", e)
            }
        }

        internal fun verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean =
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(AppKeyWrap.p256PublicKey(publicKey))
                update(data)
                verify(signature)
            }
    }
}
