package com.keepersecurity.secretsManager.yubikey

import com.keepersecurity.secretsManager.core.KEY_PRIVATE_KEY_PIN
import com.keepersecurity.secretsManager.core.KeyValueStorage
import com.keepersecurity.secretsManager.core.SecretsManagerException

open class YubiKeyException @JvmOverloads constructor(
    message: String,
    cause: Throwable? = null
) : SecretsManagerException(message, cause)

// Raised when the card answers "security status not satisfied" (PIN or management key required)
internal class SecurityStatusException(message: String) : YubiKeyException(message)

// Raised when the card rejects the PIN but has retries left
internal class WrongPinException(message: String, val retriesLeft: Int) : YubiKeyException(message)

/**
 * Supplies the PIV PIN when the YubiKey asks for it. [YubiKeySigner] calls it at most once, the first time a key
 * operation needs the PIN, and wipes the returned array on close. Keys generated with [PinPolicy.NEVER] never call it.
 */
fun interface PinProvider {
    fun pin(): CharArray

    companion object {
        /**
         * The PIN saved in the config as KEY_PRIVATE_KEY_PIN (see [YubiKeySigner.savePin]), or [fallback] when the
         * config has none. The config is read only when the PIN is needed.
         */
        @JvmStatic
        @JvmOverloads
        fun fromStorage(storage: KeyValueStorage, fallback: PinProvider? = null): PinProvider = StoragePinProvider(storage, fallback)
    }
}

// The signer recognizes this provider to treat a PIN from the config with care: an unattended run must not
// lock the PIN by retrying a wrong one
internal class StoragePinProvider(private val storage: KeyValueStorage, val fallback: PinProvider?) : PinProvider {
    fun storedPin(): CharArray? = storage.getString(KEY_PRIVATE_KEY_PIN)?.toCharArray()

    override fun pin(): CharArray = storedPin() ?: fallback?.pin() ?: throw noPinException()
}

internal fun noPinException() = YubiKeyException(
    "The YubiKey requires the PIV PIN for this operation, but the signer has none; for unattended use, " +
            "generate the key with PinPolicy.NEVER or save the PIN in the config with savePin()"
)

// PIV key slots. keyRef is the key reference used in GENERATE / GENERAL AUTHENTICATE,
// objectId is the data object that holds the slot's certificate.
enum class PivSlot(val keyRef: Int, internal val objectId: Int) {
    AUTHENTICATION(0x9A, 0x5FC105),
    SIGNATURE(0x9C, 0x5FC10A),
    KEY_MANAGEMENT(0x9D, 0x5FC10B),
    CARD_AUTHENTICATION(0x9E, 0x5FC101),

    // Retired key management slots, YubiKey 4 and later
    RETIRED1(0x82, 0x5FC10D), RETIRED2(0x83, 0x5FC10E), RETIRED3(0x84, 0x5FC10F), RETIRED4(0x85, 0x5FC110),
    RETIRED5(0x86, 0x5FC111), RETIRED6(0x87, 0x5FC112), RETIRED7(0x88, 0x5FC113), RETIRED8(0x89, 0x5FC114),
    RETIRED9(0x8A, 0x5FC115), RETIRED10(0x8B, 0x5FC116), RETIRED11(0x8C, 0x5FC117), RETIRED12(0x8D, 0x5FC118),
    RETIRED13(0x8E, 0x5FC119), RETIRED14(0x8F, 0x5FC11A), RETIRED15(0x90, 0x5FC11B), RETIRED16(0x91, 0x5FC11C),
    RETIRED17(0x92, 0x5FC11D), RETIRED18(0x93, 0x5FC11E), RETIRED19(0x94, 0x5FC11F), RETIRED20(0x95, 0x5FC120);

    override fun toString() = "$name (${"%02X".format(keyRef)})"
}

// DEFAULT leaves the choice to the YubiKey (the slot's default policy)
enum class PinPolicy(internal val value: Int) {
    DEFAULT(0), NEVER(1), ONCE(2), ALWAYS(3)
}

enum class TouchPolicy(internal val value: Int) {
    DEFAULT(0), NEVER(1), ALWAYS(2), CACHED(3)
}
