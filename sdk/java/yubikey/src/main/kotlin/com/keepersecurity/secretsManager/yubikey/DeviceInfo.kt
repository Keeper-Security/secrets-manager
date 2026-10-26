package com.keepersecurity.secretsManager.yubikey

// Device info from the YubiKey Management application (firmware 5+), used to name the device like ykman does
internal class DeviceInfo(
    val serial: Long?,
    val formFactor: Int,
    val isFips: Boolean,
    val isSky: Boolean,
    val hasNfc: Boolean,
    val version: IntArray?
) {
    // e.g. "YubiKey 5C NFC FIPS"; mirrors get_name() in Yubico's yubikit (ykman)
    val name: String
        get() {
            if (version != null && version[0] < 5) return if (isFips) "YubiKey FIPS" else "YubiKey 4"
            val isNano = formFactor == USB_A_NANO || formFactor == USB_C_NANO
            val isBio = formFactor == USB_A_BIO || formFactor == USB_C_BIO
            val isC = formFactor == USB_C_KEYCHAIN || formFactor == USB_C_NANO || formFactor == USB_C_BIO
            val parts = mutableListOf<String>()
            when {
                isSky -> parts.add("Security Key")
                isBio -> parts.add("YubiKey")
                else -> parts.addAll(listOf("YubiKey", "5"))
            }
            when {
                isC -> parts.add("C")
                formFactor == USB_C_LIGHTNING -> parts.add("Ci")
            }
            if (isBio) parts.add("Bio")
            if (isNano) parts.add("Nano")
            when {
                hasNfc -> parts.add("NFC")
                formFactor == USB_A_KEYCHAIN && !isSky -> parts.add("A")
            }
            if (isFips) parts.add("FIPS")
            return parts.joinToString(" ").replace("5 C", "5C").replace("5 A", "5A")
        }

    companion object {
        private const val USB_A_KEYCHAIN = 1
        private const val USB_A_NANO = 2
        private const val USB_C_KEYCHAIN = 3
        private const val USB_C_NANO = 4
        private const val USB_C_LIGHTNING = 5
        private const val USB_A_BIO = 6
        private const val USB_C_BIO = 7

        private const val TAG_SERIAL = 0x02
        private const val TAG_FORM_FACTOR = 0x04
        private const val TAG_VERSION = 0x05
        private const val TAG_NFC_SUPPORTED = 0x0D

        // data: the response of READ CONFIG, a length byte followed by TLVs
        fun parse(data: ByteArray): DeviceInfo? {
            if (data.isEmpty() || data[0].u() + 1 > data.size) return null
            val fields = try {
                Tlv.parse(data.copyOfRange(1, 1 + data[0].u()))
            } catch (e: YubiKeyException) {
                return null
            }
            val formFactor = fields[TAG_FORM_FACTOR]?.firstOrNull()?.u() ?: 0
            return DeviceInfo(
                serial = fields[TAG_SERIAL]?.takeIf { it.size == 4 }?.fold(0L) { acc, b -> (acc shl 8) or b.u().toLong() },
                formFactor = formFactor and 0x0F,
                isFips = (formFactor and 0x80) != 0,
                isSky = (formFactor and 0x40) != 0,
                hasNfc = fields[TAG_NFC_SUPPORTED]?.any { it.u() != 0 } == true,
                version = fields[TAG_VERSION]?.takeIf { it.size == 3 }?.let { v -> IntArray(3) { v[it].u() } }
            )
        }
    }
}
