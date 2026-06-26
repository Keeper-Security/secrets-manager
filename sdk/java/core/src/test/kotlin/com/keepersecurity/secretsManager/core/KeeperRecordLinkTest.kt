package com.keepersecurity.secretsManager.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for the [KeeperRecordLink] typed accessor layer.
 *
 * Mirrors the Python reference suite `sdk/python/core/tests/record_link_test.py` (KSM-992, PR #1036)
 * so the Java accessors match the live-verified backend payload shapes: permission booleans with an
 * `allowedSettings` fallback (top-level wins), the new credential/meta accessors, lossless
 * `getLinkData()`, and the encrypted ai/jit settings.
 */
class KeeperRecordLinkTest {

    private val recordKey: ByteArray = getRandomBytes(32)

    /** Build a link whose data is base64 of the given plain JSON payload. */
    private fun plainLink(json: String, path: String? = null, recordUid: String = "RU_test") =
        KeeperRecordLink(recordUid, bytesToBase64(json.toByteArray(Charsets.UTF_8)), path)

    /** Build a link whose data is base64 of the payload encrypted (AES-256-GCM) under [key]. */
    private fun encryptedLink(json: String, key: ByteArray, path: String? = null, recordUid: String = "RU_test") =
        KeeperRecordLink(recordUid, bytesToBase64(encrypt(json.toByteArray(Charsets.UTF_8), key)), path)

    /**
     * Produce a base64 AES-GCM ciphertext whose first decoded byte equals [marker] ('{' or '[').
     * The IV is random per call, so we re-encrypt until we hit the marker (~1/256 each try). The
     * result is a real, decryptable ciphertext that also trips the plain-JSON fast path.
     */
    private fun ciphertextStartingWith(marker: Char, json: String, key: ByteArray): String {
        val target = marker.code.toByte()
        repeat(100_000) {
            val ct = encrypt(json.toByteArray(Charsets.UTF_8), key)
            if (ct.isNotEmpty() && ct[0] == target) return bytesToBase64(ct)
        }
        throw IllegalStateException("Could not generate ciphertext starting with '$marker'")
    }

    @Test
    fun booleanAccessorsReadPlainJson() {
        val link = plainLink("""{"is_admin": true, "rotation": true, "connections": false}""")
        assertTrue(link.isAdminUser())
        assertTrue(link.allowsRotation())
        assertFalse(link.allowsConnections())
        assertFalse(link.allowsPortForwards())
        assertFalse(link.isLaunchCredential())
        assertFalse(link.isIamUser())
        assertFalse(link.belongsTo())
        assertFalse(link.noUpdateServices())
    }

    @Test
    fun versionAndDecodedData() {
        val link = plainLink("""{"version": 3, "is_admin": false}""")
        assertEquals(3, link.getLinkDataVersion())
        assertTrue(link.getDecodedData()!!.startsWith("{"))
        assertTrue(link.hasReadableData())

        val notJson = plainLink("not json at all")
        assertFalse(notJson.hasReadableData())
        assertNull(notJson.getLinkDataVersion())

        val badBase64 = KeeperRecordLink("RU_test", "!!! not base64 !!!", null)
        assertNull(badBase64.getDecodedData())
        assertNull(badBase64.getLinkData())
    }

    @Test
    fun mightBeEncryptedByPath() {
        assertTrue(plainLink("{}", path = "ai_settings").mightBeEncrypted())
        assertTrue(plainLink("{}", path = "jit_settings").mightBeEncrypted())
        assertFalse(plainLink("{}", path = "meta").mightBeEncrypted())
        assertFalse(plainLink("{}", path = "something_else").mightBeEncrypted())
        assertFalse(plainLink("{}", path = null).mightBeEncrypted())
    }

    @Test
    fun getDecryptedDataRoundtrip() {
        val link = encryptedLink("""{"enabled": true, "ttl": 3600}""", recordKey, path = "jit_settings")
        val decrypted = link.getDecryptedData(recordKey)
        assertNotNull(decrypted)
        assertTrue(decrypted.contains("enabled"))
        assertNull(link.getDecryptedData(null))
        assertNull(link.getDecryptedData(getRandomBytes(32))) // wrong key fails gracefully
    }

    @Test
    fun getLinkDataPlainAndEncrypted() {
        val plain = plainLink("""{"aiEnabled": true}""", path = "ai_settings")
        assertEquals(true, plain.getLinkData()!!["aiEnabled"])

        val encrypted = encryptedLink("""{"enabled": true}""", recordKey, path = "jit_settings")
        assertNull(encrypted.getLinkData())              // can't decrypt without a key
        assertEquals(true, encrypted.getLinkData(recordKey)!!["enabled"])
    }

    @Test
    fun settingsPathFilters() {
        val ai = plainLink("""{"aiEnabled": true}""", path = "ai_settings")
        val jit = plainLink("""{"enabled": true}""", path = "jit_settings")

        assertNotNull(ai.getAiSettingsData(recordKey))
        assertNull(ai.getJitSettingsData(recordKey))
        assertNotNull(jit.getJitSettingsData(recordKey))
        assertNull(jit.getAiSettingsData(recordKey))
        assertNotNull(ai.getSettingsForPath("ai_settings"))
        assertNull(ai.getSettingsForPath("other"))
    }

    @Test
    fun stringEncodedValuesAreNotCoerced() {
        val strings = plainLink("""{"is_admin": "true", "rotation": "false", "version": "3"}""")
        assertFalse(strings.isAdminUser())          // "true" string is not a boolean
        assertFalse(strings.allowsRotation())       // "false" string is not a boolean
        assertNull(strings.getLinkDataVersion())    // "3" string is not an integer

        val real = plainLink("""{"is_admin": true, "version": 3}""")
        assertTrue(real.isAdminUser())
        assertEquals(3, real.getLinkDataVersion())

        // A JSON boolean must not be read as an integer version.
        assertNull(plainLink("""{"version": true}""").getLinkDataVersion())
    }

    @Test
    fun hasEncryptedDataDetection() {
        // Non-printable bytes that are neither a JSON object nor printable text.
        val encryptedLooking = KeeperRecordLink("RU_test", bytesToBase64(ByteArray(40) { (it % 32).toByte() }), null)
        assertTrue(encryptedLooking.hasEncryptedData())

        assertFalse(plainLink("just plain readable text, not json").hasEncryptedData())
        assertFalse(plainLink("""{"a": 1}""").hasEncryptedData())
        assertFalse(KeeperRecordLink("RU_test", null, null).hasEncryptedData())
    }

    @Test
    fun getSettingsForPathEncrypted() {
        val link = encryptedLink("""{"customSetting": 42}""", recordKey, path = "custom_settings")
        assertEquals(42, link.getSettingsForPath("custom_settings", recordKey)!!["customSetting"])
        assertNull(link.getSettingsForPath("other", recordKey))
    }

    @Test
    fun metaLinkLiveShape() {
        val meta = plainLink(
            """
            {
              "allowedSettings": {
                "rotation": true,
                "connections": true,
                "portForwards": true,
                "sessionRecording": true,
                "typescriptRecording": false,
                "aiEnabled": true,
                "aiSessionTerminate": true,
                "remoteBrowserIsolation": true
              },
              "rotateOnTermination": false,
              "version": 1,
              "no_update_services": true
            }
            """.trimIndent(),
            path = "meta"
        )

        // Permission booleans are absent at the top level — read via the allowedSettings fallback.
        assertTrue(meta.allowsRotation())
        assertTrue(meta.allowsConnections())
        assertTrue(meta.allowsPortForwards())
        assertTrue(meta.allowsSessionRecording())
        assertFalse(meta.allowsTypescriptRecording())
        assertTrue(meta.allowsRemoteBrowserIsolation())
        assertTrue(meta.aiEnabled())
        assertTrue(meta.aiSessionTerminate())

        assertFalse(meta.rotatesOnTermination())   // top-level
        assertEquals(1, meta.getLinkDataVersion())
        assertTrue(meta.noUpdateServices())        // top-level

        assertEquals(true, meta.getAllowedSettings()["rotation"])
        assertNotNull(meta.getMetaData())
        assertNull(plainLink("{}", path = null).getMetaData()) // path-gated
    }

    @Test
    fun topLevelWinsOverAllowedSettings() {
        val both = plainLink("""{"rotation": false, "allowedSettings": {"rotation": true}}""")
        assertFalse(both.allowsRotation())          // top-level false wins

        val fallbackOnly = plainLink("""{"allowedSettings": {"rotation": true}}""")
        assertTrue(fallbackOnly.allowsRotation())   // fallback applies when top-level absent
    }

    @Test
    fun credentialLinkLiveShape() {
        val credential = plainLink(
            """
            {
              "is_admin": true,
              "is_iam_user": false,
              "belongs_to": true,
              "is_launch_credential": true,
              "rotation_settings": {
                "schedule": "",
                "pwd_complexity": "ZmFrZS1jb21wbGV4aXR5",
                "disabled": false,
                "noop": false,
                "saas_record_uid_list": []
              }
            }
            """.trimIndent()
        )
        assertTrue(credential.isAdminUser())
        assertFalse(credential.isIamUser())
        assertTrue(credential.belongsTo())
        assertTrue(credential.isLaunchCredential())

        val rotation = credential.getRotationSettings()
        assertNotNull(rotation)
        assertEquals("", rotation["schedule"])
        assertEquals(false, rotation["disabled"])
        assertEquals(emptyList<Any>(), rotation["saas_record_uid_list"])

        assertNull(plainLink("""{"is_admin": true}""").getRotationSettings())
    }

    @Test
    fun dataLessReferenceLink() {
        val ref = KeeperRecordLink("RU_ref", null, null)
        assertEquals("RU_ref", ref.recordUid)
        assertFalse(ref.isAdminUser())
        assertFalse(ref.allowsRotation())
        assertNull(ref.getLinkDataVersion())
        assertNull(ref.getDecodedData())
        assertNull(ref.getDecryptedData(recordKey))
        assertNull(ref.getLinkData())
        assertTrue(ref.getAllowedSettings().isEmpty())
        assertNull(ref.getRotationSettings())
        assertFalse(ref.hasReadableData())
        assertFalse(ref.hasEncryptedData())
    }

    @Test
    fun aiSettingsLiveShape() {
        val ai = encryptedLink(
            """
            {
              "version": "v1.0.0",
              "riskLevels": {
                "critical": {"tags": {"allow": [], "deny": []}, "aiSessionTerminate": true},
                "high": {"tags": {"allow": [], "deny": []}, "aiSessionTerminate": true},
                "medium": {"tags": {"allow": [], "deny": []}, "aiSessionTerminate": true},
                "low": {"tags": {"allow": []}, "aiSessionTerminate": false}
              }
            }
            """.trimIndent(),
            recordKey,
            path = "ai_settings"
        )
        val data = ai.getAiSettingsData(recordKey)
        assertNotNull(data)
        assertEquals("v1.0.0", data["version"])
        assertTrue(data["riskLevels"] is Map<*, *>)   // nested object preserved, not stringified
        assertNull(ai.getLinkDataVersion())            // string version is not an integer
    }

    @Test
    fun jitSettingsLiveShape() {
        val jit = encryptedLink(
            """
            {
              "createEphemeral": true,
              "elevate": true,
              "elevationMethod": "group",
              "elevationString": "arn:aws",
              "baseDistinguishedName": ""
            }
            """.trimIndent(),
            recordKey,
            path = "jit_settings"
        )
        val data = jit.getJitSettingsData(recordKey)
        assertNotNull(data)
        assertEquals(true, data["createEphemeral"])
        assertEquals(true, data["elevate"])
        assertEquals("group", data["elevationMethod"])
        assertEquals("arn:aws", data["elevationString"])
        assertEquals("", data["baseDistinguishedName"])
    }

    @Test
    fun losslessnessPreservesNestedStructures() {
        val link = plainLink("""{"is_admin": true, "futureField": {"nested": [1, 2, 3]}}""")
        val data = link.getLinkData()
        assertNotNull(data)

        val future = data["futureField"]
        assertTrue(future is Map<*, *>)               // nested object preserved as a Map, not a String
        @Suppress("UNCHECKED_CAST")
        val nested = (future as Map<String, Any>)["nested"]
        assertEquals(listOf(1, 2, 3), nested)         // nested array preserved as a List of ints

        // Raw link fields are untouched.
        assertEquals("RU_test", link.recordUid)
        assertNull(link.path)
        assertNotNull(link.data)
    }

    @Test
    fun ciphertextWithJsonLikeFirstByte() {
        val payload = """{"createEphemeral": true, "elevate": true}"""
        for (marker in listOf('{', '[')) {
            val link = KeeperRecordLink("RU_test", ciphertextStartingWith(marker, payload, recordKey), "jit_settings")
            assertEquals(marker, link.getDecodedData()!![0])
            assertNull(link.getLinkData(null))         // leading {/[ is coincidental; no key -> null
            val data = link.getLinkData(recordKey)     // falls through to decryption
            assertNotNull(data)
            assertEquals(true, data["createEphemeral"])
            assertEquals(true, data["elevate"])
            assertNotNull(link.getJitSettingsData(recordKey))
        }
        // Plain JSON is unaffected and parses without a key.
        assertEquals(1, plainLink("""{"a": 1}""").getLinkData()!!["a"])
    }
}
