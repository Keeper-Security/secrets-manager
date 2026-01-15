package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

/**
 * Test suite for PAM connection settings fields added in KSM-738 (VAUL-7662).
 * Tests serialization/deserialization of new fields in:
 * - PamRbiConnection (6 new fields: audio/clipboard controls)
 * - PamSettingsPortForward (2 new fields: local port configuration)
 * - PamSettingsConnection (43 new fields: RDP, SSH/Terminal, VNC, Kubernetes)
 */
@ExperimentalSerializationApi
internal class RecordDataPamFieldsTest {

    // Test 1: PamRbiConnection with all new audio/clipboard fields
    @Test
    fun testPamRbiConnectionWithAudioClipboardFields() {
        val connection = PamRbiConnection(
            protocol = "HTTP",
            disableAudio = true,
            disableCopy = false,
            disablePaste = true,
            audioChannels = 2,
            audioBps = 16,
            audioSampleRate = 44100
        )

        val json = Json.encodeToString(connection)
        val deserialized = Json.decodeFromString<PamRbiConnection>(json)

        assertEquals(connection, deserialized)
        assertEquals(true, deserialized.disableAudio)
        assertEquals(false, deserialized.disableCopy)
        assertEquals(true, deserialized.disablePaste)
        assertEquals(2, deserialized.audioChannels)
        assertEquals(16, deserialized.audioBps)
        assertEquals(44100, deserialized.audioSampleRate)
    }

    // Test 2: PamSettingsPortForward with local port fields
    @Test
    fun testPamSettingsPortForwardWithLocalPort() {
        val portForward = PamSettingsPortForward(
            reusePort = true,
            port = "3389",
            useSpecifiedLocalPort = true,
            localPort = "13389"
        )

        val json = Json.encodeToString(portForward)
        val deserialized = Json.decodeFromString<PamSettingsPortForward>(json)

        assertEquals(portForward, deserialized)
        assertEquals(true, deserialized.useSpecifiedLocalPort)
        assertEquals("13389", deserialized.localPort)
        assertEquals("3389", deserialized.port)
        assertEquals(true, deserialized.reusePort)
    }

    // Test 3: PamSettingsConnection with RDP fields
    @Test
    fun testPamSettingsConnectionRdpFields() {
        val connection = PamSettingsConnection(
            protocol = "RDP",
            port = "3389",
            initialProgram = "notepad.exe",
            clientName = "MyClient",
            width = 1920,
            height = 1080,
            dpi = 96,
            colorDepth = 24,
            enableTouch = true,
            enablePrinting = true,
            remoteApp = "Excel",
            remoteAppDir = "C:\\Office",
            remoteAppArgs = "/open document.xlsx",
            normalizeClipboard = "true",
            serverLayout = "en-US",
            console = false,
            readOnly = false,
            consoleAudio = true,
            enableAudioInput = true,
            enableTheming = true,
            enableFontSmoothing = true,
            enableDesktopComposition = true,
            enableMenuAnimations = false,
            disableBitmapCaching = false,
            disableOffscreenCaching = false,
            disableGlyphCaching = false,
            redirectedPrinterName = "HP LaserJet"
        )

        val json = Json.encodeToString(connection)
        val deserialized = Json.decodeFromString<PamSettingsConnection>(json)

        assertEquals("RDP", deserialized.protocol)
        assertEquals("3389", deserialized.port)
        assertEquals("notepad.exe", deserialized.initialProgram)
        assertEquals("MyClient", deserialized.clientName)
        assertEquals(1920, deserialized.width)
        assertEquals(1080, deserialized.height)
        assertEquals(96, deserialized.dpi)
        assertEquals(24, deserialized.colorDepth)
        assertEquals(true, deserialized.enableTouch)
        assertEquals(true, deserialized.enablePrinting)
        assertEquals("Excel", deserialized.remoteApp)
        assertEquals("C:\\Office", deserialized.remoteAppDir)
        assertEquals("/open document.xlsx", deserialized.remoteAppArgs)
        assertEquals("HP LaserJet", deserialized.redirectedPrinterName)
    }

    // Test 4: PamSettingsConnection with SSH/Terminal fields
    @Test
    fun testPamSettingsConnectionSshTerminalFields() {
        val connection = PamSettingsConnection(
            protocol = "SSH",
            port = "22",
            fontName = "Courier New",
            scrollback = 1000,
            backspace = "^H",
            terminalType = "xterm-256color",
            clipboardEncoding = "UTF-8",
            locale = "en_US.UTF-8",
            serverAliveInterval = 60,
            timezone = "America/New_York"
        )

        val json = Json.encodeToString(connection)
        val deserialized = Json.decodeFromString<PamSettingsConnection>(json)

        assertEquals("SSH", deserialized.protocol)
        assertEquals("22", deserialized.port)
        assertEquals("Courier New", deserialized.fontName)
        assertEquals(1000, deserialized.scrollback)
        assertEquals("^H", deserialized.backspace)
        assertEquals("xterm-256color", deserialized.terminalType)
        assertEquals("UTF-8", deserialized.clipboardEncoding)
        assertEquals("en_US.UTF-8", deserialized.locale)
        assertEquals(60, deserialized.serverAliveInterval)
        assertEquals("America/New_York", deserialized.timezone)
    }

    // Test 5: PamSettingsConnection with VNC fields
    @Test
    fun testPamSettingsConnectionVncFields() {
        val connection = PamSettingsConnection(
            protocol = "VNC",
            port = "5900",
            enableAudio = true,
            audioServername = "audio.example.com",
            swapRedBlue = false,
            cursor = "remote",
            forceLossless = true
        )

        val json = Json.encodeToString(connection)
        val deserialized = Json.decodeFromString<PamSettingsConnection>(json)

        assertEquals("VNC", deserialized.protocol)
        assertEquals("5900", deserialized.port)
        assertEquals(true, deserialized.enableAudio)
        assertEquals("audio.example.com", deserialized.audioServername)
        assertEquals(false, deserialized.swapRedBlue)
        assertEquals("remote", deserialized.cursor)
        assertEquals(true, deserialized.forceLossless)
    }

    // Test 6: PamSettingsConnection with Kubernetes fields
    @Test
    fun testPamSettingsConnectionKubernetesFields() {
        val connection = PamSettingsConnection(
            protocol = "K8S",
            useSSL = true,
            namespace = "production",
            pod = "web-pod-123",
            container = "nginx",
            caCert = "-----BEGIN CERTIFICATE-----...",
            clientCert = "-----BEGIN CERTIFICATE-----...",
            clientKey = "-----BEGIN PRIVATE KEY-----..."
        )

        val json = Json.encodeToString(connection)
        val deserialized = Json.decodeFromString<PamSettingsConnection>(json)

        assertEquals("K8S", deserialized.protocol)
        assertEquals(true, deserialized.useSSL)
        assertEquals("production", deserialized.namespace)
        assertEquals("web-pod-123", deserialized.pod)
        assertEquals("nginx", deserialized.container)
        assertEquals("-----BEGIN CERTIFICATE-----...", deserialized.caCert)
        assertEquals("-----BEGIN CERTIFICATE-----...", deserialized.clientCert)
        assertEquals("-----BEGIN PRIVATE KEY-----...", deserialized.clientKey)
    }

    // Test 7: All fields null (default constructor) - tests nullable field handling
    @Test
    fun testPamFieldsWithNullValues() {
        val rbiConnection = PamRbiConnection()
        val portForward = PamSettingsPortForward()
        val connection = PamSettingsConnection()

        val rbiJson = Json.encodeToString(rbiConnection)
        val portForwardJson = Json.encodeToString(portForward)
        val connectionJson = Json.encodeToString(connection)

        val rbiDeserialized = Json.decodeFromString<PamRbiConnection>(rbiJson)
        val portForwardDeserialized = Json.decodeFromString<PamSettingsPortForward>(portForwardJson)
        val connectionDeserialized = Json.decodeFromString<PamSettingsConnection>(connectionJson)

        // PamRbiConnection nulls
        assertNull(rbiDeserialized.protocol)
        assertNull(rbiDeserialized.disableAudio)
        assertNull(rbiDeserialized.audioChannels)

        // PamSettingsPortForward nulls
        assertNull(portForwardDeserialized.port)
        assertNull(portForwardDeserialized.useSpecifiedLocalPort)
        assertNull(portForwardDeserialized.localPort)

        // PamSettingsConnection nulls
        assertNull(connectionDeserialized.protocol)
        assertNull(connectionDeserialized.fontName)
        assertNull(connectionDeserialized.enableAudio)
        assertNull(connectionDeserialized.useSSL)
        assertNull(connectionDeserialized.initialProgram)
        assertNull(connectionDeserialized.scrollback)
    }
}
