package com.keepersecurity.secretsManager.core

import java.io.DataInputStream
import kotlin.test.*

internal class MultiReleaseJarTest {

    // Class file major versions: 52 is Java 8, 65 is Java 21.
    @Test
    fun loadedClassesMatchRuntimeJavaVersion() {
        val resource = SecretsManagerOptions::class.java.getResource("SecretsManagerOptions.class")
        assertNotNull(resource)
        val major = DataInputStream(resource.openStream()).use {
            it.readInt() // magic
            it.readUnsignedShort() // minor
            it.readUnsignedShort()
        }
        val javaVersion = System.getProperty("java.specification.version").removePrefix("1.").toInt()
        // The versioned classes are only picked up when loading from the multi-release jar.
        val expected = if (resource.protocol == "jar" && javaVersion >= 21) 65 else 52
        assertEquals(expected, major, "Unexpected class file version loaded from $resource")
    }
}
