package com.keepersecurity.secretsManager.core

import java.io.File
import java.security.Provider
import java.security.Security
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * KeeperCryptoParameters captures its provider once, on first use, so one JVM can only ever test one
 * provider. Each case therefore runs the stress workload in a fresh JVM with the provider registered
 * before the SDK initializes, and checks which provider the SDK actually captured.
 */
internal class CryptoProviderIsolationTest {

    @Test(timeout = 180_000)
    fun stressWorkloadPassesWithDefaultJca() = runIsolated(NO_PROVIDER, System.getProperty("java.class.path"))

    @Test(timeout = 180_000)
    fun stressWorkloadPassesWithBcFips() = runIsolated("BCFIPS", System.getProperty("java.class.path"))

    @Test(timeout = 180_000)
    fun stressWorkloadPassesWithBouncyCastle() {
        // bcprov and bc-fips define the same classes, so the child gets bcprov in place of bc-fips.
        // A missing property fails the test on purpose: skipping would read as coverage that never ran.
        val bcprov = assertNotNull(System.getProperty("ksm.test.bcprov.path"), "ksm.test.bcprov.path is not set")
        assertTrue(File(bcprov).isFile, "ksm.test.bcprov.path does not point at a jar: $bcprov")
        val withoutFips = System.getProperty("java.class.path").split(File.pathSeparator)
            .filterNot { File(it).name.startsWith("bc-fips") }
        runIsolated("BC", (withoutFips + bcprov).joinToString(File.pathSeparator))
    }

    private fun runIsolated(provider: String, classpath: String, budgetSeconds: Long = 150) {
        val java = File(System.getProperty("java.home"), "bin/java").path
        // Output goes to a file because reading a pipe before waitFor blocks forever on a hung child,
        // so the time budget would never apply and the JUnit timeout would orphan the process.
        val log = File.createTempFile("ksm-isolated-", ".log", File(System.getProperty("java.io.tmpdir")))
        val process = ProcessBuilder(java, "-cp", classpath, CryptoIsolationMain::class.java.name, provider)
            .redirectErrorStream(true).redirectOutput(log).start()
        try {
            if (!process.waitFor(budgetSeconds, TimeUnit.SECONDS)) {
                throw AssertionError("isolated $provider run timed out after ${budgetSeconds}s:\n${log.readText()}")
            }
            val output = log.readText()
            assertEquals(0, process.exitValue(), "isolated $provider run failed:\n$output")
            assertTrue(output.contains("provider=$provider"), "child did not report the expected provider:\n$output")
        } finally {
            process.destroyForcibly()
            log.delete()
        }
    }
}

internal const val NO_PROVIDER = "none"

internal object CryptoIsolationMain {
    // Providers load by name because the child classpath holds either bc-fips or bcprov, never both.
    private val providerClasses = mapOf(
        "BCFIPS" to "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider",
        "BC" to "org.bouncycastle.jce.provider.BouncyCastleProvider",
    )

    @JvmStatic
    fun main(args: Array<String>) {
        val expected = args[0]
        providerClasses[expected]?.let {
            Security.addProvider(Class.forName(it).getDeclaredConstructor().newInstance() as Provider)
        }
        val captured = KeeperCryptoParameters.provider?.name ?: NO_PROVIDER
        println("provider=$captured")
        if (captured != expected) {
            println("expected provider $expected but the SDK captured $captured")
            exitProcess(2)
        }
        val stress = runPublicEncryptStress()
        println("expected=${stress.expected} completed=${stress.completed} thrown=${stress.thrown.size} undecryptable=${stress.undecryptable}")
        exitProcess(if (stress.thrown.isEmpty() && stress.undecryptable == 0 && stress.completed == stress.expected) 0 else 1)
    }
}
