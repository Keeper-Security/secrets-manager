package com.keepersecurity.secretsManager.core

import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal class CryptoStressResult(val expected: Int, val thrown: List<Throwable>, val undecryptable: Int, val completed: Int)

private const val BARRIER_TIMEOUT_SECONDS = 30L
private const val SHUTDOWN_GRACE_SECONDS = 10L
internal const val STRESS_THREAD_PREFIX = "ksm-stress-"

/**
 * Runs publicEncrypt from [threadCount] threads released together by a barrier, then decrypts every
 * ciphertext on the calling thread. The barrier is what makes a shared digest, key generator or key
 * factory fail often enough to catch. [onFirstEncrypt] runs after each successful encrypt, so a latch
 * countdown there signals that workers are busy.
 */
internal fun runPublicEncryptStress(
    threadCount: Int = 8,
    bursts: Int = 2_000,
    onFirstEncrypt: () -> Unit = {},
): CryptoStressResult {
    val keyPair = generateKeyPair()
    val publicKey = extractPublicRaw(keyPair.public)
    val barrier = CyclicBarrier(threadCount)
    val thrown = ConcurrentLinkedQueue<Throwable>()
    val results = ConcurrentLinkedQueue<Pair<ByteArray, ByteArray>>()
    val threadNumber = AtomicInteger()
    // A distinct name prefix lets tests find leaked workers without matching unrelated pools.
    val pool = Executors.newFixedThreadPool(threadCount) { Thread(it, STRESS_THREAD_PREFIX + threadNumber.incrementAndGet()) }
    try {
        val futures = List(threadCount) {
            pool.submit {
                for (burst in 0 until bursts) {
                    // JUnit's timeout interrupts only the test thread, so workers must notice
                    // cancellation themselves. publicEncrypt ignores interrupts.
                    if (Thread.currentThread().isInterrupted) return@submit
                    try {
                        barrier.await(BARRIER_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    } catch (e: InterruptedException) {
                        Thread.currentThread().interrupt()
                        return@submit
                    } catch (e: Exception) {
                        thrown.add(e)
                        return@submit
                    }
                    try {
                        val data = getRandomBytes(32)
                        results.add(data to publicEncrypt(data, publicKey))
                        onFirstEncrypt()
                    } catch (e: Exception) {
                        thrown.add(e)
                    }
                }
            }
        }
        try {
            futures.forEach { it.get() }
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        }
    } finally {
        pool.shutdownNow()
        check(pool.awaitTermination(SHUTDOWN_GRACE_SECONDS, TimeUnit.SECONDS)) {
            "stress workers still running ${SHUTDOWN_GRACE_SECONDS}s after shutdown"
        }
    }

    val privateKey = keyPair.private.encoded
    val undecryptable = results.count { (data, ciphertext) ->
        runCatching { privateDecrypt(ciphertext, privateKey) }.getOrNull()?.contentEquals(data) != true
    }
    return CryptoStressResult(threadCount * bursts, thrown.toList(), undecryptable, results.size + thrown.size)
}
