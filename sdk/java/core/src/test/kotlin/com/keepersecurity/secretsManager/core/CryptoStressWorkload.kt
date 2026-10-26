package com.keepersecurity.secretsManager.core

import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal class CryptoStressResult(val expected: Int, val thrown: List<Throwable>, val undecryptable: Int, val completed: Int)

private const val BARRIER_TIMEOUT_SECONDS = 30L
private const val SHUTDOWN_GRACE_MILLIS = 10_000L
internal const val STRESS_THREAD_PREFIX = "ksm-stress-"

/**
 * Runs publicEncrypt from [threadCount] threads released together by a barrier, then decrypts every
 * ciphertext on the calling thread. The barrier is what makes a shared digest, key generator or key
 * factory fail often enough to catch. [onFirstEncrypt] runs after each successful encrypt, so a latch
 * countdown there signals that workers are busy.
 *
 * Every thread the pool creates is added to [workers], so a caller can check that none outlives the call.
 * On every exit path the pool is shut down and all workers are joined under one [cleanupMillis] deadline.
 * [afterWorkerTask] runs on a worker thread after the pool has finished with it, which lets a test hold a
 * thread open past executor termination.
 */
internal fun runPublicEncryptStress(
    threadCount: Int = 8,
    bursts: Int = 2_000,
    onFirstEncrypt: () -> Unit = {},
    workers: MutableCollection<Thread> = ConcurrentLinkedQueue(),
    cleanupMillis: Long = SHUTDOWN_GRACE_MILLIS,
    afterWorkerTask: () -> Unit = {},
): CryptoStressResult {
    val keyPair = generateKeyPair()
    val publicKey = extractPublicRaw(keyPair.public)
    val barrier = CyclicBarrier(threadCount)
    val thrown = ConcurrentLinkedQueue<Throwable>()
    val results = ConcurrentLinkedQueue<Pair<ByteArray, ByteArray>>()
    val threadNumber = AtomicInteger()
    // A distinct name prefix lets tests find leaked workers without matching unrelated pools.
    val pool = Executors.newFixedThreadPool(threadCount) {
        val worker = Thread({ try { it.run() } finally { afterWorkerTask() } }, STRESS_THREAD_PREFIX + threadNumber.incrementAndGet())
        workers.add(worker)
        worker
    }
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
    } catch (e: Throwable) {
        // The original failure is what the caller needs to see, so a cleanup problem rides along as suppressed.
        try {
            stopWorkers(pool, workers, cleanupMillis)
        } catch (cleanup: Throwable) {
            e.addSuppressed(cleanup)
        }
        throw e
    }
    stopWorkers(pool, workers, cleanupMillis)

    val privateKey = keyPair.private.encoded
    val undecryptable = results.count { (data, ciphertext) ->
        runCatching { privateDecrypt(ciphertext, privateKey) }.getOrNull()?.contentEquals(data) != true
    }
    return CryptoStressResult(threadCount * bursts, thrown.toList(), undecryptable, results.size + thrown.size)
}

/**
 * ThreadPoolExecutor.awaitTermination can return while a worker Thread is still alive (seen on JDK 17), so
 * termination of the executor and of each thread are separate facts and both are waited for here, under a
 * single deadline. Interrupts that arrive during cleanup are remembered and re-asserted at the end, not dropped.
 */
private fun stopWorkers(pool: ExecutorService, workers: Collection<Thread>, timeoutMillis: Long) {
    val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
    var interrupted = false
    try {
        pool.shutdownNow()
        var executorStopped = pool.isTerminated
        while (!executorStopped && deadline - System.nanoTime() > 0) {
            try {
                executorStopped = pool.awaitTermination(deadline - System.nanoTime(), TimeUnit.NANOSECONDS)
            } catch (e: InterruptedException) {
                interrupted = true
            }
        }
        val threads = workers.toList()
        if (joinAll(threads, deadline)) interrupted = true
        val alive = threads.count { it.isAlive }
        check(executorStopped && alive == 0) {
            "stress workers did not stop within ${timeoutMillis}ms of shutdown: executor terminated=$executorStopped, " +
                "$alive of ${threads.size} worker thread(s) still alive"
        }
    } finally {
        if (interrupted) Thread.currentThread().interrupt()
    }
}

/** Joins [threads] until [deadlineNanos] (a System.nanoTime value) and retries a join an interrupt cut short. Returns true if it was interrupted. */
internal fun joinAll(threads: Collection<Thread>, deadlineNanos: Long): Boolean {
    var interrupted = false
    for (thread in threads) {
        while (thread.isAlive && deadlineNanos - System.nanoTime() > 0) {
            try {
                TimeUnit.NANOSECONDS.timedJoin(thread, deadlineNanos - System.nanoTime())
            } catch (e: InterruptedException) {
                interrupted = true
            }
        }
    }
    return interrupted
}
