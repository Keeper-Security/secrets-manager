import {
    createCachingFunction,
    inMemoryStorage,
    localConfigStorage,
    platform,
    KeeperError,
    KeeperStorageError,
    KeyValueStorage,
    TransmissionKey,
    EncryptedPayload,
} from '../'

import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as childProcess from 'child_process'

const enc = new TextEncoder()

const makeStorageWithAppKey = async (): Promise<KeyValueStorage> => {
    const storage = inMemoryStorage({})
    await storage.saveBytes('appKey', new Uint8Array(32).fill(7))
    return storage
}

const fakeTransmissionKey = (): TransmissionKey => ({
    publicKeyId: 7,
    key: platform.getRandomBytes(32),
    encryptedKey: new Uint8Array(),
})

const fakePayload: EncryptedPayload = { payload: new Uint8Array(), signature: new Uint8Array() }
const networkFailure = () => Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })

let tmpDir: string
let cachePath: string
const originalPost = platform.post

beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ksm-cache-test-'))
    cachePath = path.join(tmpDir, 'cache.dat')
})

afterEach(() => {
    platform.post = originalPost
    fs.rmSync(tmpDir, { recursive: true, force: true })
})

describe('localConfigStorage file permissions (KSM-1263)', () => {
    test('re-asserts 0600 on save even if the file started more permissive', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, '{}')
        fs.chmodSync(configPath, 0o644)

        const kvs = localConfigStorage(configPath)
        await kvs.saveString('foo', 'bar')

        expect(fs.statSync(configPath).mode & 0o777).toBe(0o600)
    })
})

describe('localConfigStorage readStorage error handling (KSM-1266)', () => {
    test('a missing config file is a legitimate fresh start', async () => {
        const configPath = path.join(tmpDir, 'does-not-exist.json')
        let kvs: ReturnType<typeof localConfigStorage>
        expect(() => { kvs = localConfigStorage(configPath) }).not.toThrow()
        await kvs!.saveString('foo', 'bar')
        expect(await kvs!.getString('foo')).toBe('bar')
    })

    // chmod 0o000 only blocks a non-root process, and only on POSIX - running as root (common
    // in Docker-based Node images) or on Windows (where chmod doesn't gate read access the same
    // way) would leave the file readable, so this test wouldn't exercise the path it's meant to
    // cover. Using test.skip instead of a bare early return makes the skip show up in Jest's own
    // output instead of silently reporting as a pass with no coverage.
    const canSimulateUnreadableFile =
        process.platform !== 'win32' && (typeof process.getuid !== 'function' || process.getuid() !== 0)

    const runOrSkip = canSimulateUnreadableFile ? test : test.skip
    runOrSkip('an unreadable config file throws KeeperStorageError with the original EACCES code', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, '{}')
        fs.chmodSync(configPath, 0o000)
        let caught: unknown
        try {
            localConfigStorage(configPath)
        } catch (e) {
            caught = e
        }
        expect(caught).toBeInstanceOf(KeeperError)
        expect(caught).toBeInstanceOf(KeeperStorageError)
        expect((caught as KeeperStorageError).code).toBe('EACCES')
    })

    test('malformed JSON throws KeeperError instead of silently starting fresh', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, 'not json{{{')
        expect(() => localConfigStorage(configPath)).toThrow(KeeperError)
    })

    test('an empty config file (process killed mid-save) is a legitimate fresh start', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, '')
        let kvs: ReturnType<typeof localConfigStorage>
        expect(() => { kvs = localConfigStorage(configPath) }).not.toThrow()
        await kvs!.saveString('foo', 'bar')
        expect(await kvs!.getString('foo')).toBe('bar')
    })

    test('JSON that parses but is not an object throws KeeperError', () => {
        const configPath = path.join(tmpDir, 'config.json')
        for (const invalid of ['null', '42', '[1,2,3]', '"a string"']) {
            fs.writeFileSync(configPath, invalid)
            expect(() => localConfigStorage(configPath)).toThrow(KeeperError)
        }
    })

    test('a BOM-prefixed config file is not treated as corrupt', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, '﻿' + JSON.stringify({ foo: 'bar' }))
        const kvs = localConfigStorage(configPath)
        expect(await kvs.getString('foo')).toBe('bar')
    })

    test('a save-time write failure throws KeeperError instead of a raw fs error', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const kvs = localConfigStorage(configPath)
        const openSyncSpy = jest.spyOn(fs, 'openSync').mockImplementation(() => {
            throw Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' })
        })
        try {
            await expect(kvs.saveString('foo', 'bar')).rejects.toThrow(KeeperError)
        } finally {
            openSyncSpy.mockRestore()
        }
    })

    test('a save-time write failure preserves the original fs error code on KeeperStorageError', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const kvs = localConfigStorage(configPath)
        const writeSyncSpy = jest.spyOn(fs, 'writeSync').mockImplementation(() => {
            throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })
        })
        let caught: unknown
        try {
            await kvs.saveString('foo', 'bar')
        } catch (e) {
            caught = e
        } finally {
            writeSyncSpy.mockRestore()
        }
        expect(caught).toBeInstanceOf(KeeperStorageError)
        expect((caught as KeeperStorageError).code).toBe('ENOSPC')
    })

    test('a save-time failure after the temp file is opened leaves the original config untouched', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, JSON.stringify({ original: 'data' }))
        fs.chmodSync(configPath, 0o600)

        const kvs = localConfigStorage(configPath)
        // Let the temp-file open succeed; fail specifically at the write step, so this exercises
        // the atomic-rename path rather than short-circuiting before it (unlike the test above,
        // which fails before any temp file exists).
        const writeSyncSpy = jest.spyOn(fs, 'writeSync').mockImplementation(() => {
            throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })
        })
        try {
            await expect(kvs.saveString('foo', 'bar')).rejects.toThrow(KeeperError)
        } finally {
            writeSyncSpy.mockRestore()
        }

        // This is the assertion that would have failed before the atomic-write fix: the
        // destination used to be truncated before the write, so a write failure left a 0-byte
        // file behind.
        expect(fs.readFileSync(configPath, 'utf8')).toBe(JSON.stringify({ original: 'data' }))
    })

    test('a write failure is not masked by a close failure on the same fd', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const kvs = localConfigStorage(configPath)
        const writeSyncSpy = jest.spyOn(fs, 'writeSync').mockImplementation(() => {
            throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })
        })
        const closeSyncSpy = jest.spyOn(fs, 'closeSync').mockImplementation(() => {
            throw new Error('EBADF: bad file descriptor')
        })
        let caught: unknown
        try {
            await kvs.saveString('foo', 'bar')
        } catch (e) {
            caught = e
        } finally {
            writeSyncSpy.mockRestore()
            closeSyncSpy.mockRestore()
        }
        // A plain finally { closeSync(fd) } would let this closeSync failure replace the
        // writeSync failure that caused it - the caller would see EBADF and never learn the
        // disk was actually full.
        expect(caught).toBeInstanceOf(KeeperStorageError)
        expect((caught as KeeperStorageError).code).toBe('ENOSPC')
    })

    test('fsyncSync runs before renameSync, not just writeSync', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const kvs = localConfigStorage(configPath)
        const calls: string[] = []
        const originalRenameSync = fs.renameSync
        const fsyncSpy = jest.spyOn(fs, 'fsyncSync').mockImplementation(() => {
            calls.push('fsync')
        })
        const renameSyncSpy = jest.spyOn(fs, 'renameSync').mockImplementation((...args: Parameters<typeof fs.renameSync>) => {
            calls.push('rename')
            return originalRenameSync(...args)
        })
        try {
            await kvs.saveString('foo', 'bar')
        } finally {
            fsyncSpy.mockRestore()
            renameSyncSpy.mockRestore()
        }
        expect(calls).toEqual(['fsync', 'rename'])
    })

    test('a symlinked config path is written through, not replaced', async () => {
        const realPath = path.join(tmpDir, 'real-config.json')
        const symlinkPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(realPath, JSON.stringify({ original: 'data' }))
        fs.symlinkSync(realPath, symlinkPath)

        const kvs = localConfigStorage(symlinkPath)
        await kvs.saveString('foo', 'bar')

        // A plain renameSync onto symlinkPath would replace the link itself with a regular
        // file - this is the exact regression the round-4 review found.
        expect(fs.lstatSync(symlinkPath).isSymbolicLink()).toBe(true)
        expect(fs.readlinkSync(symlinkPath)).toBe(realPath)
        expect(JSON.parse(fs.readFileSync(realPath, 'utf8'))).toEqual({ original: 'data', foo: 'bar' })
    })

    test('a symlink swapped right after resolution does not redirect the write', async () => {
        const realPathA = path.join(tmpDir, 'real-a.json')
        const realPathB = path.join(tmpDir, 'real-b.json')
        const symlinkPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(realPathA, JSON.stringify({ original: 'data' }))
        fs.writeFileSync(realPathB, JSON.stringify({ decoy: 'untouched' }))
        fs.symlinkSync(realPathA, symlinkPath)

        const kvs = localConfigStorage(symlinkPath)

        // Simulates an attacker swapping the symlink's target immediately after
        // writeFileAtomic's one resolution call - the narrowest version of the residual
        // window write-file-atomic itself also leaves open. Only the first realpathSync call
        // is intercepted (mockRestore right after), so this proves the resolved path is
        // cached and reused for the eventual rename, not looked up again right before it -
        // a second, later call would hit the real, now-swapped, realpathSync instead.
        const originalRealpathSync = fs.realpathSync
        const realpathSyncSpy = jest.spyOn(fs, 'realpathSync').mockImplementation((p: fs.PathLike) => {
            const resolved = originalRealpathSync(p)
            fs.unlinkSync(symlinkPath)
            fs.symlinkSync(realPathB, symlinkPath)
            realpathSyncSpy.mockRestore()
            return resolved
        })

        await kvs.saveString('foo', 'bar')

        expect(JSON.parse(fs.readFileSync(realPathA, 'utf8'))).toEqual({ original: 'data', foo: 'bar' })
        expect(JSON.parse(fs.readFileSync(realPathB, 'utf8'))).toEqual({ decoy: 'untouched' })
        expect(fs.readlinkSync(symlinkPath)).toBe(realPathB)
    })

    test('a hard-linked config path updates every link (no atomicity, matches pre-fix behavior)', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const linkedPath = path.join(tmpDir, 'config-link.json')
        fs.writeFileSync(configPath, JSON.stringify({ original: 'data' }))
        fs.linkSync(configPath, linkedPath)

        const kvs = localConfigStorage(configPath)
        await kvs.saveString('foo', 'bar')

        // A temp-file-then-rename would detach configPath into a new inode, leaving
        // linkedPath frozen at the old content - this is the other half of the round-4
        // regression. Writing in place instead preserves the shared inode.
        const expected = { original: 'data', foo: 'bar' }
        expect(JSON.parse(fs.readFileSync(configPath, 'utf8'))).toEqual(expected)
        expect(JSON.parse(fs.readFileSync(linkedPath, 'utf8'))).toEqual(expected)
        expect(fs.statSync(configPath).ino).toBe(fs.statSync(linkedPath).ino)
    })

    test('a hard-linked config path swapped into a symlink after the nlink check is not followed', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const linkedPath = path.join(tmpDir, 'config-link.json')
        const decoyPath = path.join(tmpDir, 'decoy.json')
        fs.writeFileSync(configPath, JSON.stringify({ original: 'data' }))
        fs.linkSync(configPath, linkedPath)
        fs.writeFileSync(decoyPath, JSON.stringify({ decoy: 'untouched' }))

        const kvs = localConfigStorage(configPath)

        // Simulates an attacker swapping configPath into a symlink right after the nlink > 1
        // check passes, before the open that writes in place - the write-in-place branch has
        // no rename to fall back on for symlink safety, so it needs its own O_NOFOLLOW.
        const originalLstatSync = fs.lstatSync
        const lstatSyncSpy = jest.spyOn(fs, 'lstatSync').mockImplementation((p: fs.PathLike, opts?: any) => {
            const result = originalLstatSync(p as string, opts)
            fs.unlinkSync(configPath)
            fs.symlinkSync(decoyPath, configPath)
            lstatSyncSpy.mockRestore()
            return result
        })

        await expect(kvs.saveString('foo', 'bar')).rejects.toThrow(KeeperError)

        expect(JSON.parse(fs.readFileSync(linkedPath, 'utf8'))).toEqual({ original: 'data' })
        expect(JSON.parse(fs.readFileSync(decoyPath, 'utf8'))).toEqual({ decoy: 'untouched' })
    })

    const backdate = (filePath: string) => {
        const old = new Date(Date.now() - 5 * 60_000)
        fs.utimesSync(filePath, old, old)
    }

    test('a stale orphaned temp file is removed on the next read', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, JSON.stringify({ original: 'data' }))
        const orphanPath = `${configPath}.99999.aabbccddeeff.tmp`
        fs.writeFileSync(orphanPath, JSON.stringify({ original: 'data', foo: 'stale-secret' }))
        backdate(orphanPath)

        localConfigStorage(configPath)

        expect(fs.existsSync(orphanPath)).toBe(false)
    })

    test('a recent temp file (a concurrent writer, not a crash) is left alone', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, JSON.stringify({ original: 'data' }))
        const inFlightPath = `${configPath}.12345.001122334455.tmp`
        fs.writeFileSync(inFlightPath, 'partial-write-in-progress')

        localConfigStorage(configPath)

        expect(fs.existsSync(inFlightPath)).toBe(true)
    })

    test('a file that merely looks tmp-like but does not match the exact naming shape is not swept', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, JSON.stringify({ original: 'data' }))
        // Missing the <hex> segment writeFileAtomic always adds - close enough to be a
        // plausible false match for a looser regex, not close enough to be one of ours.
        const lookalikePath = `${configPath}.12345.tmp`
        fs.writeFileSync(lookalikePath, 'not one of ours')
        backdate(lookalikePath)

        localConfigStorage(configPath)

        expect(fs.existsSync(lookalikePath)).toBe(true)
    })

    test('an orphaned temp file next to a symlinked config real target is still swept', () => {
        const realPath = path.join(tmpDir, 'real-config.json')
        const symlinkPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(realPath, JSON.stringify({ original: 'data' }))
        fs.symlinkSync(realPath, symlinkPath)
        const orphanPath = `${realPath}.99999.aabbccddeeff.tmp`
        fs.writeFileSync(orphanPath, 'stale')
        backdate(orphanPath)

        localConfigStorage(symlinkPath)

        expect(fs.existsSync(orphanPath)).toBe(false)
    })

    // The other orphan tests hand-write a fixture filename matching cleanupOrphanedTempFiles'
    // regex - they'd stay green even if writeFileAtomic's real naming and that regex silently
    // drifted apart from each other, as long as each still matched its own fixture. This test
    // closes that gap: it kills a real child process actually running writeFileAtomic (via the
    // built dist bundle, the same one the package ships), confirming the file it actually
    // leaves behind is one cleanupOrphanedTempFiles actually recognizes.
    test('a real SIGKILL between opening the temp file and the rename leaves an orphan the next read cleans up', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, JSON.stringify({ original: 'data' }))

        const distIndexPath = path.resolve(__dirname, '../dist/index.cjs.js')
        const childScriptPath = path.join(tmpDir, 'kill-mid-save.js')
        fs.writeFileSync(childScriptPath, `
            const fs = require('fs')
            const { localConfigStorage } = require(${JSON.stringify(distIndexPath)})
            fs.renameSync = () => {
                fs.writeSync(1, 'ABOUT_TO_RENAME\\n')
                while (true) {}
            }
            localConfigStorage(${JSON.stringify(configPath)}).saveString('foo', 'bar')
        `)

        const child = childProcess.spawn(process.execPath, [childScriptPath], { stdio: ['ignore', 'pipe', 'inherit'] })
        await new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('child never signaled readiness')), 5000)
            child.stdout!.on('data', (chunk: Buffer) => {
                if (chunk.toString().includes('ABOUT_TO_RENAME')) {
                    clearTimeout(timer)
                    child.kill('SIGKILL')
                    resolve()
                }
            })
        })
        await new Promise((resolve) => child.on('exit', resolve))

        const orphan = fs.readdirSync(tmpDir).find((f) => f.startsWith('config.json.') && f.endsWith('.tmp'))
        expect(orphan).toBeDefined()
        expect(fs.readFileSync(configPath, 'utf8')).toBe(JSON.stringify({ original: 'data' }))

        const orphanPath = path.join(tmpDir, orphan!)
        backdate(orphanPath)
        localConfigStorage(configPath)

        expect(fs.existsSync(orphanPath)).toBe(false)
    }, 10000)

    test('a failed save rolls back the in-memory value to what is actually on disk', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const kvs = localConfigStorage(configPath)
        await kvs.saveString('foo', 'first')
        expect(await kvs.getString('foo')).toBe('first')

        const writeSyncSpy = jest.spyOn(fs, 'writeSync').mockImplementation(() => {
            throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })
        })
        try {
            await expect(kvs.saveString('foo', 'second')).rejects.toThrow(KeeperError)
        } finally {
            writeSyncSpy.mockRestore()
        }

        // Without the rollback, this would return 'second': the in-memory mutation happens
        // before saveStorage runs, so a failed persist would otherwise leave the live instance
        // disagreeing with what's actually on disk.
        expect(await kvs.getString('foo')).toBe('first')
        expect(JSON.parse(fs.readFileSync(configPath, 'utf8'))).toEqual({ foo: 'first' })
    })

    test('a failed save that added a new key removes it on rollback, not just overwrites it', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const kvs = localConfigStorage(configPath)
        await kvs.saveString('foo', 'first')

        const writeSyncSpy = jest.spyOn(fs, 'writeSync').mockImplementation(() => {
            throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })
        })
        try {
            await expect(kvs.saveString('bar', 'new-key')).rejects.toThrow(KeeperError)
        } finally {
            writeSyncSpy.mockRestore()
        }

        // A rollback that does Object.assign(storageData, snapshot) without first clearing
        // storageData's existing keys would leave 'bar' behind: assign only overwrites keys
        // present in the snapshot, it doesn't remove ones that aren't.
        expect(await kvs.getString('bar')).toBeUndefined()
        expect(JSON.parse(fs.readFileSync(configPath, 'utf8'))).toEqual({ foo: 'first' })
    })

    test('a failed concurrent save does not roll back a different concurrent save that succeeded', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const kvs = localConfigStorage(configPath)

        let callCount = 0
        const writeSyncSpy = jest.spyOn(fs, 'writeSync').mockImplementation((...args: Parameters<typeof fs.writeSync>) => {
            callCount++
            if (callCount === 1) {
                throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })
            }
            writeSyncSpy.mockRestore()
            return fs.writeSync(...args)
        })

        // Without serializing mutateAndPersist, saveString('b', ...)'s snapshot would be taken
        // after saveString('a', ...)'s mutation already landed in memory. When the 'a' call
        // then fails and rolls back to its own pre-mutation snapshot, that rollback would wipe
        // out 'b' too, even though the 'b' call never failed.
        const results = await Promise.allSettled([
            kvs.saveString('a', '1'),
            kvs.saveString('b', '2')
        ])

        expect(results[0].status).toBe('rejected')
        expect(results[1].status).toBe('fulfilled')
        expect(await kvs.getString('a')).toBeUndefined()
        expect(await kvs.getString('b')).toBe('2')
        expect(JSON.parse(fs.readFileSync(configPath, 'utf8'))).toEqual({ b: '2' })
    })

    test('reads through a symlinked config path, matching the Kubernetes Secret/ConfigMap volume-mount layout', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        const target = path.join(tmpDir, 'target-config.json')
        fs.writeFileSync(target, JSON.stringify({foo: 'bar'}))
        fs.symlinkSync(target, configPath)
        const kvs = localConfigStorage(configPath)
        expect(await kvs.getString('foo')).toBe('bar')
    })
})

describe('createCachingFunction (KSM-1265)', () => {
    test('round-trip: caches a successful response, then serves it when the network fails', async () => {
        const storage = await makeStorageWithAppKey()
        const responseData = enc.encode('{"ok":true}')
        const tk = fakeTransmissionKey()
        const caching = createCachingFunction(storage, {cachePath})

        platform.post = async () => ({ statusCode: 200, data: responseData, headers: [] })
        const first = await caching('https://example.com', tk, fakePayload)
        expect(first.statusCode).toBe(200)
        expect(Buffer.from(first.data)).toEqual(Buffer.from(responseData))

        platform.post = async () => { throw networkFailure() }
        const tk2 = fakeTransmissionKey()
        const second = await caching('https://example.com', tk2, fakePayload)
        expect(second.statusCode).toBe(200)
        expect(Buffer.from(second.data)).toEqual(Buffer.from(responseData))
        expect(Buffer.from(tk2.key)).toEqual(Buffer.from(tk.key))
    })

    test('serving a stale-on-network-failure cache logs a warning, the only signal a caller gets that the data may not be fresh', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath})

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
        try {
            platform.post = async () => { throw networkFailure() }
            await caching('https://example.com', fakeTransmissionKey(), fakePayload)
            expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('Network request failed'))
        } finally {
            consoleErrorSpy.mockRestore()
        }
    })

    test('rejects a tampered cache file instead of returning a synthetic 200', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath})

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        const raw = fs.readFileSync(cachePath)
        raw[raw.length - 1] ^= 0xff
        fs.writeFileSync(cachePath, raw)

        platform.post = async () => { throw networkFailure() }
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toBeInstanceOf(KeeperError)
    })

    test('rejects a cache file older than maxCacheAgeMs', async () => {
        jest.useFakeTimers()
        try {
            const storage = await makeStorageWithAppKey()
            const caching = createCachingFunction(storage, {cachePath, maxCacheAgeMs: 1000})

            platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
            await caching('https://example.com', fakeTransmissionKey(), fakePayload)

            jest.advanceTimersByTime(5000)

            platform.post = async () => { throw networkFailure() }
            await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
                .rejects.toBeInstanceOf(KeeperError)
        } finally {
            jest.useRealTimers()
        }
    })

    test('a forged freshness timestamp is rejected (the timestamp is now inside the AEAD boundary)', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath})

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        const raw = fs.readFileSync(cachePath)
        // Byte 1 falls inside the GCM ciphertext now (the format-version byte at 0 is the only
        // cleartext byte left). Flipping it used to land on the cleartext timestamp header and
        // silently pin a stale cache as fresh; now it corrupts the ciphertext and fails the tag check.
        raw[1] ^= 0xff
        fs.writeFileSync(cachePath, raw)

        platform.post = async () => { throw networkFailure() }
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toBeInstanceOf(KeeperError)
    })

    test('rejects an old-format cache file instead of misparsing it', async () => {
        const storage = await makeStorageWithAppKey()
        fs.mkdirSync(path.dirname(cachePath), { recursive: true })
        fs.writeFileSync(cachePath, Buffer.concat([Buffer.alloc(32, 1), Buffer.from('legacy-plaintext-response')]))

        platform.post = async () => { throw networkFailure() }
        const caching = createCachingFunction(storage, {cachePath})
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toBeInstanceOf(KeeperError)
    })

    test('a write failure after a successful response is swallowed, so the caller still gets the successful response', async () => {
        const storage = await makeStorageWithAppKey()
        const blockerFile = path.join(tmpDir, 'blocker')
        fs.writeFileSync(blockerFile, '')
        const badCachePath = path.join(blockerFile, 'cache.dat')
        const caching = createCachingFunction(storage, {cachePath: badCachePath})

        const responseData = enc.encode('{"ok":true}')
        platform.post = async () => ({ statusCode: 200, data: responseData, headers: [] })
        const result = await caching('https://example.com', fakeTransmissionKey(), fakePayload)
        expect(result.statusCode).toBe(200)
        expect(Buffer.from(result.data)).toEqual(Buffer.from(responseData))
    })

    test('no appKey in storage: a successful response is not cached', async () => {
        const storage = inMemoryStorage({})
        const caching = createCachingFunction(storage, {cachePath})

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        expect(fs.existsSync(cachePath)).toBe(false)
    })

    test('no appKey in storage: the fallback path throws instead of serving a nonexistent cache', async () => {
        const storage = inMemoryStorage({})
        const caching = createCachingFunction(storage, {cachePath})

        platform.post = async () => { throw networkFailure() }
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toBeInstanceOf(KeeperError)
    })

    test('appKey present but not raw bytes: skipped cleanly, not logged as a confusing internal error', async () => {
        // inMemoryStorage round-trips every saveBytes value through base64 encode/decode, so it
        // always hands back a genuine Uint8Array on read regardless of what was stored - it
        // can't simulate this. A custom KeyValueStorage could plausibly return a truthy
        // non-Uint8Array directly (this SDK's own bundled storages never do).
        //
        // Either way the cache file ends up unwritten - deriveCacheKey's own internal
        // isRawKeyBytes check throws even without this guard, and the outer try/catch already
        // swallows that. What the guard on this call site actually controls is whether that
        // throw ever happens: with it, the write is skipped before deriveCacheKey runs, no log
        // at all; without it, deriveCacheKey's TypeError reaches the outer catch and gets logged
        // as "Failed to update cached response: ...", indistinguishable from a real I/O failure.
        const storage: KeyValueStorage = {
            getString: async () => undefined,
            saveString: async () => {},
            getBytes: async () => 'not-actually-bytes' as unknown as Uint8Array,
            saveBytes: async () => {},
            delete: async () => {}
        }
        const caching = createCachingFunction(storage, {cachePath})

        const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
        try {
            platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
            await caching('https://example.com', fakeTransmissionKey(), fakePayload)
            expect(fs.existsSync(cachePath)).toBe(false)
            expect(consoleErrorSpy).not.toHaveBeenCalled()
        } finally {
            consoleErrorSpy.mockRestore()
        }
    })

    test('storage.getBytes throwing in the fallback path throws the documented "does not exist" error, not the raw storage error', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath})
        const originalGetBytes = storage.getBytes
        storage.getBytes = async () => { throw new Error('storage backend unavailable') }
        try {
            platform.post = async () => { throw networkFailure() }
            await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
                .rejects.toThrow('Cached value does not exist')
        } finally {
            storage.getBytes = originalGetBytes
        }
    })

    test('a cache entry written during backward clock skew is still treated as stale, not fresh forever', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath, maxCacheAgeMs: 1000})

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        const realNow = Date.now
        try {
            // Simulates the clock moving backward relative to when the entry was written (e.g.
            // a VM/container before its first NTP sync) - a plain `Date.now() - written` would
            // go negative and never exceed maxCacheAgeMs, letting this entry read as fresh
            // indefinitely regardless of the configured age limit.
            Date.now = () => realNow() - 10 * 60 * 1000
            platform.post = async () => { throw networkFailure() }
            await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
                .rejects.toBeInstanceOf(KeeperError)
        } finally {
            Date.now = realNow
        }
    })

    test('a cache file over the size cap is rejected before any decode attempt', async () => {
        fs.mkdirSync(path.dirname(cachePath), { recursive: true })
        fs.writeFileSync(cachePath, Buffer.alloc(11 * 1024 * 1024))
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath})

        platform.post = async () => { throw networkFailure() }
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toThrow('exceeds the maximum expected size')
    })

    test('a stale orphaned temp file next to the cache path is removed on the next read or write', async () => {
        fs.mkdirSync(path.dirname(cachePath), { recursive: true })
        const orphanPath = `${cachePath}.99999.aabbccddeeff.tmp`
        fs.writeFileSync(orphanPath, 'stale-leftover-cache-write')
        const old = new Date(Date.now() - 5 * 60_000)
        fs.utimesSync(orphanPath, old, old)

        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath})
        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        expect(fs.existsSync(orphanPath)).toBe(false)
    })

    test('hardens a cache directory this call creates, but leaves a pre-existing directory\'s permissions alone', async () => {
        const storage = await makeStorageWithAppKey()

        // A directory this call creates fresh - the SDK owns it, so it gets locked to 0700.
        const freshDir = path.join(tmpDir, 'fresh-dir')
        const freshPath = path.join(freshDir, 'cache.dat')
        const cachingFresh = createCachingFunction(storage, {cachePath: freshPath})
        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await cachingFresh('https://example.com', fakeTransmissionKey(), fakePayload)
        expect(fs.statSync(freshDir).mode & 0o777).toBe(0o700)

        // A directory that already existed before this call - a caller-supplied cachePath can
        // point at a directory the caller manages for other things (e.g. a file directly inside
        // $HOME); the SDK must not narrow permissions on a directory it doesn't own. Matches
        // established practice for this exact caller-owned-vs-SDK-owned distinction (npm's own
        // cache-directory guidance; the same "unconditional per-run chmod on an existing
        // directory" pattern is a filed, disputed bug in another CLI's own config-dir hardening).
        const looseDir = path.join(tmpDir, 'loose-dir')
        fs.mkdirSync(looseDir, { mode: 0o755 })
        const loosePath = path.join(looseDir, 'cache.dat')
        const cachingLoose = createCachingFunction(storage, {cachePath: loosePath})
        await cachingLoose('https://example.com', fakeTransmissionKey(), fakePayload)
        expect(fs.statSync(looseDir).mode & 0o777).toBe(0o755)
    })

    test('a write replaces the cache file via rename (new inode), not an in-place truncate', async () => {
        const storage = await makeStorageWithAppKey()
        fs.mkdirSync(path.dirname(cachePath), { recursive: true })
        fs.writeFileSync(cachePath, 'stale-loose-file')
        fs.chmodSync(cachePath, 0o644)
        const originalInode = fs.statSync(cachePath).ino
        const caching = createCachingFunction(storage, {cachePath})

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        // An in-place truncate-then-chmod would end up at 0600 too - the inode staying the same
        // is what actually distinguishes a real rename from that, so mode alone isn't enough.
        const stat = fs.statSync(cachePath)
        expect(stat.ino).not.toBe(originalInode)
        expect(stat.mode & 0o777).toBe(0o600)
    })

    test('a symlink at the cache path is replaced by the write, never followed; the target stays untouched and the fallback reads the healed cache', async () => {
        const storage = await makeStorageWithAppKey()
        const target = path.join(tmpDir, 'target.dat')
        fs.writeFileSync(target, 'do-not-touch')
        fs.symlinkSync(target, cachePath)
        const caching = createCachingFunction(storage, {cachePath})

        const responseData = enc.encode('{"ok":true}')
        platform.post = async () => ({ statusCode: 200, data: responseData, headers: [] })
        const tk = fakeTransmissionKey()
        await caching('https://example.com', tk, fakePayload)
        // renameSync replaces the directory entry rather than following it, so the symlink's
        // target is never written through - the arbitrary-file-overwrite this test guards
        // against stays closed - but the symlink itself is gone, replaced by a real cache file.
        expect(fs.readFileSync(target, 'utf8')).toBe('do-not-touch')
        expect(fs.lstatSync(cachePath).isSymbolicLink()).toBe(false)

        platform.post = async () => { throw networkFailure() }
        const tk2 = fakeTransmissionKey()
        const result = await caching('https://example.com', tk2, fakePayload)
        expect(result.statusCode).toBe(200)
        expect(Buffer.from(result.data)).toEqual(Buffer.from(responseData))
        expect(fs.readFileSync(target, 'utf8')).toBe('do-not-touch')
    })

    test('a relative cachePath with no directory component does not touch the current working directory', async () => {
        const storage = await makeStorageWithAppKey()
        const originalCwd = process.cwd()
        process.chdir(tmpDir)
        fs.chmodSync(tmpDir, 0o755)
        try {
            const caching = createCachingFunction(storage, {cachePath: 'cache.dat'})
            platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
            await caching('https://example.com', fakeTransmissionKey(), fakePayload)
            expect(fs.statSync(tmpDir).mode & 0o777).toBe(0o755)
        } finally {
            process.chdir(originalCwd)
        }
    })

    test('refuses to write when the cache directory itself is a symlink', async () => {
        const storage = await makeStorageWithAppKey()
        const realDir = path.join(tmpDir, 'real-dir')
        fs.mkdirSync(realDir)
        const symlinkedDir = path.join(tmpDir, 'symlinked-dir')
        fs.symlinkSync(realDir, symlinkedDir)
        const pathThroughSymlink = path.join(symlinkedDir, 'cache.dat')
        const caching = createCachingFunction(storage, {cachePath: pathThroughSymlink})

        const responseData = enc.encode('{"ok":true}')
        platform.post = async () => ({ statusCode: 200, data: responseData, headers: [] })
        const result = await caching('https://example.com', fakeTransmissionKey(), fakePayload)
        // The write is swallowed, same convention as any other write failure, but nothing lands
        // under the real directory the symlink points to.
        expect(result.statusCode).toBe(200)
        expect(Buffer.from(result.data)).toEqual(Buffer.from(responseData))
        expect(fs.readdirSync(realDir)).toEqual([])
    })

    test('storage.getBytes throwing after a successful response does not propagate; the fresh response still wins', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath})
        const originalGetBytes = storage.getBytes
        storage.getBytes = async () => { throw new Error('storage backend unavailable') }
        try {
            const responseData = enc.encode('{"ok":true}')
            platform.post = async () => ({ statusCode: 200, data: responseData, headers: [] })
            const result = await caching('https://example.com', fakeTransmissionKey(), fakePayload)
            expect(result.statusCode).toBe(200)
            expect(Buffer.from(result.data)).toEqual(Buffer.from(responseData))
        } finally {
            storage.getBytes = originalGetBytes
        }
    })

    test('a successful write leaves no leftover temp file behind', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath})
        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)
        expect(fs.readdirSync(tmpDir)).toEqual(['cache.dat'])
    })

    test('a write that fails before the rename leaves a pre-existing valid cache file intact', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, {cachePath})

        const responseData = enc.encode('{"first":true}')
        platform.post = async () => ({ statusCode: 200, data: responseData, headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)
        const before = fs.readFileSync(cachePath)

        // Forces the temp-file create to fail (simulating disk-full, a permission race, etc.)
        // deterministically, rather than relying on OS-level permission bits, which some
        // filesystems/ACL setups don't enforce the same way for every test runner.
        const originalOpenSync = fs.openSync
        const openSyncSpy = jest.spyOn(fs, 'openSync').mockImplementation((p: any, flags: any, mode?: any) => {
            if (typeof p === 'string' && p.endsWith('.tmp')) {
                throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })
            }
            return originalOpenSync(p, flags, mode)
        })
        try {
            platform.post = async () => ({ statusCode: 200, data: enc.encode('{"second":true}'), headers: [] })
            await caching('https://example.com', fakeTransmissionKey(), fakePayload)
        } finally {
            openSyncSpy.mockRestore()
        }

        expect(fs.readFileSync(cachePath)).toEqual(before)
    })

    test('uses ~/.keeper/ksm-cache.dat and creates + hardens the directory on first write', async () => {
        const storage = await makeStorageWithAppKey()
        const originalHomedir = os.homedir
        ;(os as any).homedir = () => tmpDir
        try {
            const caching = createCachingFunction(storage)
            platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
            await caching('https://example.com', fakeTransmissionKey(), fakePayload)

            const expectedPath = path.join(tmpDir, '.keeper', 'ksm-cache.dat')
            expect(fs.existsSync(expectedPath)).toBe(true)
            expect(fs.statSync(path.dirname(expectedPath)).mode & 0o777).toBe(0o700)
        } finally {
            (os as any).homedir = originalHomedir
        }
    })
})
