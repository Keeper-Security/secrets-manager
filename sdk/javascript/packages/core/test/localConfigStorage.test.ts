import {localConfigStorage, KeeperError, KeeperStorageError} from '../'

import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as childProcess from 'child_process'

let tmpDir: string

beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ksm-cache-test-'))
})

afterEach(() => {
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
        // writeConfigFile's one resolution call - the narrowest version of the residual
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
        const originalStatSync = fs.statSync
        const statSyncSpy = jest.spyOn(fs, 'statSync').mockImplementation((p: fs.PathLike, opts?: any) => {
            const result = originalStatSync(p as string, opts)
            fs.unlinkSync(configPath)
            fs.symlinkSync(decoyPath, configPath)
            statSyncSpy.mockRestore()
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
        // Missing the <hex> segment writeConfigFile always adds - close enough to be a
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
    // regex - they'd stay green even if writeConfigFile's real naming and that regex silently
    // drifted apart from each other, as long as each still matched its own fixture. This test
    // closes that gap: it kills a real child process actually running writeConfigFile (via the
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
})
