import {localConfigStorage, KeeperError} from '../'

import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'

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
    runOrSkip('an unreadable config file throws KeeperError instead of silently starting fresh', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, '{}')
        fs.chmodSync(configPath, 0o000)
        expect(() => localConfigStorage(configPath)).toThrow(KeeperError)
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
})
