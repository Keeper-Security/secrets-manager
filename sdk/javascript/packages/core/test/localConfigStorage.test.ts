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

    test('an unreadable config file throws KeeperError instead of silently starting fresh', () => {
        // chmod 0o000 only blocks a non-root process; running this suite as root (common in
        // Docker-based Node images) would leave the file readable and this test would not
        // exercise the path it's meant to cover.
        if (typeof process.getuid === 'function' && process.getuid() === 0) {
            return
        }
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
})
