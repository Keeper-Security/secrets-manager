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
    test('a missing config file is a legitimate fresh start', () => {
        const configPath = path.join(tmpDir, 'does-not-exist.json')
        expect(() => localConfigStorage(configPath)).not.toThrow()
    })

    test('an unreadable config file throws KeeperError instead of silently starting fresh', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, '{}')
        fs.chmodSync(configPath, 0o000)
        try {
            expect(() => localConfigStorage(configPath)).toThrow(KeeperError)
        } finally {
            fs.chmodSync(configPath, 0o600)
        }
    })

    test('malformed JSON throws KeeperError instead of silently starting fresh', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, 'not json{{{')
        expect(() => localConfigStorage(configPath)).toThrow(KeeperError)
    })
})
