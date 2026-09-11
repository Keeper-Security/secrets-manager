import {localConfigStorage} from '../'

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
