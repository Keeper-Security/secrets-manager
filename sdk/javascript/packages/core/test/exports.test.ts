import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as childProcess from 'child_process'

// Jest's own module resolution never goes through package.json's `exports` conditions the way a
// real consumer's `import`/`require` does - every other test in this suite imports via `from
// '../'`, a relative path that bypasses conditional exports entirely. That gap is exactly how a
// broken `exports` block (condition order matters, and Node has no built-in `browser` condition,
// so an unguarded native-ESM import here falls through to the browser bundle) shipped with a
// fully green suite and a clean `tsc --noEmit`. This spawns a real child Node process, in its own
// package with its own `type: module`, to exercise the actual resolution algorithm.
test('an ESM Node consumer resolves the Node build, not the browser bundle', () => {
    const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ksm-exports-test-'))
    try {
        fs.writeFileSync(path.join(scratchDir, 'package.json'), JSON.stringify({ name: 'exports-test', type: 'module' }))
        const scopeDir = path.join(scratchDir, 'node_modules', '@keeper-security')
        fs.mkdirSync(scopeDir, { recursive: true })
        fs.symlinkSync(path.resolve(__dirname, '..'), path.join(scopeDir, 'secrets-manager-core'), 'dir')

        const configPath = path.join(scratchDir, 'config.json')
        const probeScript = `
            import { localConfigStorage } from '@keeper-security/secrets-manager-core'
            const kvs = localConfigStorage(${JSON.stringify(configPath)})
            await kvs.saveString('foo', 'bar')
            console.log('OK')
        `
        const probePath = path.join(scratchDir, 'probe.mjs')
        fs.writeFileSync(probePath, probeScript)

        const result = childProcess.spawnSync(process.execPath, [probePath], { encoding: 'utf8' })

        // The browser bundle's localConfigStorage resolves in Node too (it's the same exported
        // name), but it's backed by IndexedDB, which doesn't exist outside a browser - so it
        // fails at the first storage call, not at import time. That's the actual failure mode a
        // wrong `exports` resolution produces, and what this asserts against.
        expect(result.stderr).not.toContain('indexedDB is not defined')
        expect(result.stdout).toContain('OK')
        expect(result.status).toBe(0)
    } finally {
        fs.rmSync(scratchDir, { recursive: true, force: true })
    }
})
