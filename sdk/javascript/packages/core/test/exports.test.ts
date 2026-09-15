import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as childProcess from 'child_process'

// A minimal, faithful implementation of Node's own package-exports condition matching
// (https://nodejs.org/api/packages.html#conditional-exports): walk an exports sub-object's own
// keys in the order they're written, take the first key that is 'default' or appears in the
// caller's condition set, recursing into nested objects. This is the only way to test a
// condition set that omits 'node' - a real Node.js process always adds that condition itself and
// cannot be made to drop it, so childProcess.spawnSync (used above) can prove the fix works for
// Node but not that the fix's target scenario, a bundler with no 'node' condition, is covered.
const resolveCondition = (node: unknown, conditions: string[]): string | undefined => {
    if (typeof node === 'string') return node
    if (Array.isArray(node)) {
        for (const item of node) {
            const resolved = resolveCondition(item, conditions)
            if (resolved !== undefined) return resolved
        }
        return undefined
    }
    if (typeof node === 'object' && node !== null) {
        for (const key of Object.keys(node)) {
            if (key === 'default' || conditions.includes(key)) {
                const resolved = resolveCondition((node as Record<string, unknown>)[key], conditions)
                if (resolved !== undefined) return resolved
            }
        }
    }
    return undefined
}

describe('package.json exports condition resolution', () => {
    const exportsNode = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).exports['.']

    // A bundler with no 'node' and no 'browser' in its condition set (for example
    // @rollup/plugin-node-resolve at its documented defaults, ['default', 'module', 'import'])
    // is not declaring a target platform at all, just an ESM preference. Without this fix, it
    // fell through to the 'import' key, which pointed at the browser bundle - the same
    // ReferenceError: indexedDB is not defined failure the Node-specific test above guards
    // against, just for a resolver the previous fix's real-Node-process test cannot reach.
    test('an import-only bundler condition set (no node, no browser) resolves the Node build', () => {
        expect(resolveCondition(exportsNode, ['import', 'default'])).toBe('./dist/index.cjs.js')
        expect(resolveCondition(exportsNode, ['module', 'import', 'default'])).toBe('./dist/index.cjs.js')
    })

    test('a real Node ESM or CJS consumer still resolves the Node build', () => {
        expect(resolveCondition(exportsNode, ['node', 'import', 'default'])).toBe('./dist/index.cjs.js')
        expect(resolveCondition(exportsNode, ['node', 'require', 'default'])).toBe('./dist/index.cjs.js')
    })

    test('a browser-targeting bundler still resolves the browser build', () => {
        expect(resolveCondition(exportsNode, ['browser', 'import', 'default'])).toBe('./dist/index.es.js')
        expect(resolveCondition(exportsNode, ['browser', 'require', 'default'])).toBe('./dist/index.es.js')
    })
})

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
