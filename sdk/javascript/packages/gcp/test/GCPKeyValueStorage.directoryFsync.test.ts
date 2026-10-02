// writeFileAtomicSync() fsyncs the containing directory last, so the rename survives a power
// loss. That step runs after the data is already fsynced and the rename has already committed, so
// it must never be able to fail the write: the bytes are on disk either way, and a caller told
// "the save failed" will retry or abandon a credential rotation that already landed.
//
// The failing call is the directory open, not the fsync. On Windows fs.openSync of a directory
// fails outright, and on a directory the process may write but not read (mode 0300) it fails with
// EACCES. Neither is reachable from a test that only stubs fsyncSync, so this file stubs openSync.
//
// jest.mock('fs') is used rather than jest.spyOn because fs.openSync is non-configurable in modern
// Node and jest.spyOn(fs, 'openSync') throws "Cannot redefine property". jest.mock intercepts
// module resolution instead of patching the live object, so atomicWrite.ts's
// `import * as fsSync from "fs"` resolves to the object below while every other fs call reaches
// the real implementation through requireActual. The hook is inert unless a test sets it, so the
// happy-path assertions run against stock behaviour.
type DirectoryOpenFailure = { code?: string; openFlags: string[] };
const hooks: DirectoryOpenFailure = { openFlags: [] };

jest.mock('fs', () => {
    const actual = jest.requireActual('fs');
    return {
        ...actual,
        openSync: (...args: unknown[]) => {
            const flags = String(args[1]);
            hooks.openFlags.push(flags);
            // 'r' is the directory open; the temp file is opened with 'wx'.
            if (flags === 'r' && hooks.code) {
                const error: NodeJS.ErrnoException = new Error(`${hooks.code}: simulated failure`);
                error.code = hooks.code;
                throw error;
            }
            return (actual.openSync as (...a: unknown[]) => number)(...args);
        },
    };
});

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { writeFileAtomicSync } from '../src/atomicWrite';

function fileMode(filePath: string): number {
    return fs.statSync(filePath).mode & 0o777;
}

describe('writeFileAtomicSync() when the containing directory cannot be fsynced', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-dir-fsync-'));
        configPath = path.join(tmpDir, 'config.json');
        delete hooks.code;
        hooks.openFlags = [];
    });

    afterEach(() => {
        delete hooks.code;
        hooks.openFlags = [];
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    // EACCES is the POSIX shape (a mode 0300 directory). EPERM is the code the previous
    // allow-list named, and it is included to show the tolerance was attached to the wrong call:
    // the open fails before fsyncSync is ever reached, so the old catch never saw it. ENOTSUP and
    // EINVAL stand for the codes a network or container filesystem can return that no allow-list
    // anticipated, and which the previous code rethrew.
    const failureCodes = ['EACCES', 'EPERM', 'EISDIR', 'ENOTSUP', 'EINVAL', 'EBADF'];

    it.each(failureCodes)(
        'still reports success, and still writes the file, when the directory open fails with %s',
        (code) => {
            fs.writeFileSync(configPath, 'OLD-CONFIG', { mode: 0o600 });
            hooks.code = code;

            expect(() => writeFileAtomicSync(configPath, 'NEW-CONFIG-BYTES')).not.toThrow();

            expect(fs.readFileSync(configPath, 'utf8')).toBe('NEW-CONFIG-BYTES');
            expect(fileMode(configPath)).toBe(0o600);
            // A tolerated failure must not leave the temp file behind holding a copy of the config.
            expect(fs.readdirSync(tmpDir)).toEqual(['config.json']);
        }
    );

    // Guards against over-correcting into silently dropping the fsync altogether: the durability
    // step still has to happen on every platform that allows it.
    it('still opens and fsyncs the directory when the platform allows it', () => {
        writeFileAtomicSync(configPath, 'NEW-CONFIG-BYTES');

        expect(hooks.openFlags).toEqual(['wx', 'r']);
        expect(fs.readFileSync(configPath, 'utf8')).toBe('NEW-CONFIG-BYTES');
    });

    // The end-to-end proof on a real filesystem, with no fs stubbing at all: a directory the
    // process may write and traverse but not read. Creating and renaming inside it are permitted,
    // so the write genuinely succeeds and only the durability step is blocked.
    const posixNonRoot =
        process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() !== 0;
    const describeOnPosix = posixNonRoot ? describe : describe.skip;

    describeOnPosix('on a real write-only directory', () => {
        it('resolves and persists the new content in a directory that cannot be opened for read', () => {
            fs.writeFileSync(configPath, 'OLD-CONFIG', { mode: 0o600 });
            fs.chmodSync(tmpDir, 0o300);

            try {
                expect(() => writeFileAtomicSync(configPath, 'ROTATED-CREDENTIAL')).not.toThrow();
                expect(fs.readFileSync(configPath, 'utf8')).toBe('ROTATED-CREDENTIAL');
                expect(fileMode(configPath)).toBe(0o600);
            } finally {
                // Restore before afterEach's recursive remove, which needs to read the directory.
                fs.chmodSync(tmpDir, 0o700);
            }
        });
    });
});
