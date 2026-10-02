// KSM-1458: the config file on disk must always be either the complete old content or the
// complete new content, never a partial write left by a crash or an interrupted process.
//
// This needs its own file rather than living in GCPKeyValueStorage.atomicWrite.test.ts, which
// deliberately does not mock `fs` at all. jest.mock('fs', ...) is hoisted to the top of
// whichever file it's declared in and applies to every test in that file, not just one - adding
// it there would make every other real-fs assertion in that file observe the same intercepted
// fs.writeSync this file needs, corrupting tests that have nothing to do with a short write.
//
// fs.writeSync is non-configurable in modern Node, so jest.spyOn(fs, 'writeSync') cannot
// redefine it on the live module object (this throws "Cannot redefine property"). jest.mock
// intercepts module *resolution* instead of the live object, so it works regardless:
// atomicWrite.ts's `import * as fsSync from "fs"` resolves to this mocked object, while every
// other fs.* call (mkdtempSync, statSync, readFileSync, readdirSync, rmSync, ...) still reaches
// the real implementation via jest.requireActual.
jest.mock('fs', () => {
    const actual = jest.requireActual('fs');
    return {
        ...actual,
        writeSync: (...args: unknown[]) => {
            // Perform the real write, then report back fewer bytes than were actually
            // written. This triggers writeFileAtomicSync's own short-write detection
            // deterministically, without needing to time a real SIGKILL against a live
            // syscall or corrupt a real file descriptor mid-write.
            const actualBytesWritten = (actual.writeSync as (...a: unknown[]) => number)(...args);
            return Math.floor(actualBytesWritten / 2);
        },
    };
});

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { writeFileAtomicSync } from '../src/atomicWrite';

describe('writeFileAtomicSync() when the write is interrupted (KSM-1458)', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ksm-1458-crash-write-'));
        configPath = path.join(tmpDir, 'config.json');
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('leaves the original file byte-for-byte unchanged, at the same inode, with no leftover temp file', () => {
        const originalContent = 'OLD-COMPLETE-CONFIG-CONTENT-MUST-SURVIVE';
        fs.writeFileSync(configPath, originalContent, { mode: 0o600 });
        const originalInode = fs.statSync(configPath).ino;

        expect(() => {
            writeFileAtomicSync(configPath, 'NEW-CONTENT-THAT-SHOULD-NEVER-LAND-PARTIALLY');
        }).toThrow(/Short write/);

        // The real config path was never opened for writing at all - only the temp file was -
        // so an in-place truncate is structurally impossible here, not just avoided by luck.
        expect(fs.readFileSync(configPath, 'utf8')).toBe(originalContent);
        expect(fs.statSync(configPath).ino).toBe(originalInode);

        // The failed temp file must be cleaned up, not left behind holding a partial write.
        const remainingFiles = fs.readdirSync(tmpDir);
        expect(remainingFiles).toEqual(['config.json']);
    });
});
