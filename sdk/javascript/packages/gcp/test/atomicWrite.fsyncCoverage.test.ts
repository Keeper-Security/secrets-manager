// writeFileAtomicSync()'s three data-durability primitives (temp file opened at mode 0600,
// the file's data fsynced before rename, the containing directory fsynced after rename) have
// no assertion that fails if any one of them is silently dropped. The redundant
// chmodSecure(tmpPath) call masks a weakened openSync mode -- the final file still lands at
// 0600 even if the temp file was opened at 0644. And nothing observes whether fsyncSync was
// actually invoked on either fd, only whether the directory was opened at all (which
// GCPKeyValueStorage.directoryFsync.test.ts already covers, at line 90).
//
// jest.mock('fs') is used because fs.openSync/fsyncSync are non-configurable in modern Node,
// so jest.spyOn(fs, 'openSync') throws "Cannot redefine property". The wrapper records a
// chronological event log (open/fsync/close), then delegates to the real implementation, so
// this file exercises the real filesystem end to end.
//
// fd numbers are reused by the OS once closed: the temp file's fd is freed by closeSync
// before the directory is opened, so the directory can (and in practice does) get the exact
// same fd number back. A bare "was fsyncSync ever called with fd N" check would pass on a
// mutant that drops the temp file's own fsync, because the later directory fsync reuses N.
// Each check below is scoped to the open call's own lifetime window (its index in the log up
// to its matching close, or the end of the log if the fd is never explicitly closed) rather
// than to the bare fd number.
type Event =
    | { kind: 'open'; fd: number; path: string; flags: string; mode?: number }
    | { kind: 'fsync'; fd: number }
    | { kind: 'close'; fd: number };
let log: Event[] = [];

jest.mock('fs', () => {
    const actual = jest.requireActual('fs');
    return {
        ...actual,
        openSync: (...args: unknown[]) => {
            const fd = (actual.openSync as (...a: unknown[]) => number)(...args);
            log.push({
                kind: 'open',
                fd,
                path: String(args[0]),
                flags: String(args[1]),
                mode: args[2] as number | undefined,
            });
            return fd;
        },
        fsyncSync: (fd: number) => {
            log.push({ kind: 'fsync', fd });
            return (actual.fsyncSync as (fd: number) => void)(fd);
        },
        closeSync: (fd: number) => {
            log.push({ kind: 'close', fd });
            return (actual.closeSync as (fd: number) => void)(fd);
        },
    };
});

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { writeFileAtomicSync } from '../src/atomicWrite';

function findOpen(flags: string): { index: number; event: Event & { kind: 'open' } } {
    const index = log.findIndex((e) => e.kind === 'open' && e.flags === flags);
    expect(index).toBeGreaterThanOrEqual(0);
    return { index, event: log[index] as Event & { kind: 'open' } };
}

// The end of this fd's lifetime window: its own explicit close, or the end of the log if it's
// never closed (fsyncDirectory's fd is closed in a finally, but scoping defensively either way
// means a future change that stops closing it doesn't make this check pass for the wrong reason).
function lifetimeEnd(openIndex: number, fd: number): number {
    const closeIndex = log.findIndex((e, i) => i > openIndex && e.kind === 'close' && e.fd === fd);
    return closeIndex === -1 ? log.length : closeIndex;
}

function fsyncedWithinLifetime(openIndex: number, fd: number): boolean {
    const end = lifetimeEnd(openIndex, fd);
    return log.some((e, i) => i > openIndex && i < end && e.kind === 'fsync' && e.fd === fd);
}

describe('writeFileAtomicSync() durability primitives', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-fsync-coverage-'));
        configPath = path.join(tmpDir, 'config.json');
        log = [];
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('opens the temp file at mode 0600 itself, not only via the later chmod', () => {
        writeFileAtomicSync(configPath, 'SECRET');

        const { event: tempOpen } = findOpen('wx');
        expect(tempOpen.mode).toBe(0o600);
    });

    it("fsyncs the temp file's data, within its own open/close lifetime, before it is renamed", () => {
        writeFileAtomicSync(configPath, 'SECRET');

        const { index, event: tempOpen } = findOpen('wx');
        expect(fsyncedWithinLifetime(index, tempOpen.fd)).toBe(true);
    });

    it('fsyncs the containing directory, within its own open lifetime, not only opens it', () => {
        writeFileAtomicSync(configPath, 'SECRET');

        const { index, event: dirOpen } = findOpen('r');
        expect(fsyncedWithinLifetime(index, dirOpen.fd)).toBe(true);
    });
});
