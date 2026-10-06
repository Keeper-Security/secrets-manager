// Windows has no POSIX file modes: libuv reports 0666 for any writable file, and chmod only
// toggles the read-only attribute. A test that asserts a mode, or that relies on POSIX rename or
// errno behavior, omits that part or skips there. Linux CI still runs every test that Windows
// skips. The one Windows-only test is skipped on Linux.
import * as fs from 'fs';

export const isWindows = process.platform === 'win32';

export const itUnlessWindows = isWindows ? it.skip : it;

export const itOnWindows = isWindows ? it : it.skip;

export function expectMode(filePath: string, expected: number): void {
    if (isWindows) {
        return;
    }
    expect(fs.statSync(filePath).mode & 0o777).toBe(expected);
}
