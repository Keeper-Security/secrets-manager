import * as fsSync from "fs";
import { randomBytes } from "crypto";

const chmodSecure = (filePath: string) => fsSync.chmodSync(filePath, 0o600);

// mode: 0o600 on openSync only applies when the file is created; an existing file keeps its
// old mode through the write. Rename takes on the source file's mode, not the destination's,
// so the temp file must already be 0600 before the rename, not the final path after it.
// This also produces a new inode: a reader fd opened against the old file before this call
// stays on the old content instead of reading through to the newly-written secret, which an
// in-place write+chmod cannot do (see GCPKeyValueStorage.atomicWrite.test.ts's stale-fd test).
export function writeFileAtomicSync(finalPath: string, data: string | Buffer): void {
  const tmpPath = `${finalPath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  const buffer = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const fd = fsSync.openSync(tmpPath, "w", 0o600);
  try {
    const bytesWritten = fsSync.writeSync(fd, buffer);
    if (bytesWritten !== buffer.byteLength) {
      throw new Error(
        `Short write: wrote ${bytesWritten} of ${buffer.byteLength} bytes to ${tmpPath}`
      );
    }
    fsSync.fsyncSync(fd);
  } catch (writeError) {
    try {
      fsSync.closeSync(fd);
    } catch {
      // secondary to the write error above
    }
    try {
      fsSync.unlinkSync(tmpPath);
    } catch {
      // best effort cleanup
    }
    throw writeError;
  }
  fsSync.closeSync(fd);
  chmodSecure(tmpPath);
  try {
    fsSync.renameSync(tmpPath, finalPath);
  } catch (renameError) {
    try {
      fsSync.unlinkSync(tmpPath);
    } catch {
      // best effort cleanup
    }
    throw renameError;
  }
}
