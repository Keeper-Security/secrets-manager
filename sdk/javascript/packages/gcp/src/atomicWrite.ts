import * as fsSync from "fs";
import { randomBytes } from "crypto";
import { dirname } from "path";

const chmodSecure = (filePath: string) => fsSync.chmodSync(filePath, 0o600);

// Rename replaces finalPath's directory entry, but that entry isn't durable until the
// containing directory's own fd is fsynced - the file's data being fsynced (below) doesn't
// cover the rename itself surviving a crash.
//
// Deliberately best effort, and deliberately never throws. By the time this runs the file's data
// is already fsynced and the rename has already committed, so the write has succeeded and the
// caller must be told so. The only thing at stake here is the directory entry surviving a power
// loss, which is never worth reporting a successful write as a failed one: a caller that treats a
// rejected save as "not persisted" would retry or abandon a credential rotation that already
// landed. Both calls are inside the try because the open is what fails on the platforms that
// cannot give us a directory fd at all (Windows), and on a directory we may write but not read;
// an allow-list of error codes would also rethrow the unanticipated ones that network and
// container filesystems produce, such as ENOTSUP, EINVAL and EBADF.
const fsyncDirectory = (filePath: string): void => {
  let dirFd: number | undefined;
  try {
    dirFd = fsSync.openSync(dirname(filePath), "r");
    fsSync.fsyncSync(dirFd);
  } catch {
    // durability of the rename only, see above
  } finally {
    if (dirFd !== undefined) {
      try {
        fsSync.closeSync(dirFd);
      } catch {
        // the descriptor is unusable either way
      }
    }
  }
};

// mode: 0o600 on openSync only applies when the file is created; an existing file keeps its
// old mode through the write. Rename takes on the source file's mode, not the destination's,
// so the temp file must already be 0600 before the rename, not the final path after it.
// This also produces a new inode: a reader fd opened against the old file before this call
// stays on the old content instead of reading through to the newly-written secret, which an
// in-place write+chmod cannot do (see GCPKeyValueStorage.atomicWrite.test.ts's stale-fd test).
export function writeFileAtomicSync(finalPath: string, data: string | Buffer): void {
  const tmpPath = `${finalPath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  const buffer = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  // 'wx' adds O_EXCL: a name collision with another writer's in-flight temp file fails with
  // EEXIST instead of truncating it. The pid+random suffix already makes a collision unlikely;
  // this closes the class rather than relying on that alone.
  const fd = fsSync.openSync(tmpPath, "wx", 0o600);
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
  fsyncDirectory(finalPath);
}
