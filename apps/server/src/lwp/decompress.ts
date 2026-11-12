/** LWP 响应体解压：钉钉对较大的 body 使用 gzip */
import { gunzipSync } from 'node:zlib';

export function maybeGunzip(buf: Buffer): Buffer {
  if (buf.length > 3 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      return gunzipSync(buf);
    } catch {
      return buf;
    }
  }
  return buf;
}
