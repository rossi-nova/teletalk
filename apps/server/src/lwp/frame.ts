/**
 * LWP 帧编解码
 *
 * 请求  LWP <uri>\n<k:v>\n...\n\n<body>
 * 响应  <code>\n<k:v>\n...\n\n<body>
 */
export interface LwpFrame {
  kind: 'req' | 'res';
  uri?: string;
  code?: number;
  headers: Record<string, string>;
  body: Buffer;
}

/** 从缓冲区解出所有完整帧；返回帧与剩余未消费字节 */
export function parseFrames(buf: Buffer): { frames: LwpFrame[]; rest: Buffer } {
  const frames: LwpFrame[] = [];
  let off = 0;

  while (off < buf.length) {
    const headerEnd = buf.indexOf('\n\n', off);
    if (headerEnd === -1) break;

    const head = buf.slice(off, headerEnd).toString('latin1');
    const lines = head.split('\n');
    const first = lines[0] ?? '';

    const isReq = first.startsWith('LWP ');
    const isRes = /^\d{3}$/.test(first);
    if (!isReq && !isRes) {
      // 非法起点，丢弃一个字节继续找
      off += 1;
      continue;
    }

    const headers: Record<string, string> = {};
    for (const line of lines.slice(1)) {
      const i = line.indexOf(':');
      if (i > 0) headers[line.slice(0, i)] = line.slice(i + 1);
    }

    const bodyLen = Number(headers.len ?? 0);
    const bodyStart = headerEnd + 2;
    const bodyEnd = bodyStart + bodyLen;
    if (bodyEnd > buf.length) break; // 帧未收完

    frames.push({
      kind: isReq ? 'req' : 'res',
      uri: isReq ? first.slice(4) : undefined,
      code: isReq ? undefined : Number(first),
      headers,
      body: buf.slice(bodyStart, bodyEnd),
    });
    off = bodyEnd;
  }

  return { frames, rest: buf.slice(off) };
}

/** 编码请求帧 */
export function encodeRequest(uri: string, headers: Record<string, string>, body?: Buffer): Buffer {
  const h: Record<string, string> = { ...headers };
  if (body && body.length) h.len = String(body.length);
  const head = [`LWP ${uri}`, ...Object.entries(h).map(([k, v]) => `${k}:${v}`), '', ''].join('\n');
  const headBuf = Buffer.from(head, 'latin1');
  return body && body.length ? Buffer.concat([headBuf, body]) : headBuf;
}

/** 生成本次会话的公共头 */
export function baseHeaders(opts: {
  mid: string;
  did: string;
  appKey: string;
  appkey: string;
  ua: string;
  orgId?: string;
  token?: string;
  dt?: 'p' | 'j';
}): Record<string, string> {
  const h: Record<string, string> = {
    mid: opts.mid,
    'app-key': opts.appKey,
    appkey: opts.appkey,
    did: opts.did,
    tz: 'Asia/Shanghai',
    ua: opts.ua,
    vhost: 'WK',
    wv: 'im:3,au:3,sy:10',
    'cache-header': 'app-key cs-idx-ver did tz ua vhost wv',
    'cs-idx-ver': '0',
  };
  if (opts.dt) h.dt = opts.dt;
  if (opts.orgId) h['app-realm-orgId'] = opts.orgId;
  if (opts.token) h.token = opts.token;
  return h;
}

/** mid 生成器：8 位 hex + 空格 + 0 */
export class MidGenerator {
  private seq = 0;
  constructor(private readonly prefix = 'f091') {}
  next(): string {
    this.seq = (this.seq + 1) >>> 0;
    const v = this.seq.toString(16).padStart(4, '0');
    return `${this.prefix}${v} 0`;
  }
}
